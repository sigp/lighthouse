//! An implementation of "reduced tree" LMD GHOST fork choice.
//!
//! This algorithm was conceived at IC3 Cornell, 2019.
//!
//! This implementation is incomplete and has known bugs. Do not use in production.
use super::{LmdGhost, Result as SuperResult};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{iter::BlockRootsIterator, Error as StoreError, Store};
use types::{BeaconBlock, BeaconState, EthSpec, Hash256, Slot};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    MissingNode(Hash256),
    MissingBlock(Hash256),
    MissingState(Hash256),
    MissingChild(Hash256),
    NotInTree(Hash256),
    NoCommonAncestor((Hash256, Hash256)),
    StoreError(StoreError),
    ValidatorWeightUnknown(usize),
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Error {
        Error::StoreError(e)
    }
}

pub struct ThreadSafeReducedTree<T, E> {
    core: RwLock<ReducedTree<T, E>>,
}

impl<T, E> fmt::Debug for ThreadSafeReducedTree<T, E> {
    /// `Debug` just defers to the implementation of `self.core`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.core.fmt(f)
    }
}

impl<T, E> LmdGhost<T, E> for ThreadSafeReducedTree<T, E>
where
    T: Store,
    E: EthSpec,
{
    fn new(store: Arc<T>, genesis_block: &BeaconBlock<E>, genesis_root: Hash256) -> Self {
        ThreadSafeReducedTree {
            core: RwLock::new(ReducedTree::new(store, genesis_block, genesis_root)),
        }
    }

    fn process_attestation(
        &self,
        validator_index: usize,
        block_hash: Hash256,
        block_slot: Slot,
    ) -> SuperResult<()> {
        self.core
            .write()
            .process_message(validator_index, block_hash, block_slot)
            .map_err(|e| format!("process_attestation failed: {:?}", e))
    }

    /// Process a block that was seen on the network.
    fn process_block(&self, block: &BeaconBlock<E>, block_hash: Hash256) -> SuperResult<()> {
        self.core
            .write()
            .maybe_add_weightless_node(block.slot, block_hash)
            .map_err(|e| format!("process_block failed: {:?}", e))
    }

    fn find_head<F>(
        &self,
        start_block_slot: Slot,
        start_block_root: Hash256,
        weight_fn: F,
    ) -> SuperResult<Hash256>
    where
        F: Fn(usize) -> Option<u64> + Copy,
    {
        self.core
            .write()
            .update_weights_and_find_head(start_block_slot, start_block_root, weight_fn)
            .map_err(|e| format!("find_head failed: {:?}", e))
    }

    fn update_finalized_root(
        &self,
        new_block: &BeaconBlock<E>,
        new_root: Hash256,
    ) -> SuperResult<()> {
        self.core
            .write()
            .update_root(new_block.slot, new_root)
            .map_err(|e| format!("update_finalized_root failed: {:?}", e))
    }

    fn latest_message(&self, validator_index: usize) -> Option<(Hash256, Slot)> {
        self.core.read().latest_message(validator_index)
    }

    fn verify_integrity(&self) -> std::result::Result<(), String> {
        self.core.read().verify_integrity()
    }
}

struct ReducedTree<T, E> {
    store: Arc<T>,
    /// Stores all nodes of the tree, keyed by the block hash contained in the node.
    nodes: HashMap<Hash256, Node>,
    /// Maps validator indices to their latest votes.
    latest_votes: ElasticList<Option<Vote>>,
    /// Stores the root of the tree, used for pruning.
    root: (Hash256, Slot),
    _phantom: PhantomData<E>,
}

impl<T, E> fmt::Debug for ReducedTree<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.nodes.fmt(f)
    }
}

impl<T, E> ReducedTree<T, E>
where
    T: Store,
    E: EthSpec,
{
    pub fn new(store: Arc<T>, genesis_block: &BeaconBlock<E>, genesis_root: Hash256) -> Self {
        let mut nodes = HashMap::new();

        // Insert the genesis node.
        nodes.insert(
            genesis_root,
            Node {
                block_hash: genesis_root,
                ..Node::default()
            },
        );

        Self {
            store,
            nodes,
            latest_votes: ElasticList::default(),
            root: (genesis_root, genesis_block.slot),
            _phantom: PhantomData,
        }
    }

    /// Set the root node (the node without any parents) to the given `new_slot` and `new_root`.
    ///
    /// The given `new_root` must be in the block tree (but not necessarily in the reduced tree).
    /// Any nodes which are not a descendant of `new_root` will be removed from the store.
    pub fn update_root(&mut self, new_slot: Slot, new_root: Hash256) -> Result<()> {
        self.maybe_add_weightless_node(new_slot, new_root)?;

        self.retain_subtree(self.root.0, new_root)?;

        self.root = (new_root, new_slot);

        let root_node = self.get_mut_node(new_root)?;
        root_node.parent_hash = None;

        Ok(())
    }

    /// Removes `current_hash` and all descendants, except `subtree_hash` and all nodes
    /// which have `subtree_hash` as an ancestor.
    ///
    /// In effect, prunes the tree so that only decendants of `subtree_hash` exist.
    fn retain_subtree(&mut self, current_hash: Hash256, subtree_hash: Hash256) -> Result<()> {
        if current_hash != subtree_hash {
            let children = self.get_node(current_hash)?.children.clone();

            for child_hash in children {
                self.retain_subtree(child_hash, subtree_hash)?;
            }

            self.nodes.remove(&current_hash);
        }

        Ok(())
    }

    pub fn process_message(
        &mut self,
        validator_index: usize,
        block_hash: Hash256,
        slot: Slot,
    ) -> Result<()> {
        if slot >= self.root_slot() {
            if let Some(previous_vote) = self.latest_votes.get(validator_index) {
                // Note: it is possible to do a cheap equivocation check here:
                //
                // slashable = (previous_vote.slot == slot) && (previous_vote.hash != block_hash)

                if previous_vote.slot < slot {
                    self.remove_latest_message(validator_index)?;
                } else {
                    return Ok(());
                }
            }

            self.latest_votes.insert(
                validator_index,
                Some(Vote {
                    slot,
                    hash: block_hash,
                }),
            );

            self.add_latest_message(validator_index, block_hash)?;
        }

        Ok(())
    }

    pub fn update_weights_and_find_head<F>(
        &mut self,
        start_block_slot: Slot,
        start_block_root: Hash256,
        weight_fn: F,
    ) -> Result<Hash256>
    where
        F: Fn(usize) -> Option<u64> + Copy,
    {
        // It is possible that the given `start_block_root` is not in the reduced tree.
        //
        // In this case, we add a weightless node at `start_block_root`.
        if !self.nodes.contains_key(&start_block_root) {
            self.maybe_add_weightless_node(start_block_slot, start_block_root)?;
        };

        let _root_weight = self.update_weight(start_block_root, weight_fn)?;

        let start_node = self.get_node(start_block_root)?;
        let head_node = self.find_head_from(start_node)?;

        Ok(head_node.block_hash)
    }

    pub fn latest_message(&self, validator_index: usize) -> Option<(Hash256, Slot)> {
        match self.latest_votes.get_ref(validator_index) {
            Some(Some(v)) => Some((v.hash, v.slot)),
            _ => None,
        }
    }

    fn find_head_from<'a>(&'a self, start_node: &'a Node) -> Result<&'a Node> {
        if start_node.does_not_have_children() {
            Ok(start_node)
        } else {
            let children = start_node
                .children
                .iter()
                .map(|hash| self.get_node(*hash))
                .collect::<Result<Vec<&Node>>>()?;

            // TODO: check if `max_by` is `O(n^2)`.
            let best_child = children
                .iter()
                .max_by(|a, b| {
                    if a.weight != b.weight {
                        a.weight.cmp(&b.weight)
                    } else {
                        a.block_hash.cmp(&b.block_hash)
                    }
                })
                // There can only be no maximum if there are no children. This code path is guarded
                // against that condition.
                .expect("There must be a maximally weighted node.");

            self.find_head_from(best_child)
        }
    }

    fn update_weight<F>(&mut self, start_block_root: Hash256, weight_fn: F) -> Result<u64>
    where
        F: Fn(usize) -> Option<u64> + Copy,
    {
        let weight = {
            let node = self.get_node(start_block_root)?.clone();

            let mut weight = 0;

            for &child in &node.children {
                weight += self.update_weight(child, weight_fn)?;
            }

            for &voter in &node.voters {
                weight += weight_fn(voter).ok_or_else(|| Error::ValidatorWeightUnknown(voter))?;
            }

            weight
        };

        let node = self.get_mut_node(start_block_root)?;
        node.weight = weight;

        Ok(weight)
    }

    /// Removes the vote from `validator_index` from the reduced tree.
    ///
    /// If the validator had a vote in the tree, the removal of that vote may cause a node to
    /// become redundant and removed from the reduced tree.
    fn remove_latest_message(&mut self, validator_index: usize) -> Result<()> {
        if let Some(vote) = *self.latest_votes.get(validator_index) {
            if self.nodes.contains_key(&vote.hash) {
                self.get_mut_node(vote.hash)?.remove_voter(validator_index);
                let node = self.get_node(vote.hash)?.clone();

                if let Some(parent_hash) = node.parent_hash {
                    if node.has_votes() || node.children.len() > 1 {
                        // A node with votes or more than one child is never removed.
                    } else if node.children.len() == 1 {
                        // A node which has only one child may be removed.
                        //
                        // Load the child of the node and set it's parent to be the parent of this
                        // node (viz., graft the node's child to the node's parent)
                        let child = self.get_mut_node(node.children[0])?;
                        child.parent_hash = node.parent_hash;

                        // Graft the parent of this node to it's child.
                        if let Some(parent_hash) = node.parent_hash {
                            let parent = self.get_mut_node(parent_hash)?;
                            parent.replace_child(node.block_hash, node.children[0])?;
                        }

                        self.nodes.remove(&vote.hash);
                    } else if node.children.is_empty() {
                        // Remove the to-be-deleted node from it's parent.
                        if let Some(parent_hash) = node.parent_hash {
                            self.get_mut_node(parent_hash)?
                                .remove_child(node.block_hash)?;
                        }

                        self.nodes.remove(&vote.hash);

                        // A node which has no children may be deleted and potentially it's parent
                        // too.
                        self.maybe_delete_node(parent_hash)?;
                    } else {
                        // It is impossible for a node to have a number of children that is not 0, 1 or
                        // greater than one.
                        //
                        // This code is strictly unnecessary, however we keep it for readability.
                        unreachable!();
                    }
                } else {
                    // A node without a parent is the genesis/finalized node and should never be removed.
                }

                self.latest_votes.insert(validator_index, Some(vote));
            }
        }

        Ok(())
    }

    /// Deletes a node if it is unnecessary.
    ///
    /// Any node is unnecessary if all of the following are true:
    ///
    /// - it is not the root node.
    /// - it only has one child.
    /// - it does not have any votes.
    fn maybe_delete_node(&mut self, hash: Hash256) -> Result<()> {
        let should_delete = {
            if let Ok(node) = self.get_node(hash) {
                let node = node.clone();

                if let Some(parent_hash) = node.parent_hash {
                    if (node.children.len() == 1) && !node.has_votes() {
                        let child_hash = node.children[0];

                        // Graft the single descendant `node` to the `parent` of node.
                        self.get_mut_node(child_hash)?.parent_hash = Some(parent_hash);

                        // Detach `node` from `parent`, replacing it with `child`.
                        self.get_mut_node(parent_hash)?
                            .replace_child(hash, child_hash)?;

                        true
                    } else {
                        false
                    }
                } else {
                    // A node without a parent is the genesis node and should not be deleted.
                    false
                }
            } else {
                // No need to delete a node that does not exist.
                false
            }
        };

        if should_delete {
            self.nodes.remove(&hash);
        }

        Ok(())
    }

    fn add_latest_message(&mut self, validator_index: usize, hash: Hash256) -> Result<()> {
        if let Ok(node) = self.get_mut_node(hash) {
            node.add_voter(validator_index);
        } else {
            let node = Node {
                block_hash: hash,
                voters: vec![validator_index],
                ..Node::default()
            };

            self.add_node(node)?;
        }

        Ok(())
    }

    fn maybe_add_weightless_node(&mut self, slot: Slot, hash: Hash256) -> Result<()> {
        if slot > self.root_slot() && !self.nodes.contains_key(&hash) {
            let node = Node {
                block_hash: hash,
                ..Node::default()
            };

            self.add_node(node)?;

            // Read the `parent_hash` from the newly created node. If it has a parent (i.e., it's
            // not the root), see if it is superfluous.
            if let Some(parent_hash) = self.get_node(hash)?.parent_hash {
                self.maybe_delete_node(parent_hash)?;
            }
        }

        Ok(())
    }

    /// Add `node` to the reduced tree, returning an error if `node` is not rooted in the tree.
    fn add_node(&mut self, mut node: Node) -> Result<()> {
        // Find the highest (by slot) ancestor of the given node in the reduced tree.
        //
        // If this node has no ancestor in the tree, exit early.
        let mut prev_in_tree = self
            .find_prev_in_tree(node.block_hash)
            .ok_or_else(|| Error::NotInTree(node.block_hash))
            .and_then(|hash| self.get_node(hash))?
            .clone();

        // If the ancestor of `node` has children, there are three possible operations:
        //
        // 1. Graft the `node` between two existing nodes.
        // 2. Create another node that will be grafted between two existing nodes, then graft
        //    `node` to it.
        // 3. Graft `node` to an existing node.
        if !prev_in_tree.children.is_empty() {
            for &child_hash in &prev_in_tree.children {
                // 1. Graft the new node between two existing nodes.
                //
                // If `node` is a descendant of `prev_in_tree` but an ancestor of a child connected to
                // `prev_in_tree`.
                //
                // This means that `node` can be grafted between `prev_in_tree` and the child that is a
                // descendant of both `node` and `prev_in_tree`.
                if self
                    .iter_ancestors(child_hash)?
                    .take_while(|(_, slot)| *slot >= self.root_slot())
                    .any(|(ancestor, _slot)| ancestor == node.block_hash)
                {
                    let child = self.get_mut_node(child_hash)?;

                    // Graft `child` to `node`.
                    child.parent_hash = Some(node.block_hash);
                    // Graft `node` to `child`.
                    node.children.push(child_hash);
                    // Detach `child` from `prev_in_tree`, replacing it with `node`.
                    prev_in_tree.replace_child(child_hash, node.block_hash)?;
                    // Graft `node` to `prev_in_tree`.
                    node.parent_hash = Some(prev_in_tree.block_hash);

                    break;
                }
            }

            // 2. Create another node that will be grafted between two existing nodes, then graft
            //    `node` to it.
            //
            // Note: given that `prev_in_tree` has children and that `node` is not an ancestor of
            // any of the children of `prev_in_tree`, we know that `node` is on a different fork to
            // all of the children of `prev_in_tree`.
            if node.parent_hash.is_none() {
                for &child_hash in &prev_in_tree.children {
                    // Find the highest (by slot) common ancestor between `node` and `child`.
                    //
                    // The common ancestor is the last block before `node` and `child` forked.
                    let ancestor_hash =
                        self.find_highest_common_ancestor(node.block_hash, child_hash)?;

                    // If the block before `node` and `child` forked is _not_ `prev_in_tree` we
                    // must add this new block into the tree (because it is a decision node
                    // between two forks).
                    if ancestor_hash != prev_in_tree.block_hash {
                        let child = self.get_mut_node(child_hash)?;

                        // Create a new `common_ancestor` node which represents the `ancestor_hash`
                        // block, has `prev_in_tree` as the parent and has both `node` and `child`
                        // as children.
                        let common_ancestor = Node {
                            block_hash: ancestor_hash,
                            parent_hash: Some(prev_in_tree.block_hash),
                            children: vec![node.block_hash, child_hash],
                            ..Node::default()
                        };

                        // Graft `child` and `node` to `common_ancestor`.
                        child.parent_hash = Some(common_ancestor.block_hash);
                        node.parent_hash = Some(common_ancestor.block_hash);

                        // Detach `child` from `prev_in_tree`, replacing it with `common_ancestor`.
                        prev_in_tree.replace_child(child_hash, common_ancestor.block_hash)?;

                        // Store the new `common_ancestor` node.
                        self.nodes
                            .insert(common_ancestor.block_hash, common_ancestor);

                        break;
                    }
                }
            }
        }

        if node.parent_hash.is_none() {
            // 3. Graft `node` to an existing node.
            //
            // Graft `node` to `prev_in_tree` and `prev_in_tree` to `node`
            node.parent_hash = Some(prev_in_tree.block_hash);
            prev_in_tree.children.push(node.block_hash);
        }

        // Update `prev_in_tree`. A mutable reference was not maintained to satisfy the borrow
        // checker. Perhaps there's a better way?
        self.nodes.insert(prev_in_tree.block_hash, prev_in_tree);
        self.nodes.insert(node.block_hash, node);

        Ok(())
    }

    /// For the given block `hash`, find it's highest (by slot) ancestor that exists in the reduced
    /// tree.
    fn find_prev_in_tree(&mut self, hash: Hash256) -> Option<Hash256> {
        self.iter_ancestors(hash)
            .ok()?
            .take_while(|(_, slot)| *slot >= self.root_slot())
            .find(|(root, _slot)| self.nodes.contains_key(root))
            .and_then(|(root, _slot)| Some(root))
    }

    /// For the two given block roots (`a_root` and `b_root`), find the first block they share in
    /// the tree. Viz, find the block that these two distinct blocks forked from.
    fn find_highest_common_ancestor(&self, a_root: Hash256, b_root: Hash256) -> Result<Hash256> {
        let mut a_iter = self
            .iter_ancestors(a_root)?
            .take_while(|(_, slot)| *slot >= self.root_slot());
        let mut b_iter = self
            .iter_ancestors(b_root)?
            .take_while(|(_, slot)| *slot >= self.root_slot());

        // Combines the `next()` fns on the `a_iter` and `b_iter` and returns the roots of two
        // blocks at the same slot, or `None` if we have gone past genesis or the root of this tree.
        let mut iter_blocks_at_same_height = || -> Option<(Hash256, Hash256)> {
            match (a_iter.next(), b_iter.next()) {
                (Some((mut a_root, a_slot)), Some((mut b_root, b_slot))) => {
                    // If either of the slots are lower than the root of this tree, exit early.
                    if a_slot < self.root.1 || b_slot < self.root.1 {
                        None
                    } else {
                        if a_slot < b_slot {
                            for _ in a_slot.as_u64()..b_slot.as_u64() {
                                b_root = b_iter.next()?.0;
                            }
                        } else if a_slot > b_slot {
                            for _ in b_slot.as_u64()..a_slot.as_u64() {
                                a_root = a_iter.next()?.0;
                            }
                        }

                        Some((a_root, b_root))
                    }
                }
                _ => None,
            }
        };

        loop {
            match iter_blocks_at_same_height() {
                Some((a_root, b_root)) if a_root == b_root => break Ok(a_root),
                Some(_) => (),
                None => break Err(Error::NoCommonAncestor((a_root, b_root))),
            }
        }
    }

    fn iter_ancestors(&self, child: Hash256) -> Result<BlockRootsIterator<E, T>> {
        let block = self.get_block(child)?;
        let state = self.get_state(block.state_root)?;

        Ok(BlockRootsIterator::owned(self.store.clone(), state))
    }

    /// Verify the integrity of `self`. Returns `Ok(())` if the tree has integrity, otherwise returns `Err(description)`.
    ///
    /// Tries to detect the following erroneous conditions:
    ///
    /// - Dangling references inside the tree.
    /// - Any scenario where there's not exactly one root node.
    ///
    /// ## Notes
    ///
    /// Computationally intensive, likely only useful during testing.
    pub fn verify_integrity(&self) -> std::result::Result<(), String> {
        let num_root_nodes = self
            .nodes
            .iter()
            .filter(|(_key, node)| node.parent_hash.is_none())
            .count();

        if num_root_nodes != 1 {
            return Err(format!(
                "Tree has {} roots, should have exactly one.",
                num_root_nodes
            ));
        }

        let verify_node_exists = |key: Hash256, msg: String| -> std::result::Result<(), String> {
            if self.nodes.contains_key(&key) {
                Ok(())
            } else {
                Err(msg)
            }
        };

        // Iterate through all the nodes and ensure all references they store are valid.
        self.nodes
            .iter()
            .map(|(_key, node)| {
                if let Some(parent_hash) = node.parent_hash {
                    verify_node_exists(parent_hash, "parent must exist".to_string())?;
                }

                node.children
                    .iter()
                    .map(|child| verify_node_exists(*child, "child_must_exist".to_string()))
                    .collect::<std::result::Result<(), String>>()?;

                verify_node_exists(node.block_hash, "block hash must exist".to_string())?;

                Ok(())
            })
            .collect::<std::result::Result<(), String>>()?;

        Ok(())
    }

    fn get_node(&self, hash: Hash256) -> Result<&Node> {
        self.nodes
            .get(&hash)
            .ok_or_else(|| Error::MissingNode(hash))
    }

    fn get_mut_node(&mut self, hash: Hash256) -> Result<&mut Node> {
        self.nodes
            .get_mut(&hash)
            .ok_or_else(|| Error::MissingNode(hash))
    }

    fn get_block(&self, block_root: Hash256) -> Result<BeaconBlock<E>> {
        self.store
            .get::<BeaconBlock<E>>(&block_root)?
            .ok_or_else(|| Error::MissingBlock(block_root))
    }

    fn get_state(&self, state_root: Hash256) -> Result<BeaconState<E>> {
        self.store
            .get::<BeaconState<E>>(&state_root)?
            .ok_or_else(|| Error::MissingState(state_root))
    }

    fn root_slot(&self) -> Slot {
        self.root.1
    }
}

#[derive(Default, Clone, Debug)]
pub struct Node {
    pub parent_hash: Option<Hash256>,
    pub children: Vec<Hash256>,
    pub weight: u64,
    pub block_hash: Hash256,
    pub voters: Vec<usize>,
}

impl Node {
    pub fn does_not_have_children(&self) -> bool {
        self.children.is_empty()
    }

    pub fn replace_child(&mut self, old: Hash256, new: Hash256) -> Result<()> {
        let i = self
            .children
            .iter()
            .position(|&c| c == old)
            .ok_or_else(|| Error::MissingChild(old))?;
        self.children[i] = new;

        Ok(())
    }

    pub fn remove_child(&mut self, child: Hash256) -> Result<()> {
        let i = self
            .children
            .iter()
            .position(|&c| c == child)
            .ok_or_else(|| Error::MissingChild(child))?;

        self.children.remove(i);

        Ok(())
    }

    pub fn remove_voter(&mut self, voter: usize) -> Option<usize> {
        let i = self.voters.iter().position(|&v| v == voter)?;
        Some(self.voters.remove(i))
    }

    pub fn add_voter(&mut self, voter: usize) {
        self.voters.push(voter);
    }

    pub fn has_votes(&self) -> bool {
        !self.voters.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Vote {
    hash: Hash256,
    slot: Slot,
}

/// A Vec-wrapper which will grow to match any request.
///
/// E.g., a `get` or `insert` to an out-of-bounds element will cause the Vec to grow (using
/// Default) to the smallest size required to fulfill the request.
#[derive(Default, Clone, Debug)]
pub struct ElasticList<T>(Vec<T>);

impl<T> ElasticList<T>
where
    T: Default,
{
    fn ensure(&mut self, i: usize) {
        if self.0.len() <= i {
            self.0.resize_with(i + 1, Default::default);
        }
    }

    pub fn get(&mut self, i: usize) -> &T {
        self.ensure(i);
        &self.0[i]
    }

    pub fn get_ref(&self, i: usize) -> Option<&T> {
        self.0.get(i)
    }

    pub fn insert(&mut self, i: usize, element: T) {
        self.ensure(i);
        self.0[i] = element;
    }
}

impl From<Error> for String {
    fn from(e: Error) -> String {
        format!("{:?}", e)
    }
}
