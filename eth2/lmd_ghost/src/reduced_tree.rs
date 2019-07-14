//! An implementation of "reduced tree" LMD GHOST fork choice.
//!
//! This algorithm was concieved at IC3 Cornell, 2019.
//!
//! This implementation is incomplete and has known bugs. Do not use in production.
use super::{LmdGhost, Result as SuperResult};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{iter::BestBlockRootsIterator, Error as StoreError, Store};
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

impl<T, E> LmdGhost<T, E> for ThreadSafeReducedTree<T, E>
where
    T: Store,
    E: EthSpec,
{
    fn new(store: Arc<T>, genesis_block: &BeaconBlock, genesis_root: Hash256) -> Self {
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
    fn process_block(&self, block: &BeaconBlock, block_hash: Hash256) -> SuperResult<()> {
        self.core
            .write()
            .add_weightless_node(block.slot, block_hash)
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

    fn update_finalized_root(&self, new_block: &BeaconBlock, new_root: Hash256) -> SuperResult<()> {
        self.core
            .write()
            .update_root(new_block.slot, new_root)
            .map_err(|e| format!("update_finalized_root failed: {:?}", e))
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

impl<T, E> ReducedTree<T, E>
where
    T: Store,
    E: EthSpec,
{
    pub fn new(store: Arc<T>, genesis_block: &BeaconBlock, genesis_root: Hash256) -> Self {
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

    pub fn update_root(&mut self, new_slot: Slot, new_root: Hash256) -> Result<()> {
        if !self.nodes.contains_key(&new_root) {
            let node = Node {
                block_hash: new_root,
                voters: vec![],
                ..Node::default()
            };

            self.add_node(node)?;
        }

        self.retain_subtree(self.root.0, new_root)?;

        self.root = (new_root, new_slot);

        let root_node = self.get_mut_node(new_root)?;
        root_node.parent_hash = None;

        Ok(())
    }

    /// Removes `current_hash` and all decendants, except `subtree_hash` and all nodes
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
            self.add_weightless_node(start_block_slot, start_block_root)?;
        };

        let _root_weight = self.update_weight(start_block_root, weight_fn)?;

        let start_node = self.get_node(start_block_root)?;
        let head_node = self.find_head_from(start_node)?;

        Ok(head_node.block_hash)
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

    fn remove_latest_message(&mut self, validator_index: usize) -> Result<()> {
        if self.latest_votes.get(validator_index).is_some() {
            // Unwrap is safe as prior `if` statements ensures the result is `Some`.
            let vote = self.latest_votes.get(validator_index).unwrap();

            let should_delete = {
                self.get_mut_node(vote.hash)?.remove_voter(validator_index);
                let node = self.get_node(vote.hash)?.clone();

                if let Some(parent_hash) = node.parent_hash {
                    if node.has_votes() || node.children.len() > 1 {
                        // A node with votes or more than one child is never removed.
                        false
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

                        true
                    } else if node.children.is_empty() {
                        // A node which has no children may be deleted and potentially it's parent
                        // too.
                        self.maybe_delete_node(parent_hash)?;

                        true
                    } else {
                        // It is impossible for a node to have a number of children that is not 0, 1 or
                        // greater than one.
                        //
                        // This code is strictly unnecessary, however we keep it for readability.
                        unreachable!();
                    }
                } else {
                    // A node without a parent is the genesis/finalized node and should never be removed.
                    false
                }
            };

            if should_delete {
                self.nodes.remove(&vote.hash);
            }

            self.latest_votes.insert(validator_index, Some(vote));
        }

        Ok(())
    }

    fn maybe_delete_node(&mut self, hash: Hash256) -> Result<()> {
        let should_delete = {
            let node = self.get_node(hash)?.clone();

            if let Some(parent_hash) = node.parent_hash {
                if (node.children.len() == 1) && !node.has_votes() {
                    // Graft the child to it's grandparent.
                    let child_hash = {
                        let child_node = self.get_mut_node(node.children[0])?;
                        child_node.parent_hash = node.parent_hash;

                        child_node.block_hash
                    };

                    // Graft the grandparent to it's grandchild.
                    let parent_node = self.get_mut_node(parent_hash)?;
                    parent_node.replace_child(node.block_hash, child_hash)?;

                    true
                } else {
                    false
                }
            } else {
                // A node without a parent is the genesis node and should not be deleted.
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

    fn add_weightless_node(&mut self, slot: Slot, hash: Hash256) -> Result<()> {
        if slot >= self.root_slot() && !self.nodes.contains_key(&hash) {
            let node = Node {
                block_hash: hash,
                ..Node::default()
            };

            self.add_node(node)?;

            if let Some(parent_hash) = self.get_node(hash)?.parent_hash {
                self.maybe_delete_node(parent_hash)?;
            }
        }

        Ok(())
    }

    fn add_node(&mut self, mut node: Node) -> Result<()> {
        // Find the highest (by slot) ancestor of the given hash/block that is in the reduced tree.
        let mut prev_in_tree = {
            let hash = self
                .find_prev_in_tree(node.block_hash)
                .ok_or_else(|| Error::NotInTree(node.block_hash))?;
            self.get_mut_node(hash)?.clone()
        };

        let mut added = false;

        if !prev_in_tree.children.is_empty() {
            for &child_hash in &prev_in_tree.children {
                if self
                    .iter_ancestors(child_hash)?
                    .any(|(ancestor, _slot)| ancestor == node.block_hash)
                {
                    let child = self.get_mut_node(child_hash)?;

                    child.parent_hash = Some(node.block_hash);
                    node.children.push(child_hash);
                    prev_in_tree.replace_child(child_hash, node.block_hash)?;
                    node.parent_hash = Some(prev_in_tree.block_hash);

                    added = true;

                    break;
                }
            }

            if !added {
                for &child_hash in &prev_in_tree.children {
                    let ancestor_hash =
                        self.find_least_common_ancestor(node.block_hash, child_hash)?;

                    if ancestor_hash != prev_in_tree.block_hash {
                        let child = self.get_mut_node(child_hash)?;
                        let common_ancestor = Node {
                            block_hash: ancestor_hash,
                            parent_hash: Some(prev_in_tree.block_hash),
                            children: vec![node.block_hash, child_hash],
                            ..Node::default()
                        };
                        child.parent_hash = Some(common_ancestor.block_hash);
                        node.parent_hash = Some(common_ancestor.block_hash);

                        prev_in_tree.replace_child(child_hash, ancestor_hash)?;

                        self.nodes
                            .insert(common_ancestor.block_hash, common_ancestor);

                        added = true;

                        break;
                    }
                }
            }
        }

        if !added {
            node.parent_hash = Some(prev_in_tree.block_hash);
            prev_in_tree.children.push(node.block_hash);
        }

        // Update `prev_in_tree`. A mutable reference was not maintained to satisfy the borrow
        // checker.
        //
        // This is not an ideal solution and results in unnecessary memory copies -- a better
        // solution is certainly possible.
        self.nodes.insert(prev_in_tree.block_hash, prev_in_tree);
        self.nodes.insert(node.block_hash, node);

        Ok(())
    }

    /// For the given block `hash`, find it's highest (by slot) ancestor that exists in the reduced
    /// tree.
    fn find_prev_in_tree(&mut self, hash: Hash256) -> Option<Hash256> {
        self.iter_ancestors(hash)
            .ok()?
            .find(|(root, _slot)| self.nodes.contains_key(root))
            .and_then(|(root, _slot)| Some(root))
    }

    /// For the given `child` block hash, return the block's ancestor at the given `target` slot.
    fn find_ancestor_at_slot(&self, child: Hash256, target: Slot) -> Result<Hash256> {
        let (root, slot) = self
            .iter_ancestors(child)?
            .find(|(_block, slot)| *slot <= target)
            .ok_or_else(|| Error::NotInTree(child))?;

        // Explicitly check that the slot is the target in the case that the given child has a slot
        // above target.
        if slot == target {
            Ok(root)
        } else {
            Err(Error::NotInTree(child))
        }
    }

    /// For the two given block roots (`a_root` and `b_root`), find the first block they share in
    /// the tree. Viz, find the block that these two distinct blocks forked from.
    fn find_least_common_ancestor(&self, a_root: Hash256, b_root: Hash256) -> Result<Hash256> {
        // If the blocks behind `a_root` and `b_root` are not at the same slot, take the highest
        // block (by slot) down to be equal with the lower slot.
        //
        // The result is two roots which identify two blocks at the same height.
        let (a_root, b_root) = {
            let a = self.get_block(a_root)?;
            let b = self.get_block(b_root)?;

            if a.slot > b.slot {
                (self.find_ancestor_at_slot(a_root, b.slot)?, b_root)
            } else if b.slot > a.slot {
                (a_root, self.find_ancestor_at_slot(b_root, a.slot)?)
            } else {
                (a_root, b_root)
            }
        };

        let ((a_root, _a_slot), (_b_root, _b_slot)) = self
            .iter_ancestors(a_root)?
            .zip(self.iter_ancestors(b_root)?)
            .find(|((a_root, _), (b_root, _))| a_root == b_root)
            .ok_or_else(|| Error::NoCommonAncestor((a_root, b_root)))?;

        Ok(a_root)
    }

    fn iter_ancestors(&self, child: Hash256) -> Result<BestBlockRootsIterator<E, T>> {
        let block = self.get_block(child)?;
        let state = self.get_state(block.state_root)?;

        Ok(BestBlockRootsIterator::owned(
            self.store.clone(),
            state,
            block.slot - 1,
        ))
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

    fn get_block(&self, block_root: Hash256) -> Result<BeaconBlock> {
        self.store
            .get::<BeaconBlock>(&block_root)?
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
