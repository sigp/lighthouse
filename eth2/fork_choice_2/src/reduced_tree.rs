use super::{Error as SuperError, LmdGhostBackend};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{iter::BlockRootsIterator, Error as StoreError, Store};
use types::{BeaconBlock, BeaconState, EthSpec, Hash256, Slot};

type Result<T> = std::result::Result<T, Error>;

pub const SKIP_LIST_LEN: usize = 16;

#[derive(Debug, PartialEq)]
pub enum Error {
    MissingNode(Hash256),
    MissingBlock(Hash256),
    MissingState(Hash256),
    NotInTree(Hash256),
    NoCommonAncestor((Hash256, Hash256)),
    StoreError(StoreError),
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Error {
        Error::StoreError(e)
    }
}

pub type Height = usize;

#[derive(Default, Clone)]
pub struct Node {
    pub parent_hash: Option<Hash256>,
    pub children: Vec<Hash256>,
    pub score: u64,
    pub height: Height,
    pub block_hash: Hash256,
    pub voters: Vec<usize>,
}

impl Node {
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

    pub fn is_genesis(&self) -> bool {
        self.parent_hash.is_some()
    }
}

impl Node {
    fn does_not_have_children(&self) -> bool {
        self.children.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Vote {
    hash: Hash256,
    slot: Slot,
}

pub struct ReducedTree<T, E> {
    store: Arc<T>,
    nodes: HashMap<Hash256, Node>,
    /// Maps validator indices to their latest votes.
    latest_votes: ElasticList<Option<Vote>>,
    _phantom: PhantomData<E>,
}

impl<T, E> LmdGhostBackend<T> for ReducedTree<T, E>
where
    T: Store,
    E: EthSpec,
{
    fn new(store: Arc<T>) -> Self {
        Self::new(store)
    }

    fn process_message(
        &mut self,
        validator_index: usize,
        block_hash: Hash256,
        block_slot: Slot,
    ) -> std::result::Result<(), SuperError> {
        self.process_message(validator_index, block_hash, block_slot)
            .map_err(Into::into)
    }

    fn find_head(&mut self) -> std::result::Result<Hash256, SuperError> {
        unimplemented!();
    }
}

impl From<Error> for SuperError {
    fn from(e: Error) -> SuperError {
        SuperError::BackendError(format!("{:?}", e))
    }
}

impl<T, E> ReducedTree<T, E>
where
    T: Store,
    E: EthSpec,
{
    pub fn new(store: Arc<T>) -> Self {
        Self {
            store,
            nodes: HashMap::new(),
            latest_votes: ElasticList::default(),
            _phantom: PhantomData,
        }
    }

    pub fn process_message(
        &mut self,
        validator_index: usize,
        block_hash: Hash256,
        slot: Slot,
    ) -> Result<()> {
        if let Some(previous_vote) = self.latest_votes.get(validator_index) {
            if previous_vote.slot > slot {
                // Given vote is earier than known vote, nothing to do.
                return Ok(());
            } else if previous_vote.slot == slot && previous_vote.hash == block_hash {
                // Given vote is identical to known vote, nothing to do.
                return Ok(());
            } else if previous_vote.slot == slot && previous_vote.hash != block_hash {
                // Vote is an equivocation (double-vote), ignore it.
                //
                // TODO: flag this as slashable.
                return Ok(());
            } else {
                // Given vote is newer or different to current vote, replace the current vote.
                self.remove_latest_message(validator_index)?;
            }
        }

        // TODO: add new vote.

        Ok(())
    }

    pub fn remove_latest_message(&mut self, validator_index: usize) -> Result<()> {
        if self.latest_votes.get(validator_index).is_some() {
            // Unwrap is safe as prior `if` statements ensures the result is `Some`.
            let vote = self.latest_votes.get(validator_index).unwrap();

            let should_delete = {
                self.get_mut_node(vote.hash)?.remove_voter(validator_index);
                let node = self.get_node(vote.hash)?.clone();

                if let Some(parent_hash) = node.parent_hash {
                    if node.has_votes() {
                        // A node with votes is never removed.
                        false
                    } else if node.children.len() > 1 {
                        // A node with more than one child is never removed.
                        false
                    } else if node.children.len() == 1 {
                        // A node which has only one child may be removed.
                        //
                        // Load the child of the node and set it's parent to be the parent of this
                        // node (viz., graft the node's child to the node's parent)
                        let child = self
                            .nodes
                            .get_mut(&node.children[0])
                            .ok_or_else(|| Error::MissingNode(node.children[0]))?;

                        child.parent_hash = node.parent_hash;

                        true
                    } else if node.children.len() == 0 {
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

            if node.parent_hash.is_some() {
                if (node.children.len() == 1) && !node.has_votes() {
                    let child_node = self.get_mut_node(node.children[0])?;

                    child_node.parent_hash = node.parent_hash;

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

    pub fn add_latest_message(&mut self, validator_index: usize, hash: Hash256) -> Result<()> {
        if let Ok(node) = self.get_mut_node(hash) {
            node.add_voter(validator_index);
        } else {
            self.add_node(hash, vec![validator_index])?;
        }

        Ok(())
    }

    pub fn add_node(&mut self, hash: Hash256, voters: Vec<usize>) -> Result<()> {
        // Find the highest (by slot) ancestor of the given hash/block that is in the reduced tree.
        let mut prev_in_tree = {
            let hash = self
                .find_prev_in_tree(hash)
                .ok_or_else(|| Error::NotInTree(hash))?;
            self.get_mut_node(hash)?.clone()
        };

        let mut node = Node {
            block_hash: hash,
            parent_hash: Some(prev_in_tree.block_hash),
            voters,
            ..Node::default()
        };

        if prev_in_tree.does_not_have_children() {
            node.parent_hash = Some(prev_in_tree.block_hash);
            prev_in_tree.children.push(hash);
        } else {
            for &child_hash in &prev_in_tree.children {
                let ancestor_hash = self.find_least_common_ancestor(hash, child_hash)?;
                if ancestor_hash != prev_in_tree.block_hash {
                    let child = self.get_mut_node(child_hash)?;
                    let common_ancestor = Node {
                        block_hash: ancestor_hash,
                        parent_hash: Some(prev_in_tree.block_hash),
                        ..Node::default()
                    };
                    child.parent_hash = Some(common_ancestor.block_hash);
                    node.parent_hash = Some(common_ancestor.block_hash);

                    self.nodes
                        .insert(common_ancestor.block_hash, common_ancestor);
                }
            }
        }

        // Update `prev_in_tree`. A mutable reference was not maintained to satisfy the borrow
        // checker.
        //
        // This is not an ideal solution and results in unnecessary memory copies -- a better
        // solution is certainly possible.
        self.nodes.insert(prev_in_tree.block_hash, prev_in_tree);
        self.nodes.insert(hash, node);

        Ok(())
    }

    /// For the given block `hash`, find it's highest (by slot) ancestor that exists in the reduced
    /// tree.
    fn find_prev_in_tree(&mut self, hash: Hash256) -> Option<Hash256> {
        self.iter_ancestors(hash)
            .ok()?
            .find(|(root, _slit)| self.get_node(*root).is_ok())
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

    fn iter_ancestors(&self, child: Hash256) -> Result<BlockRootsIterator<E, T>> {
        let block = self.get_block(child)?;
        let state = self.get_state(block.state_root)?;

        Ok(BlockRootsIterator::new(
            self.store.clone(),
            state,
            block.slot,
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
}

/// A Vec-wrapper which will grow to match any request.
///
/// E.g., a `get` or `insert` to an out-of-bounds element will cause the Vec to grow (using
/// Default) to the smallest size required to fulfill the request.
#[derive(Default, Clone)]
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

    pub fn get_mut(&mut self, i: usize) -> &mut T {
        self.ensure(i);
        &mut self.0[i]
    }

    pub fn insert(&mut self, i: usize, element: T) {
        self.ensure(i);
        self.0[i] = element;
    }
}
