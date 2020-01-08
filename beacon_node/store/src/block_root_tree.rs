use itertools::Itertools;
use parking_lot::RwLock;
use ssz_derive::{Decode, Encode};
use std::collections::{HashMap, HashSet};
use std::iter::{self, FromIterator};
use types::{Hash256, Slot};

/// In-memory cache of all block roots post-finalization. Includes short-lived forks.
///
/// Used by fork choice to avoid reconstructing hot states just for their block roots.
// NOTE: could possibly be streamlined by combining with the head tracker and/or fork choice
#[derive(Debug)]
pub struct BlockRootTree {
    nodes: RwLock<HashMap<Hash256, Node>>,
}

impl Clone for BlockRootTree {
    fn clone(&self) -> Self {
        Self {
            nodes: RwLock::new(self.nodes.read().clone()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum BlockRootTreeError {
    PrevUnknown(Hash256),
}

/// Data for a single `block_root` in the tree.
#[derive(Debug, Clone, Encode, Decode)]
struct Node {
    /// Hash of the preceding block (should be the parent block).
    ///
    /// A `previous` of `Hash256::zero` indicates the root of the tree.
    previous: Hash256,
    /// Slot of this node's block.
    slot: Slot,
}

impl BlockRootTree {
    /// Create a new block root tree where `(root_hash, root_slot)` is considered finalized.
    ///
    /// All subsequent blocks added should descend from the root block.
    pub fn new(root_hash: Hash256, root_slot: Slot) -> Self {
        Self {
            nodes: RwLock::new(HashMap::from_iter(iter::once((
                root_hash,
                Node {
                    previous: Hash256::zero(),
                    slot: root_slot,
                },
            )))),
        }
    }

    /// Check if `block_root` exists in the tree.
    pub fn is_known_block_root(&self, block_root: &Hash256) -> bool {
        self.nodes.read().contains_key(block_root)
    }

    /// Add a new `block_root` to the tree.
    ///
    /// Will return an error if `prev_block_root` doesn't exist in the tree.
    pub fn add_block_root(
        &self,
        block_root: Hash256,
        prev_block_root: Hash256,
        block_slot: Slot,
    ) -> Result<(), BlockRootTreeError> {
        let mut nodes = self.nodes.write();
        if nodes.contains_key(&prev_block_root) {
            nodes.insert(
                block_root,
                Node {
                    previous: prev_block_root,
                    slot: block_slot,
                },
            );
            Ok(())
        } else {
            Err(BlockRootTreeError::PrevUnknown(prev_block_root))
        }
    }

    /// Create a reverse iterator from `block_root` (inclusive).
    ///
    /// Will skip slots, see `every_slot_iter_from` for a non-skipping variant.
    pub fn iter_from(&self, block_root: Hash256) -> BlockRootTreeIter {
        BlockRootTreeIter {
            tree: self,
            current_block_root: block_root,
        }
    }

    /// Create a reverse iterator that yields a block root for every slot.
    ///
    /// E.g. if slot 6 is skipped, this iterator will return the block root from slot 5 at slot 6.
    pub fn every_slot_iter_from<'a>(
        &'a self,
        block_root: Hash256,
    ) -> impl Iterator<Item = (Hash256, Slot)> + 'a {
        let mut block_roots = self.iter_from(block_root).peekable();

        // Include the value for the first `block_root` if any, then fill in the skipped slots
        // between each pair of previous block roots by duplicating the older root.
        block_roots
            .peek()
            .cloned()
            .into_iter()
            .chain(block_roots.tuple_windows().flat_map(
                |((_, high_slot), (low_hash, low_slot))| {
                    (low_slot.as_u64()..high_slot.as_u64())
                        .rev()
                        .map(move |slot| (low_hash, Slot::new(slot)))
                },
            ))
    }

    /// Prune the tree.
    ///
    /// Only keep block roots descended from `finalized_root`, which lie on a chain leading
    /// to one of the heads contained in `heads`.
    pub fn prune_to(&self, finalized_root: Hash256, heads: impl IntoIterator<Item = Hash256>) {
        let mut keep = HashSet::new();
        keep.insert(finalized_root);

        for head_block_root in heads.into_iter() {
            // Iterate backwards until we reach a portion of the chain that we've already decided
            // to keep. This also discards the pre-finalization block roots.
            let mut keep_head = false;

            let head_blocks = self
                .iter_from(head_block_root)
                .map(|(block_root, _)| block_root)
                .inspect(|block_root| {
                    if block_root == &finalized_root {
                        keep_head = true;
                    }
                })
                .take_while(|block_root| !keep.contains(&block_root))
                .collect::<HashSet<_>>();

            // If the head descends from the finalized root, keep it. Else throw it out.
            if keep_head {
                keep.extend(head_blocks);
            }
        }

        self.nodes
            .write()
            .retain(|block_root, _| keep.contains(block_root));
    }

    pub fn as_ssz_container(&self) -> SszBlockRootTree {
        SszBlockRootTree {
            nodes: Vec::from_iter(self.nodes.read().clone()),
        }
    }
}

/// Simple (skipping) iterator for `BlockRootTree`.
#[derive(Debug)]
pub struct BlockRootTreeIter<'a> {
    tree: &'a BlockRootTree,
    current_block_root: Hash256,
}

impl<'a> Iterator for BlockRootTreeIter<'a> {
    type Item = (Hash256, Slot);

    fn next(&mut self) -> Option<Self::Item> {
        // Genesis
        if self.current_block_root.is_zero() {
            None
        } else {
            let block_root = self.current_block_root;
            self.tree.nodes.read().get(&block_root).map(|node| {
                self.current_block_root = node.previous;
                (block_root, node.slot)
            })
        }
    }
}

/// Serializable version of `BlockRootTree` that can be persisted to disk.
#[derive(Debug, Clone, Encode, Decode)]
pub struct SszBlockRootTree {
    nodes: Vec<(Hash256, Node)>,
}

impl Into<BlockRootTree> for SszBlockRootTree {
    fn into(self) -> BlockRootTree {
        BlockRootTree {
            nodes: RwLock::new(HashMap::from_iter(self.nodes)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn int_hash(x: u64) -> Hash256 {
        Hash256::from_low_u64_be(x)
    }

    fn check_iter_from(
        block_tree: &BlockRootTree,
        start_block_root: Hash256,
        expected: &[(Hash256, Slot)],
    ) {
        assert_eq!(
            &block_tree.iter_from(start_block_root).collect::<Vec<_>>()[..],
            expected
        );
    }

    fn check_every_slot_iter_from(
        block_tree: &BlockRootTree,
        start_block_root: Hash256,
        expected: &[(Hash256, Slot)],
    ) {
        assert_eq!(
            &block_tree
                .every_slot_iter_from(start_block_root)
                .collect::<Vec<_>>()[..],
            expected
        );
    }

    #[test]
    fn single_chain() {
        let block_tree = BlockRootTree::new(int_hash(1), Slot::new(1));
        for i in 2..100 {
            block_tree
                .add_block_root(int_hash(i), int_hash(i - 1), Slot::new(i))
                .expect("add_block_root ok");

            let expected = (1..i + 1)
                .rev()
                .map(|j| (int_hash(j), Slot::new(j)))
                .collect::<Vec<_>>();

            check_iter_from(&block_tree, int_hash(i), &expected);
            check_every_slot_iter_from(&block_tree, int_hash(i), &expected);

            // Still OK after pruning.
            block_tree.prune_to(int_hash(1), vec![int_hash(i)]);

            check_iter_from(&block_tree, int_hash(i), &expected);
            check_every_slot_iter_from(&block_tree, int_hash(i), &expected);
        }
    }

    #[test]
    fn skips_of_2() {
        let block_tree = BlockRootTree::new(int_hash(1), Slot::new(1));
        let step_length = 2u64;
        for i in (1 + step_length..100).step_by(step_length as usize) {
            block_tree
                .add_block_root(int_hash(i), int_hash(i - step_length), Slot::new(i))
                .expect("add_block_root ok");

            let sparse_expected = (1..i + 1)
                .rev()
                .step_by(step_length as usize)
                .map(|j| (int_hash(j), Slot::new(j)))
                .collect_vec();
            let every_slot_expected = (1..i + 1)
                .rev()
                .map(|j| {
                    let nearest = 1 + (j - 1) / step_length * step_length;
                    (int_hash(nearest), Slot::new(j))
                })
                .collect_vec();

            check_iter_from(&block_tree, int_hash(i), &sparse_expected);
            check_every_slot_iter_from(&block_tree, int_hash(i), &every_slot_expected);

            // Still OK after pruning.
            block_tree.prune_to(int_hash(1), vec![int_hash(i)]);

            check_iter_from(&block_tree, int_hash(i), &sparse_expected);
            check_every_slot_iter_from(&block_tree, int_hash(i), &every_slot_expected);
        }
    }

    #[test]
    fn prune_small_fork() {
        let tree = BlockRootTree::new(int_hash(1), Slot::new(1));
        // Space between fork hash values
        let offset = 1000;
        let num_blocks = 50;

        let fork1_start = 2;
        let fork2_start = 2 + offset;

        tree.add_block_root(int_hash(fork1_start), int_hash(1), Slot::new(2))
            .expect("add first block of left fork");
        tree.add_block_root(int_hash(fork2_start), int_hash(1), Slot::new(2))
            .expect("add first block of right fork");

        for i in 3..num_blocks {
            tree.add_block_root(int_hash(i), int_hash(i - 1), Slot::new(i))
                .expect("add block to left fork");
            tree.add_block_root(int_hash(i + offset), int_hash(i + offset - 1), Slot::new(i))
                .expect("add block to right fork");
        }

        let root = (int_hash(1), Slot::new(1));

        let (all_fork1_blocks, all_fork2_blocks): (Vec<_>, Vec<_>) = (2..num_blocks)
            .rev()
            .map(|i| {
                (
                    (int_hash(i), Slot::new(i)),
                    (int_hash(i + offset), Slot::new(i)),
                )
            })
            .chain(iter::once((root, root)))
            .unzip();

        let fork1_head = int_hash(num_blocks - 1);
        let fork2_head = int_hash(num_blocks + offset - 1);

        // Check that pruning with both heads preserves both chains.
        let both_tree = tree.clone();
        both_tree.prune_to(root.0, vec![fork1_head, fork2_head]);
        check_iter_from(&both_tree, fork1_head, &all_fork1_blocks);
        check_iter_from(&both_tree, fork2_head, &all_fork2_blocks);

        // Check that pruning to either of the single chains leaves just that chain in the tree.
        let fork1_tree = tree.clone();
        fork1_tree.prune_to(root.0, vec![fork1_head]);
        check_iter_from(&fork1_tree, fork1_head, &all_fork1_blocks);
        check_iter_from(&fork1_tree, fork2_head, &[]);

        let fork2_tree = tree.clone();
        fork2_tree.prune_to(root.0, vec![fork2_head]);
        check_iter_from(&fork2_tree, fork1_head, &[]);
        check_iter_from(&fork2_tree, fork2_head, &all_fork2_blocks);

        // Check that advancing the finalized root onto one side completely removes the other
        // side.
        let fin_tree = tree.clone();
        let prune_point = num_blocks / 2;
        let remaining_fork1_blocks = all_fork1_blocks
            .clone()
            .into_iter()
            .take_while(|(_, slot)| *slot >= prune_point)
            .collect_vec();
        fin_tree.prune_to(int_hash(prune_point), vec![fork1_head, fork2_head]);
        check_iter_from(&fin_tree, fork1_head, &remaining_fork1_blocks);
        check_iter_from(&fin_tree, fork2_head, &[]);
    }

    #[test]
    fn iter_zero() {
        let block_tree = BlockRootTree::new(int_hash(0), Slot::new(0));
        assert_eq!(block_tree.iter_from(int_hash(0)).count(), 0);
        assert_eq!(block_tree.every_slot_iter_from(int_hash(0)).count(), 0);
    }
}
