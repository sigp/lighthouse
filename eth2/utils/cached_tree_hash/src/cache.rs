use crate::{Error, Hash256};
use eth2_hashing::{hash_concat, ZERO_HASHES};
use tree_hash::BYTES_PER_CHUNK;

/// Sparse Merkle tree suitable for tree hashing vectors and lists.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct TreeHashCache {
    /// Depth is such that the tree has a capacity for 2^depth leaves
    depth: usize,
    /// Sparse layers.
    ///
    /// The leaves are contained in `self.layers[self.depth]`, and each other layer `i`
    /// contains the parents of the nodes in layer `i + 1`.
    layers: Vec<Vec<Hash256>>,
}

impl TreeHashCache {
    /// Create a new cache with the given `depth`, but no actual content.
    pub fn new(depth: usize) -> Self {
        TreeHashCache {
            depth,
            layers: vec![vec![]; depth + 1],
        }
    }

    /// Compute the updated Merkle root for the given `leaves`.
    pub fn recalculate_merkle_root(
        &mut self,
        leaves: impl Iterator<Item = [u8; BYTES_PER_CHUNK]>,
    ) -> Result<Hash256, Error> {
        let dirty_indices = self.update_leaves(leaves)?;
        Ok(self.update_merkle_root(dirty_indices))
    }

    /// Phase 1 of the algorithm: compute the indices of all dirty leaves.
    fn update_leaves(
        &mut self,
        leaves: impl Iterator<Item = [u8; BYTES_PER_CHUNK]>,
    ) -> Result<Vec<usize>, Error> {
        let mut dirty = vec![];
        let mut num_new_leaves = 0;

        for (i, new_leaf) in leaves.enumerate() {
            match self.leaves().get_mut(i) {
                Some(leaf) => {
                    if leaf.as_bytes() != &new_leaf {
                        *leaf = Hash256::from_slice(&new_leaf);
                        dirty.push(i);
                    }
                }
                None => {
                    if i < 2usize.pow(self.depth as u32) {
                        self.leaves().push(Hash256::from_slice(&new_leaf));
                        dirty.push(i);
                    } else {
                        return Err(Error::TooManyLeaves);
                    }
                }
            }
            num_new_leaves += 1;
        }

        // Disallow updates that reduce the number of leaves
        if num_new_leaves < self.leaves().len() {
            Err(Error::CannotShrink)
        } else {
            Ok(dirty)
        }
    }

    /// Phase 2: propagate changes upwards from the leaves of the tree, and compute the root.
    fn update_merkle_root(&mut self, mut dirty_indices: Vec<usize>) -> Hash256 {
        if dirty_indices.is_empty() {
            return self.root();
        }

        let mut depth = self.depth;

        while depth > 0 {
            let new_dirty_indices = lift_dirty(&dirty_indices);

            for &idx in &new_dirty_indices {
                let left_idx = 2 * idx;
                let right_idx = left_idx + 1;

                let left = self.layers[depth][left_idx];
                let right = self.layers[depth]
                    .get(right_idx)
                    .copied()
                    .unwrap_or_else(|| Hash256::from_slice(&ZERO_HASHES[self.depth - depth]));

                let new_hash = Hash256::from_slice(&hash_concat(left.as_bytes(), right.as_bytes()));

                match self.layers[depth - 1].get_mut(idx) {
                    Some(hash) => {
                        *hash = new_hash;
                    }
                    None => {
                        assert_eq!(self.layers[depth - 1].len(), idx);
                        self.layers[depth - 1].push(new_hash);
                    }
                }
            }

            dirty_indices = new_dirty_indices;
            depth -= 1;
        }

        self.root()
    }

    fn root(&self) -> Hash256 {
        self.layers[0]
            .get(0)
            .copied()
            .unwrap_or_else(|| Hash256::from_slice(&ZERO_HASHES[self.depth]))
    }

    fn leaves(&mut self) -> &mut Vec<Hash256> {
        &mut self.layers[self.depth]
    }
}

/// Compute the dirty indices for one layer up.
fn lift_dirty(dirty_indices: &[usize]) -> Vec<usize> {
    let mut new_dirty = dirty_indices.iter().map(|i| *i / 2).collect::<Vec<_>>();
    new_dirty.dedup();
    new_dirty
}
