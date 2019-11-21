use crate::{Error, Hash256};
use eth2_hashing::{hash_concat, ZERO_HASHES};
use ssz_derive::{Decode, Encode};
use tree_hash::BYTES_PER_CHUNK;

/// Sparse Merkle tree suitable for tree hashing vectors and lists.
#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
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
        leaves: impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator,
    ) -> Result<Hash256, Error> {
        let dirty_indices = self.update_leaves(leaves)?;
        self.update_merkle_root(dirty_indices)
    }

    /// Phase 1 of the algorithm: compute the indices of all dirty leaves.
    pub fn update_leaves(
        &mut self,
        mut leaves: impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator,
    ) -> Result<Vec<usize>, Error> {
        let new_leaf_count = leaves.len();

        if new_leaf_count < self.leaves().len() {
            return Err(Error::CannotShrink);
        } else if new_leaf_count > 2usize.pow(self.depth as u32) {
            return Err(Error::TooManyLeaves);
        }

        // Update the existing leaves
        let mut dirty = self
            .leaves()
            .iter_mut()
            .enumerate()
            .zip(&mut leaves)
            .flat_map(|((i, leaf), new_leaf)| {
                if leaf.as_bytes() != new_leaf {
                    leaf.assign_from_slice(&new_leaf);
                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Push the rest of the new leaves (if any)
        dirty.extend(self.leaves().len()..new_leaf_count);
        self.leaves()
            .extend(leaves.map(|l| Hash256::from_slice(&l)));

        Ok(dirty)
    }

    /// Phase 2: propagate changes upwards from the leaves of the tree, and compute the root.
    ///
    /// Returns an error if `dirty_indices` is inconsistent with the cache.
    pub fn update_merkle_root(&mut self, mut dirty_indices: Vec<usize>) -> Result<Hash256, Error> {
        if dirty_indices.is_empty() {
            return Ok(self.root());
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

                let new_hash = hash_concat(left.as_bytes(), right.as_bytes());

                match self.layers[depth - 1].get_mut(idx) {
                    Some(hash) => {
                        hash.assign_from_slice(&new_hash);
                    }
                    None => {
                        // Parent layer should already contain nodes for all non-dirty indices
                        if idx != self.layers[depth - 1].len() {
                            return Err(Error::CacheInconsistent);
                        }
                        self.layers[depth - 1].push(Hash256::from_slice(&new_hash));
                    }
                }
            }

            dirty_indices = new_dirty_indices;
            depth -= 1;
        }

        Ok(self.root())
    }

    /// Get the root of this cache, without doing any updates/computation.
    pub fn root(&self) -> Hash256 {
        self.layers[0]
            .get(0)
            .copied()
            .unwrap_or_else(|| Hash256::from_slice(&ZERO_HASHES[self.depth]))
    }

    pub fn leaves(&mut self) -> &mut Vec<Hash256> {
        &mut self.layers[self.depth]
    }
}

/// Compute the dirty indices for one layer up.
fn lift_dirty(dirty_indices: &[usize]) -> Vec<usize> {
    let mut new_dirty = dirty_indices.iter().map(|i| *i / 2).collect::<Vec<_>>();
    new_dirty.dedup();
    new_dirty
}
