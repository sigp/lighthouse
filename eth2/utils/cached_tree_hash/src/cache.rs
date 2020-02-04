use crate::vec_arena;
use crate::{Error, Hash256};
use eth2_hashing::{hash32_concat, ZERO_HASHES};
use ssz_derive::{Decode, Encode};
use tree_hash::BYTES_PER_CHUNK;

type VecArena = vec_arena::VecArena<Hash256>;
type SubVecArena = vec_arena::SubVecArena<Hash256>;

/// Sparse Merkle tree suitable for tree hashing vectors and lists.
#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct TreeHashCache {
    pub initialized: bool,
    /// Depth is such that the tree has a capacity for 2^depth leaves
    depth: usize,
    /// Sparse layers.
    ///
    /// The leaves are contained in `self.layers[self.depth]`, and each other layer `i`
    /// contains the parents of the nodes in layer `i + 1`.
    layers: Vec<SubVecArena>,
}

fn nodes_per_layer(layer: usize, depth: usize, leaves: usize) -> usize {
    if layer == depth {
        leaves
    } else {
        let leaves_per_node = 1 << (depth - layer);
        (leaves + leaves_per_node - 1) / leaves_per_node
    }
}

impl TreeHashCache {
    /// Create a new cache with the given `depth` with enough nodes allocated to suit `leaves`. All
    /// leaves are set to `Hash256::zero()`>
    pub fn new(arena: &mut VecArena, depth: usize, leaves: usize) -> Self {
        // TODO: what about when leaves is zero?
        let layers = (0..=depth)
            .map(|i| {
                let mut vec = arena.alloc();
                vec.extend_with_vec(
                    arena,
                    vec![Hash256::zero(); nodes_per_layer(i, depth, leaves)],
                )
                .expect(
                    "A newly allocated sub-arena cannot fail unless it has reached max capacity",
                );

                vec
            })
            .collect();

        TreeHashCache {
            initialized: false,
            depth,
            layers,
        }
    }

    /// Compute the updated Merkle root for the given `leaves`.
    pub fn recalculate_merkle_root(
        &mut self,
        arena: &mut VecArena,
        leaves: impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator,
    ) -> Result<Hash256, Error> {
        let dirty_indices = self.update_leaves(arena, leaves)?;
        self.update_merkle_root(arena, dirty_indices)
    }

    /// Phase 1 of the algorithm: compute the indices of all dirty leaves.
    pub fn update_leaves(
        &mut self,
        arena: &mut VecArena,
        mut leaves: impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator,
    ) -> Result<Vec<usize>, Error> {
        let new_leaf_count = leaves.len();

        if new_leaf_count < self.leaves().len(arena)? {
            return Err(Error::CannotShrink);
        } else if new_leaf_count > 2usize.pow(self.depth as u32) {
            return Err(Error::TooManyLeaves);
        }

        // Update the existing leaves
        let mut dirty = self
            .leaves()
            .iter_mut(arena)
            .enumerate()
            .zip(&mut leaves)
            .flat_map(|((i, leaf), new_leaf)| {
                if leaf.as_bytes() != new_leaf || self.initialized == false {
                    leaf.assign_from_slice(&new_leaf);
                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Push the rest of the new leaves (if any)
        dirty.extend(self.leaves().len(arena)?..new_leaf_count);
        self.leaves()
            .extend_with_vec(arena, leaves.map(|l| Hash256::from_slice(&l)).collect())
            // TODO: fix expect
            .expect("should extend");

        Ok(dirty)
    }

    /// Phase 2: propagate changes upwards from the leaves of the tree, and compute the root.
    ///
    /// Returns an error if `dirty_indices` is inconsistent with the cache.
    pub fn update_merkle_root(
        &mut self,
        arena: &mut VecArena,
        mut dirty_indices: Vec<usize>,
    ) -> Result<Hash256, Error> {
        if dirty_indices.is_empty() {
            return Ok(self.root(arena));
        }

        let mut depth = self.depth;

        while depth > 0 {
            let new_dirty_indices = lift_dirty(&dirty_indices);

            for &idx in &new_dirty_indices {
                let left_idx = 2 * idx;
                let right_idx = left_idx + 1;

                let left = self.layers[depth]
                    .get(arena, left_idx)?
                    // TODO: fix expect
                    .expect("must have left idx");
                let right = self.layers[depth]
                    .get(arena, right_idx)?
                    .copied()
                    .unwrap_or_else(|| Hash256::from_slice(&ZERO_HASHES[self.depth - depth]));

                let new_hash = hash32_concat(left.as_bytes(), right.as_bytes());

                match self.layers[depth - 1].get_mut(arena, idx)? {
                    Some(hash) => {
                        hash.assign_from_slice(&new_hash);
                    }
                    None => {
                        // Parent layer should already contain nodes for all non-dirty indices
                        if idx != self.layers[depth - 1].len(arena)? {
                            return Err(Error::CacheInconsistent);
                        }
                        self.layers[depth - 1]
                            .push(arena, Hash256::from_slice(&new_hash))
                            // TODO: fix expect
                            .expect("should push");
                    }
                }
            }

            dirty_indices = new_dirty_indices;
            depth -= 1;
        }

        self.initialized = true;

        Ok(self.root(arena))
    }

    /// Get the root of this cache, without doing any updates/computation.
    pub fn root(&self, arena: &VecArena) -> Hash256 {
        self.layers[0]
            .get(arena, 0)
            // TODO: deal with expect
            .expect("arena should be known")
            .copied()
            .unwrap_or_else(|| Hash256::from_slice(&ZERO_HASHES[self.depth]))
    }

    pub fn leaves(&mut self) -> &mut SubVecArena {
        &mut self.layers[self.depth]
    }

    /// Returns the approximate size of the cache in bytes.
    ///
    /// The size is approximate because we ignore some stack-allocated `u64` and `Vec` pointers.
    /// We focus instead on the lists of hashes, which should massively outweigh the items that we
    /// ignore.
    pub fn approx_mem_size(&self) -> usize {
        self.layers.iter().map(|layer| layer.len() * 32).sum()
    }
}

/// Compute the dirty indices for one layer up.
fn lift_dirty(dirty_indices: &[usize]) -> Vec<usize> {
    let mut new_dirty = dirty_indices.iter().map(|i| *i / 2).collect::<Vec<_>>();
    new_dirty.dedup();
    new_dirty
}
