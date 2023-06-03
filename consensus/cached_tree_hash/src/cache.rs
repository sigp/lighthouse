use crate::cache_arena;
use crate::SmallVec8;
use crate::{Error, Hash256};
use ethereum_hashing::{hash32_concat, ZERO_HASHES};
use smallvec::smallvec;
use ssz_derive::{Decode, Encode};
use tree_hash::BYTES_PER_CHUNK;

type CacheArena = cache_arena::CacheArena<Hash256>;
type CacheArenaAllocation = cache_arena::CacheArenaAllocation<Hash256>;

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
    layers: SmallVec8<CacheArenaAllocation>,
}

impl TreeHashCache {
    /// Create a new cache with the given `depth` with enough nodes allocated to suit `leaves`. All
    /// leaves are set to `Hash256::zero()`.
    pub fn new(arena: &mut CacheArena, depth: usize, leaves: usize) -> Self {
        let mut layers = SmallVec8::with_capacity(depth + 1);

        for i in 0..=depth {
            let vec = arena.alloc();
            vec.extend_with_vec(
                arena,
                smallvec![Hash256::zero(); nodes_per_layer(i, depth, leaves)],
            )
            .expect("A newly allocated sub-arena cannot fail unless it has reached max capacity");

            layers.push(vec)
        }

        TreeHashCache {
            initialized: false,
            depth,
            layers,
        }
    }

    /// Compute the updated Merkle root for the given `leaves`.
    pub fn recalculate_merkle_root(
        &mut self,
        arena: &mut CacheArena,
        leaves: impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator,
    ) -> Result<Hash256, Error> {
        let dirty_indices = self.update_leaves(arena, leaves)?;
        self.update_merkle_root(arena, dirty_indices)
    }

    /// Phase 1 of the algorithm: compute the indices of all dirty leaves.
    pub fn update_leaves(
        &mut self,
        arena: &mut CacheArena,
        mut leaves: impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator,
    ) -> Result<SmallVec8<usize>, Error> {
        let new_leaf_count = leaves.len();

        if new_leaf_count < self.leaves().len(arena)? {
            return Err(Error::CannotShrink);
        } else if new_leaf_count > 2usize.pow(self.depth as u32) {
            return Err(Error::TooManyLeaves);
        }

        let mut dirty = SmallVec8::new();

        // Update the existing leaves
        self.leaves()
            .iter_mut(arena)?
            .enumerate()
            .zip(&mut leaves)
            .for_each(|((i, leaf), new_leaf)| {
                if !self.initialized || leaf.as_bytes() != new_leaf {
                    leaf.assign_from_slice(&new_leaf);
                    dirty.push(i);
                }
            });

        // Push the rest of the new leaves (if any)
        dirty.extend(self.leaves().len(arena)?..new_leaf_count);
        self.leaves()
            .extend_with_vec(arena, leaves.map(|l| Hash256::from_slice(&l)).collect())?;

        Ok(dirty)
    }

    /// Phase 2: propagate changes upwards from the leaves of the tree, and compute the root.
    ///
    /// Returns an error if `dirty_indices` is inconsistent with the cache.
    pub fn update_merkle_root(
        &mut self,
        arena: &mut CacheArena,
        mut dirty_indices: SmallVec8<usize>,
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
                    .ok_or(Error::MissingLeftIdx(left_idx))?;
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
                        self.layers[depth - 1].push(arena, Hash256::from_slice(&new_hash))?;
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
    pub fn root(&self, arena: &CacheArena) -> Hash256 {
        self.layers[0]
            .get(arena, 0)
            .expect("cached tree should have a root layer")
            .copied()
            .unwrap_or_else(|| Hash256::from_slice(&ZERO_HASHES[self.depth]))
    }

    pub fn leaves(&mut self) -> &mut CacheArenaAllocation {
        &mut self.layers[self.depth]
    }
}

/// Compute the dirty indices for one layer up.
fn lift_dirty(dirty_indices: &[usize]) -> SmallVec8<usize> {
    let mut new_dirty = SmallVec8::with_capacity(dirty_indices.len());

    for index in dirty_indices {
        new_dirty.push(index / 2)
    }

    new_dirty.dedup();
    new_dirty
}

/// Returns the number of nodes that should be at each layer of a tree with the given `depth` and
/// number of `leaves`.
///
/// Note: the top-most layer is `0` and a tree that has 8 leaves (4 layers) has a depth of 3 (_not_
/// a depth of 4).
///
/// ## Example
///
/// Consider the following tree that has `depth = 3` and `leaves = 5`.
///
///```ignore
/// 0        o      <-- height 0 has 1 node
///        /   \
/// 1    o      o   <-- height 1 has 2 nodes
///     / \    /
/// 2  o   o   o    <-- height 2 has 3 nodes
///   /\   /\ /
/// 3 o o o o o     <-- height 3 have 5 nodes
/// ```
fn nodes_per_layer(layer: usize, depth: usize, leaves: usize) -> usize {
    if layer == depth {
        leaves
    } else {
        let leaves_per_node = 1 << (depth - layer);
        (leaves + leaves_per_node - 1) / leaves_per_node
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn zero_leaves() {
        let arena = &mut CacheArena::default();

        let depth = 3;
        let num_leaves = 0;

        let mut cache = TreeHashCache::new(arena, depth, num_leaves);
        let leaves: Vec<[u8; BYTES_PER_CHUNK]> = vec![];

        cache
            .recalculate_merkle_root(arena, leaves.into_iter())
            .expect("should calculate root");
    }

    #[test]
    fn test_node_per_layer_unbalanced_tree() {
        assert_eq!(nodes_per_layer(0, 3, 5), 1);
        assert_eq!(nodes_per_layer(1, 3, 5), 2);
        assert_eq!(nodes_per_layer(2, 3, 5), 3);
        assert_eq!(nodes_per_layer(3, 3, 5), 5);
    }

    #[test]
    fn test_node_per_layer_balanced_tree() {
        assert_eq!(nodes_per_layer(0, 3, 8), 1);
        assert_eq!(nodes_per_layer(1, 3, 8), 2);
        assert_eq!(nodes_per_layer(2, 3, 8), 4);
        assert_eq!(nodes_per_layer(3, 3, 8), 8);
    }
}
