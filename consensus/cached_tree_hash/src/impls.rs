use crate::{CacheArena, CachedTreeHash, Error, Hash256, TreeHashCache};
use ssz_types::{typenum::Unsigned, FixedVector, VariableList};
use std::mem::size_of;
use tree_hash::{mix_in_length, BYTES_PER_CHUNK};

/// Compute ceil(log(n))
///
/// Smallest number of bits d so that n <= 2^d
pub fn int_log(n: usize) -> usize {
    match n.checked_next_power_of_two() {
        Some(x) => x.trailing_zeros() as usize,
        None => 8 * std::mem::size_of::<usize>(),
    }
}

pub fn hash256_leaf_count(len: usize) -> usize {
    len
}

pub fn u64_leaf_count(len: usize) -> usize {
    let type_size = size_of::<u64>();
    let vals_per_chunk = BYTES_PER_CHUNK / type_size;

    (len + vals_per_chunk - 1) / vals_per_chunk
}

pub fn hash256_iter(
    values: &[Hash256],
) -> impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator + '_ {
    values.iter().copied().map(Hash256::to_fixed_bytes)
}

pub fn u64_iter(
    values: &[u64],
) -> impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator + '_ {
    let type_size = size_of::<u64>();
    let vals_per_chunk = BYTES_PER_CHUNK / type_size;
    values.chunks(vals_per_chunk).map(move |xs| {
        xs.iter().map(|x| x.to_le_bytes()).enumerate().fold(
            [0; BYTES_PER_CHUNK],
            |mut chunk, (i, x_bytes)| {
                chunk[i * type_size..(i + 1) * type_size].copy_from_slice(&x_bytes);
                chunk
            },
        )
    })
}

impl<N: Unsigned> CachedTreeHash<TreeHashCache> for FixedVector<Hash256, N> {
    fn new_tree_hash_cache(&self, arena: &mut CacheArena) -> TreeHashCache {
        TreeHashCache::new(
            arena,
            int_log(N::to_usize()),
            hash256_leaf_count(self.len()),
        )
    }

    fn recalculate_tree_hash_root(
        &self,
        arena: &mut CacheArena,
        cache: &mut TreeHashCache,
    ) -> Result<Hash256, Error> {
        cache.recalculate_merkle_root(arena, hash256_iter(self))
    }
}

impl<N: Unsigned> CachedTreeHash<TreeHashCache> for FixedVector<u64, N> {
    fn new_tree_hash_cache(&self, arena: &mut CacheArena) -> TreeHashCache {
        let vals_per_chunk = BYTES_PER_CHUNK / size_of::<u64>();
        TreeHashCache::new(
            arena,
            int_log(N::to_usize() / vals_per_chunk),
            u64_leaf_count(self.len()),
        )
    }

    fn recalculate_tree_hash_root(
        &self,
        arena: &mut CacheArena,
        cache: &mut TreeHashCache,
    ) -> Result<Hash256, Error> {
        cache.recalculate_merkle_root(arena, u64_iter(self))
    }
}

impl<N: Unsigned> CachedTreeHash<TreeHashCache> for VariableList<Hash256, N> {
    fn new_tree_hash_cache(&self, arena: &mut CacheArena) -> TreeHashCache {
        TreeHashCache::new(
            arena,
            int_log(N::to_usize()),
            hash256_leaf_count(self.len()),
        )
    }

    fn recalculate_tree_hash_root(
        &self,
        arena: &mut CacheArena,
        cache: &mut TreeHashCache,
    ) -> Result<Hash256, Error> {
        Ok(mix_in_length(
            &cache.recalculate_merkle_root(arena, hash256_iter(self))?,
            self.len(),
        ))
    }
}

impl<N: Unsigned> CachedTreeHash<TreeHashCache> for VariableList<u64, N> {
    fn new_tree_hash_cache(&self, arena: &mut CacheArena) -> TreeHashCache {
        let vals_per_chunk = BYTES_PER_CHUNK / size_of::<u64>();
        TreeHashCache::new(
            arena,
            int_log(N::to_usize() / vals_per_chunk),
            u64_leaf_count(self.len()),
        )
    }

    fn recalculate_tree_hash_root(
        &self,
        arena: &mut CacheArena,
        cache: &mut TreeHashCache,
    ) -> Result<Hash256, Error> {
        Ok(mix_in_length(
            &cache.recalculate_merkle_root(arena, u64_iter(self))?,
            self.len(),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_int_log() {
        for i in 0..63 {
            assert_eq!(int_log(2usize.pow(i)), i as usize);
        }
        assert_eq!(int_log(10), 4);
    }
}
