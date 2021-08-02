#![allow(clippy::integer_arithmetic)]

use crate::{Hash256, ParticipationFlags, Unsigned, VariableList};
use cached_tree_hash::{int_log, CacheArena, CachedTreeHash, Error, TreeHashCache};
use tree_hash::{mix_in_length, BYTES_PER_CHUNK};

/// Wrapper type allowing the implementation of `CachedTreeHash`.
#[derive(Debug)]
pub struct ParticipationList<'a, N: Unsigned> {
    pub inner: &'a VariableList<ParticipationFlags, N>,
}

impl<'a, N: Unsigned> ParticipationList<'a, N> {
    pub fn new(inner: &'a VariableList<ParticipationFlags, N>) -> Self {
        Self { inner }
    }
}

impl<'a, N: Unsigned> CachedTreeHash<TreeHashCache> for ParticipationList<'a, N> {
    fn new_tree_hash_cache(&self, arena: &mut CacheArena) -> TreeHashCache {
        TreeHashCache::new(
            arena,
            int_log(N::to_usize() / BYTES_PER_CHUNK),
            leaf_count(self.inner.len()),
        )
    }

    fn recalculate_tree_hash_root(
        &self,
        arena: &mut CacheArena,
        cache: &mut TreeHashCache,
    ) -> Result<Hash256, Error> {
        Ok(mix_in_length(
            &cache.recalculate_merkle_root(arena, leaf_iter(self.inner))?,
            self.inner.len(),
        ))
    }
}

pub fn leaf_count(len: usize) -> usize {
    (len + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK
}

pub fn leaf_iter(
    values: &[ParticipationFlags],
) -> impl Iterator<Item = [u8; BYTES_PER_CHUNK]> + ExactSizeIterator + '_ {
    values.chunks(BYTES_PER_CHUNK).map(|xs| {
        // Zero-pad chunks on the right.
        let mut chunk = [0u8; BYTES_PER_CHUNK];
        for (byte, x) in chunk.iter_mut().zip(xs) {
            *byte = x.into_u8();
        }
        chunk
    })
}
