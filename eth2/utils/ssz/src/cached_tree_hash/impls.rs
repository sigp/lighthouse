use super::*;
use crate::ssz_encode;

impl CachedTreeHash for u64 {
    fn build_cache_bytes(&self) -> Vec<u8> {
        merkleize(ssz_encode(self))
    }

    fn num_bytes(&self) -> usize {
        8
    }

    fn max_num_leaves(&self) -> usize {
        1
    }

    fn cached_hash_tree_root(
        &self,
        other: &Self,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Option<usize> {
        if self != other {
            let leaf = merkleize(ssz_encode(self));
            cache.modify_chunk(chunk, &leaf)?;
        }

        Some(chunk + 1)
    }
}
