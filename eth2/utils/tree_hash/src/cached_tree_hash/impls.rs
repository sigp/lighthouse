use super::resize::{grow_merkle_cache, shrink_merkle_cache};
use super::*;

mod vec;

impl CachedTreeHashSubTree<u64> for u64 {
    fn new_tree_hash_cache(&self) -> Result<TreeHashCache, Error> {
        Ok(TreeHashCache::from_bytes(
            merkleize(self.to_le_bytes().to_vec()),
            false,
        )?)
    }

    fn tree_hash_cache_overlay(&self, chunk_offset: usize) -> Result<BTreeOverlay, Error> {
        BTreeOverlay::from_lengths(chunk_offset, vec![1])
    }

    fn update_tree_hash_cache(
        &self,
        other: &Self,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        if self != other {
            let leaf = merkleize(self.to_le_bytes().to_vec());
            cache.modify_chunk(chunk, &leaf)?;
        }

        Ok(chunk + 1)
    }
}
