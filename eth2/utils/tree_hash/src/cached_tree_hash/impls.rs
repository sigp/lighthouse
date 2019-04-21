use super::*;

mod vec;

impl CachedTreeHashSubTree<u64> for u64 {
    fn new_tree_hash_cache(&self) -> Result<TreeHashCache, Error> {
        Ok(TreeHashCache::from_bytes(
            merkleize(self.to_le_bytes().to_vec()),
            false,
            self.tree_hash_cache_overlay(0)?,
        )?)
    }

    fn tree_hash_cache_overlay(&self, chunk_offset: usize) -> Result<BTreeOverlay, Error> {
        BTreeOverlay::from_lengths(chunk_offset, 1, vec![1])
    }

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error> {
        let leaf = merkleize(self.to_le_bytes().to_vec());
        cache.maybe_update_chunk(cache.chunk_index, &leaf)?;

        cache.chunk_index += 1;
        cache.overlay_index += 1;

        Ok(())
    }
}
