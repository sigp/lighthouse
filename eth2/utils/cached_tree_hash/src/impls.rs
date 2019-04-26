use super::*;
use crate::merkleize::merkleize;

pub mod vec;

impl CachedTreeHash<u64> for u64 {
    fn new_tree_hash_cache(&self, _depth: usize) -> Result<TreeHashCache, Error> {
        Ok(TreeHashCache::from_bytes(
            merkleize(self.to_le_bytes().to_vec()),
            false,
            None,
        )?)
    }

    fn num_tree_hash_cache_chunks(&self) -> usize {
        1
    }

    fn tree_hash_cache_overlay(&self, _chunk_offset: usize, _depth: usize) -> BTreeOverlay {
        unreachable!("Basic should not produce overlay");
    }

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error> {
        let leaf = merkleize(self.to_le_bytes().to_vec());
        cache.maybe_update_chunk(cache.chunk_index, &leaf)?;

        cache.chunk_index += 1;
        // cache.overlay_index += 1;

        Ok(())
    }
}

impl CachedTreeHash<usize> for usize {
    fn new_tree_hash_cache(&self, _depth: usize) -> Result<TreeHashCache, Error> {
        Ok(TreeHashCache::from_bytes(
            merkleize(self.to_le_bytes().to_vec()),
            false,
            None,
        )?)
    }

    fn num_tree_hash_cache_chunks(&self) -> usize {
        1
    }

    fn tree_hash_cache_overlay(&self, _chunk_offset: usize, _depth: usize) -> BTreeOverlay {
        unreachable!("Basic should not produce overlay");
    }

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error> {
        let leaf = merkleize(self.to_le_bytes().to_vec());
        cache.maybe_update_chunk(cache.chunk_index, &leaf)?;

        cache.chunk_index += 1;
        // cache.overlay_index += 1;

        Ok(())
    }
}
