use super::resize::{grow_merkle_cache, shrink_merkle_cache};
use super::*;
use ssz::ssz_encode;

mod vec;

impl CachedTreeHash<u64> for u64 {
    fn item_type() -> ItemType {
        ItemType::Basic
    }

    fn new_cache(&self) -> Result<TreeHashCache, Error> {
        Ok(TreeHashCache::from_bytes(
            merkleize(ssz_encode(self)),
            false,
        )?)
    }

    fn btree_overlay(&self, chunk_offset: usize) -> Result<BTreeOverlay, Error> {
        BTreeOverlay::from_lengths(chunk_offset, vec![1])
    }

    fn packed_encoding(&self) -> Result<Vec<u8>, Error> {
        Ok(ssz_encode(self))
    }

    fn packing_factor() -> usize {
        HASHSIZE / 8
    }

    fn update_cache(
        &self,
        other: &Self,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        if self != other {
            let leaf = merkleize(ssz_encode(self));
            cache.modify_chunk(chunk, &leaf)?;
        }

        Ok(chunk + 1)
    }
}
