use super::*;
use crate::merkleize::merkleize;
use ethereum_types::H256;

pub mod vec;

macro_rules! impl_for_single_leaf_int {
    ($type: ident) => {
        impl CachedTreeHash for $type {
            fn new_tree_hash_cache(&self, _depth: usize) -> Result<TreeHashCache, Error> {
                Ok(TreeHashCache::from_bytes(
                    merkleize(self.to_le_bytes().to_vec()),
                    false,
                    None,
                )?)
            }

            fn tree_hash_cache_schema(&self, depth: usize) -> BTreeSchema {
                BTreeSchema::from_lengths(depth, vec![1])
            }

            fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error> {
                let leaf = merkleize(self.to_le_bytes().to_vec());
                cache.maybe_update_chunk(cache.chunk_index, &leaf)?;

                cache.chunk_index += 1;

                Ok(())
            }
        }
    };
}

impl_for_single_leaf_int!(u8);
impl_for_single_leaf_int!(u16);
impl_for_single_leaf_int!(u32);
impl_for_single_leaf_int!(u64);
impl_for_single_leaf_int!(usize);

impl CachedTreeHash for bool {
    fn new_tree_hash_cache(&self, _depth: usize) -> Result<TreeHashCache, Error> {
        Ok(TreeHashCache::from_bytes(
            merkleize((*self as u8).to_le_bytes().to_vec()),
            false,
            None,
        )?)
    }

    fn tree_hash_cache_schema(&self, depth: usize) -> BTreeSchema {
        BTreeSchema::from_lengths(depth, vec![1])
    }

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error> {
        let leaf = merkleize((*self as u8).to_le_bytes().to_vec());
        cache.maybe_update_chunk(cache.chunk_index, &leaf)?;

        cache.chunk_index += 1;

        Ok(())
    }
}

macro_rules! impl_for_u8_array {
    ($len: expr) => {
        impl CachedTreeHash for [u8; $len] {
            fn new_tree_hash_cache(&self, _depth: usize) -> Result<TreeHashCache, Error> {
                Ok(TreeHashCache::from_bytes(
                    merkleize(self.to_vec()),
                    false,
                    None,
                )?)
            }

            fn tree_hash_cache_schema(&self, depth: usize) -> BTreeSchema {
                BTreeSchema::from_lengths(depth, vec![1])
            }

            fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error> {
                let leaf = merkleize(self.to_vec());
                cache.maybe_update_chunk(cache.chunk_index, &leaf)?;

                cache.chunk_index += 1;

                Ok(())
            }
        }
    };
}

impl_for_u8_array!(4);
impl_for_u8_array!(32);

impl CachedTreeHash for H256 {
    fn new_tree_hash_cache(&self, _depth: usize) -> Result<TreeHashCache, Error> {
        Ok(TreeHashCache::from_bytes(
            self.as_bytes().to_vec(),
            false,
            None,
        )?)
    }

    fn num_tree_hash_cache_chunks(&self) -> usize {
        1
    }

    fn tree_hash_cache_schema(&self, depth: usize) -> BTreeSchema {
        BTreeSchema::from_lengths(depth, vec![1])
    }

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error> {
        cache.maybe_update_chunk(cache.chunk_index, self.as_bytes())?;

        cache.chunk_index += 1;

        Ok(())
    }
}
