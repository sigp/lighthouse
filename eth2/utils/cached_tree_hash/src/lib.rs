use hashing::hash;
use std::ops::Range;
use tree_hash::{TreeHash, TreeHashType, BYTES_PER_CHUNK, HASHSIZE};

mod btree_overlay;
mod errors;
pub mod impls;
pub mod merkleize;
mod resize;
mod tree_hash_cache;

pub use btree_overlay::{BTreeOverlay, BTreeSchema};
pub use errors::Error;
pub use tree_hash_cache::TreeHashCache;

pub trait CachedTreeHash<Item>: TreeHash {
    fn tree_hash_cache_schema(&self, depth: usize) -> BTreeSchema;

    fn num_tree_hash_cache_chunks(&self) -> usize {
        self.tree_hash_cache_schema(0).into_overlay(0).num_chunks()
    }

    fn new_tree_hash_cache(&self, depth: usize) -> Result<TreeHashCache, Error>;

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error>;
}

#[derive(Debug, PartialEq)]
pub struct CachedTreeHasher {
    cache: TreeHashCache,
}

impl CachedTreeHasher {
    pub fn new<T>(item: &T) -> Result<Self, Error>
    where
        T: CachedTreeHash<T>,
    {
        Ok(Self {
            cache: TreeHashCache::new(item, 0)?,
        })
    }

    pub fn update<T>(&mut self, item: &T) -> Result<(), Error>
    where
        T: CachedTreeHash<T>,
    {
        // Reset the per-hash counters.
        self.cache.chunk_index = 0;
        self.cache.schema_index = 0;

        // Reset the "modified" flags for the cache.
        self.cache.reset_modifications();

        // Update the cache with the (maybe) changed object.
        item.update_tree_hash_cache(&mut self.cache)?;

        Ok(())
    }

    pub fn tree_hash_root(&self) -> Result<Vec<u8>, Error> {
        // Return the root of the cache -- the merkle root.
        Ok(self.cache.root()?.to_vec())
    }
}
