use hashing::hash;
use merkleize::num_unsanitized_leaves;
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

#[macro_export]
macro_rules! cached_tree_hash_ssz_encoding_as_vector {
    ($type: ident, $num_bytes: expr) => {
        impl cached_tree_hash::CachedTreeHash<$type> for $type {
            fn new_tree_hash_cache(
                &self,
                depth: usize,
            ) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
                let (cache, _schema) = cached_tree_hash::impls::vec::new_tree_hash_cache(
                    &ssz::ssz_encode(self),
                    depth,
                )?;

                Ok(cache)
            }

            fn tree_hash_cache_schema(&self, depth: usize) -> cached_tree_hash::BTreeSchema {
                let lengths =
                    vec![1; cached_tree_hash::merkleize::num_unsanitized_leaves($num_bytes)];
                cached_tree_hash::BTreeSchema::from_lengths(depth, lengths)
            }

            fn update_tree_hash_cache(
                &self,
                cache: &mut cached_tree_hash::TreeHashCache,
            ) -> Result<(), cached_tree_hash::Error> {
                cached_tree_hash::impls::vec::update_tree_hash_cache(
                    &ssz::ssz_encode(self),
                    cache,
                )?;

                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! cached_tree_hash_bytes_as_list {
    ($type: ident) => {
        impl cached_tree_hash::CachedTreeHash<$type> for $type {
            fn new_tree_hash_cache(
                &self,
                depth: usize,
            ) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
                let bytes = self.to_bytes();

                let (mut cache, schema) =
                    cached_tree_hash::impls::vec::new_tree_hash_cache(&bytes, depth)?;

                cache.add_length_nodes(schema.into_overlay(0).chunk_range(), bytes.len())?;

                Ok(cache)
            }

            fn num_tree_hash_cache_chunks(&self) -> usize {
                // Add two extra nodes to cater for the node before and after to allow mixing-in length.
                cached_tree_hash::BTreeOverlay::new(self, 0, 0).num_chunks() + 2
            }

            fn tree_hash_cache_schema(&self, depth: usize) -> cached_tree_hash::BTreeSchema {
                cached_tree_hash::impls::vec::produce_schema(&ssz::ssz_encode(self), depth)
            }

            fn update_tree_hash_cache(
                &self,
                cache: &mut cached_tree_hash::TreeHashCache,
            ) -> Result<(), cached_tree_hash::Error> {
                let bytes = self.to_bytes();

                // Skip the length-mixed-in root node.
                cache.chunk_index += 1;

                // Update the cache, returning the new overlay.
                let new_overlay =
                    cached_tree_hash::impls::vec::update_tree_hash_cache(&bytes, cache)?;

                // Mix in length
                cache.mix_in_length(new_overlay.chunk_range(), bytes.len())?;

                // Skip an extra node to clear the length node.
                cache.chunk_index = new_overlay.next_node() + 1;

                Ok(())
            }
        }
    };
}
