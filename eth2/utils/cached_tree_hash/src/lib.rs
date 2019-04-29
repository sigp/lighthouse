//! Performs cached merkle-hashing adhering to the Ethereum 2.0 specification defined
//! [here](https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/simple-serialize.md#merkleization).
//!
//! Caching allows for reduced hashing when some object has only been partially modified. This
//! allows for significant CPU-time savings (at the cost of additional storage). For example,
//! determining the root of a list of 1024 items with a single modification has been observed to
//! run in 1/25th of the time of a full merkle hash.
//!
//!
//! # Example:
//!
//! ```
//! use cached_tree_hash::TreeHashCache;
//! use tree_hash_derive::{TreeHash, CachedTreeHash};
//!
//! #[derive(TreeHash, CachedTreeHash)]
//! struct Foo {
//!     bar: u64,
//!     baz: Vec<u64>
//! }
//!
//! let mut foo = Foo {
//!     bar: 1,
//!     baz: vec![0, 1, 2]
//! };
//!
//! let mut cache = TreeHashCache::new(&foo).unwrap();
//!
//! foo.baz[1] = 0;
//!
//! cache.update(&foo).unwrap();
//!
//! println!("Root is: {:?}", cache.tree_hash_root().unwrap());
//! ```

use hashing::hash;
use std::ops::Range;
use tree_hash::{TreeHash, TreeHashType, BYTES_PER_CHUNK, HASHSIZE};

mod btree_overlay;
mod errors;
mod impls;
pub mod merkleize;
mod resize;
mod tree_hash_cache;

pub use btree_overlay::{BTreeOverlay, BTreeSchema};
pub use errors::Error;
pub use impls::vec;
pub use tree_hash_cache::TreeHashCache;

pub trait CachedTreeHash: TreeHash {
    fn tree_hash_cache_schema(&self, depth: usize) -> BTreeSchema;

    fn num_tree_hash_cache_chunks(&self) -> usize {
        self.tree_hash_cache_schema(0).into_overlay(0).num_chunks()
    }

    fn new_tree_hash_cache(&self, depth: usize) -> Result<TreeHashCache, Error>;

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error>;
}

/// Implements `CachedTreeHash` on `$type` as a fixed-length tree-hash vector of the ssz encoding
/// of `$type`.
#[macro_export]
macro_rules! cached_tree_hash_ssz_encoding_as_vector {
    ($type: ident, $num_bytes: expr) => {
        impl cached_tree_hash::CachedTreeHash for $type {
            fn new_tree_hash_cache(
                &self,
                depth: usize,
            ) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
                let (cache, _schema) =
                    cached_tree_hash::vec::new_tree_hash_cache(&ssz::ssz_encode(self), depth)?;

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
                cached_tree_hash::vec::update_tree_hash_cache(&ssz::ssz_encode(self), cache)?;

                Ok(())
            }
        }
    };
}

/// Implements `CachedTreeHash` on `$type` as a variable-length tree-hash list of the result of
/// calling `.as_bytes()` on `$type`.
#[macro_export]
macro_rules! cached_tree_hash_bytes_as_list {
    ($type: ident) => {
        impl cached_tree_hash::CachedTreeHash for $type {
            fn new_tree_hash_cache(
                &self,
                depth: usize,
            ) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
                let bytes = self.to_bytes();

                let (mut cache, schema) =
                    cached_tree_hash::vec::new_tree_hash_cache(&bytes, depth)?;

                cache.add_length_nodes(schema.into_overlay(0).chunk_range(), bytes.len())?;

                Ok(cache)
            }

            fn num_tree_hash_cache_chunks(&self) -> usize {
                // Add two extra nodes to cater for the node before and after to allow mixing-in length.
                cached_tree_hash::BTreeOverlay::new(self, 0, 0).num_chunks() + 2
            }

            fn tree_hash_cache_schema(&self, depth: usize) -> cached_tree_hash::BTreeSchema {
                let bytes = self.to_bytes();
                cached_tree_hash::vec::produce_schema(&bytes, depth)
            }

            fn update_tree_hash_cache(
                &self,
                cache: &mut cached_tree_hash::TreeHashCache,
            ) -> Result<(), cached_tree_hash::Error> {
                let bytes = self.to_bytes();

                // Skip the length-mixed-in root node.
                cache.chunk_index += 1;

                // Update the cache, returning the new overlay.
                let new_overlay = cached_tree_hash::vec::update_tree_hash_cache(&bytes, cache)?;

                // Mix in length
                cache.mix_in_length(new_overlay.chunk_range(), bytes.len())?;

                // Skip an extra node to clear the length node.
                cache.chunk_index += 1;

                Ok(())
            }
        }
    };
}
