mod cache;
mod impls;
mod multi_cache;
#[cfg(test)]
mod test;

pub use crate::cache::TreeHashCache;
pub use crate::impls::int_log;
pub use crate::multi_cache::MultiTreeHashCache;
use ethereum_types::H256 as Hash256;
use tree_hash::TreeHash;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// Attempting to provide more than 2^depth leaves to a Merkle tree is disallowed.
    TooManyLeaves,
    /// Shrinking a Merkle tree cache by providing it with less leaves than it currently has is
    /// disallowed (for simplicity).
    CannotShrink,
    /// Cache is inconsistent with the list of dirty indices provided.
    CacheInconsistent,
}

/// Trait for types which can make use of a cache to accelerate calculation of their tree hash root.
pub trait CachedTreeHash<Cache>: TreeHash {
    /// Create a new cache appropriate for use with values of this type.
    fn new_tree_hash_cache() -> Cache;

    /// Update the cache and use it to compute the tree hash root for `self`.
    fn recalculate_tree_hash_root(&self, cache: &mut Cache) -> Result<Hash256, Error>;
}
