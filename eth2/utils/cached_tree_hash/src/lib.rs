mod cache;
mod impls;
#[cfg(test)]
mod test;

pub use crate::cache::TreeHashCache;
use ethereum_types::H256 as Hash256;
use tree_hash::TreeHash;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Attempting to provide more than 2^depth leaves to a Merkle tree is disallowed.
    TooManyLeaves,
    /// Shrinking a Merkle tree cache by providing it with less leaves than it currently has is
    /// disallowed (for simplicity).
    CannotShrink,
}

/// Trait for types which can make use of a cache to accelerate calculation of their tree hash root.
pub trait CachedTreeHash: TreeHash {
    type Cache;

    /// Create a new cache appropriate for use with `self`.
    fn new_tree_hash_cache(&self) -> Self::Cache;

    /// Update the cache and use it to compute the tree hash root for `self`.
    fn recalculate_tree_hash_root(&self, cache: &mut Self::Cache) -> Result<Hash256, Error>;
}
