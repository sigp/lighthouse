mod cache;
mod cache_arena;
mod impls;
#[cfg(test)]
mod test;
use smallvec::SmallVec;

type SmallVec8<T> = SmallVec<[T; 8]>;
pub type CacheArena = cache_arena::CacheArena<Hash256>;

pub use crate::cache::TreeHashCache;
pub use crate::impls::int_log;
use ethereum_types::H256 as Hash256;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// Attempting to provide more than 2^depth leaves to a Merkle tree is disallowed.
    TooManyLeaves,
    /// Shrinking a Merkle tree cache by providing it with less leaves than it currently has is
    /// disallowed (for simplicity).
    CannotShrink,
    /// Cache is inconsistent with the list of dirty indices provided.
    CacheInconsistent,
    CacheArenaError(cache_arena::Error),
    /// Unable to find left index in Merkle tree.
    MissingLeftIdx(usize),
}

impl From<cache_arena::Error> for Error {
    fn from(e: cache_arena::Error) -> Error {
        Error::CacheArenaError(e)
    }
}

/// Trait for types which can make use of a cache to accelerate calculation of their tree hash root.
pub trait CachedTreeHash<Cache> {
    /// Create a new cache appropriate for use with values of this type.
    fn new_tree_hash_cache(&self, arena: &mut CacheArena) -> Cache;

    /// Update the cache and use it to compute the tree hash root for `self`.
    fn recalculate_tree_hash_root(
        &self,
        arena: &mut CacheArena,
        cache: &mut Cache,
    ) -> Result<Hash256, Error>;
}
