use lru::LruCache;
use types::{
    beacon_state::CommitteeCache, BeaconState, BeaconStateError, Epoch, EthSpec, Hash256,
    RelativeEpoch, ShufflingId,
};

/// The size of the LRU cache that stores committee caches for quicker verification.
///
/// Each entry should be `8 + 800,000 = 800,008` bytes in size with 100k validators. (8-byte hash + 100k indices). Therefore, this cache should be approx `16 * 800,008 = 12.8 MB`. (Note: this ignores a few extra bytes in the caches that should be insignificant compared to the indices).
///
/// I have used a size `16` because it allows for 4 epochs since finality with 4 different forks.
const CACHE_SIZE: usize = 16;

/// Provides an LRU cache for `CommitteeCache`.
///
/// It has been named `ShufflingCache` because `CommitteeCacheCache` is a bit weird and looks like
/// a find/replace error.
pub struct ShufflingCache {
    cache: LruCache<(Epoch, Hash256), CommitteeCache>,
}

// TODO: add a prune method to the cache.

impl ShufflingCache {
    pub fn new() -> Self {
        Self {
            cache: LruCache::new(CACHE_SIZE),
        }
    }

    pub fn get(&mut self, epoch: Epoch, root: Hash256) -> Option<&CommitteeCache> {
        self.cache.get(&(epoch, root))
    }

    pub fn insert(&mut self, epoch: Epoch, root: Hash256, committee_cache: &CommitteeCache) {
        let key = (epoch, root);

        if !self.cache.contains(&key) {
            self.cache.put(key, committee_cache.clone());
        }
    }
}
