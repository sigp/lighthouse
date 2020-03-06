use crate::metrics;
use lru::LruCache;
use types::{beacon_state::CommitteeCache, Epoch, Hash256};

/// The size of the LRU cache that stores committee caches for quicker verification.
///
/// Each entry should be `8 + 800,000 = 800,008` bytes in size with 100k validators. (8-byte hash +
/// 100k indices). Therefore, this cache should be approx `16 * 800,008 = 12.8 MB`. (Note: this
/// ignores a few extra bytes in the caches that should be insignificant compared to the indices).
const CACHE_SIZE: usize = 16;

/// Provides an LRU cache for `CommitteeCache`.
///
/// It has been named `ShufflingCache` because `CommitteeCacheCache` is a bit weird and looks like
/// a find/replace error.
pub struct ShufflingCache {
    cache: LruCache<(Epoch, Hash256), CommitteeCache>,
}

impl ShufflingCache {
    pub fn new() -> Self {
        Self {
            cache: LruCache::new(CACHE_SIZE),
        }
    }

    pub fn get(&mut self, epoch: Epoch, root: Hash256) -> Option<&CommitteeCache> {
        let opt = self.cache.get(&(epoch, root));

        if opt.is_some() {
            metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
        } else {
            metrics::inc_counter(&metrics::SHUFFLING_CACHE_MISSES);
        }

        opt
    }

    pub fn insert(&mut self, epoch: Epoch, root: Hash256, committee_cache: &CommitteeCache) {
        let key = (epoch, root);

        if !self.cache.contains(&key) {
            self.cache.put(key, committee_cache.clone());
        }
    }
}
