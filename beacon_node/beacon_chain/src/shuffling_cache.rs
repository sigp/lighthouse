use crate::metrics;
use lru::LruCache;
use types::{beacon_state::CommitteeCache, AttestationShufflingId, Epoch, Hash256};

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
    cache: LruCache<AttestationShufflingId, CommitteeCache>,
}

impl ShufflingCache {
    pub fn new() -> Self {
        Self {
            cache: LruCache::new(CACHE_SIZE),
        }
    }

    pub fn get(&mut self, key: &AttestationShufflingId) -> Option<&CommitteeCache> {
        let opt = self.cache.get(key);

        if opt.is_some() {
            metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
        } else {
            metrics::inc_counter(&metrics::SHUFFLING_CACHE_MISSES);
        }

        opt
    }

    pub fn contains(&self, key: &AttestationShufflingId) -> bool {
        self.cache.contains(key)
    }

    pub fn insert(&mut self, key: AttestationShufflingId, committee_cache: &CommitteeCache) {
        if !self.cache.contains(&key) {
            self.cache.put(key, committee_cache.clone());
        }
    }
}

impl Default for ShufflingCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Contains the shuffling IDs for a beacon block.
pub struct BlockShufflingIds {
    pub current: AttestationShufflingId,
    pub next: AttestationShufflingId,
    pub block_root: Hash256,
}

impl BlockShufflingIds {
    /// Returns the shuffling ID for the given epoch.
    ///
    /// Returns `None` if `epoch` is prior to `self.current.shuffling_epoch`.
    pub fn id_for_epoch(&self, epoch: Epoch) -> Option<AttestationShufflingId> {
        if epoch == self.current.shuffling_epoch {
            Some(self.current.clone())
        } else if epoch == self.next.shuffling_epoch {
            Some(self.next.clone())
        } else if epoch > self.next.shuffling_epoch {
            Some(AttestationShufflingId::from_components(
                epoch,
                self.block_root,
            ))
        } else {
            None
        }
    }
}
