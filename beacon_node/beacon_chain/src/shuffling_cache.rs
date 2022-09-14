use crate::{metrics, BeaconChainError};
use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError};
use lru::LruCache;
use std::sync::Arc;
use types::{beacon_state::CommitteeCache, AttestationShufflingId, Epoch, Hash256};

/// The size of the LRU cache that stores committee caches for quicker verification.
///
/// Each entry should be `8 + 800,000 = 800,008` bytes in size with 100k validators. (8-byte hash +
/// 100k indices). Therefore, this cache should be approx `16 * 800,008 = 12.8 MB`. (Note: this
/// ignores a few extra bytes in the caches that should be insignificant compared to the indices).
const CACHE_SIZE: usize = 16;

#[derive(Clone)]
pub enum CacheItem {
    Ready(Arc<CommitteeCache>),
    Promise(Receiver<Arc<CommitteeCache>>),
}

impl CacheItem {
    pub fn wait(self) -> Result<Arc<CommitteeCache>, BeaconChainError> {
        match self {
            CacheItem::Ready(cache) => Ok(cache),
            CacheItem::Promise(receiver) => receiver
                .recv()
                .map_err(BeaconChainError::CommitteeCacheWait),
        }
    }
}

/// Provides an LRU cache for `CommitteeCache`.
///
/// It has been named `ShufflingCache` because `CommitteeCacheCache` is a bit weird and looks like
/// a find/replace error.
pub struct ShufflingCache {
    cache: LruCache<AttestationShufflingId, CacheItem>,
}

impl ShufflingCache {
    pub fn new() -> Self {
        Self {
            cache: LruCache::new(CACHE_SIZE),
        }
    }

    pub fn get(&mut self, key: &AttestationShufflingId) -> Option<CacheItem> {
        match self.cache.get(key) {
            // The cache contained the committee cache, return it.
            item @ Some(CacheItem::Ready(_)) => {
                metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
                item.cloned()
            }
            // The cache contains a promise for the committee cache. Check to see if the promise has
            // already been resolved, without waiting for it.
            item @ Some(CacheItem::Promise(receiver)) => match receiver.try_recv() {
                // The promise has already been resolved. Replace the entry in the cache with a
                // `Ready` entry and then return the committee.
                Ok(committee) => {
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
                    let ready = CacheItem::Ready(committee);
                    self.cache.put(key.clone(), ready.clone());
                    Some(ready)
                }
                // The promise has not yet been resolved. Return the promise so the caller can await
                // it.
                Err(TryRecvError::Empty) => {
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
                    item.cloned()
                }
                // The sender has been dropped without sending a committee. There was most likely
                // and error computing the committee cache. Drop the key from the cache and return
                // `None` so the caller can recompute the cache.
                Err(TryRecvError::Disconnected) => {
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_MISSES);
                    self.cache.pop(key);
                    None
                }
            },
            // The cache does not have this committee and it's not already promised to be computed.
            None => {
                metrics::inc_counter(&metrics::SHUFFLING_CACHE_MISSES);
                None
            }
        }
    }

    pub fn contains(&self, key: &AttestationShufflingId) -> bool {
        self.cache.contains(key)
    }

    pub fn insert_committee_cache(
        &mut self,
        key: AttestationShufflingId,
        committee_cache: &CommitteeCache,
    ) {
        if self
            .cache
            .get(&key)
            // Replace the committee if it's not present, or if it's a promise. An actual value is
            // always better than a promise!
            .map_or(true, |item| matches!(item, CacheItem::Promise(_)))
        {
            self.cache
                .put(key, CacheItem::Ready(Arc::new(committee_cache.clone())));
        }
    }

    #[must_use]
    pub fn create_promise(&mut self, key: AttestationShufflingId) -> Sender<Arc<CommitteeCache>> {
        let (sender, receiver) = bounded(1);
        self.cache.put(key, CacheItem::Promise(receiver));
        sender
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
