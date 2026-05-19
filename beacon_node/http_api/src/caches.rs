use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;
use types::{AttestationShufflingId, CommitteeCache};

const HISTORICAL_COMMITTEE_CACHE_SIZE: usize = 16;

pub struct HistoricalCommitteeCache {
    committees: Mutex<LruCache<AttestationShufflingId, Arc<CommitteeCache>>>,
}

impl Default for HistoricalCommitteeCache {
    fn default() -> Self {
        Self {
            committees: Mutex::new(LruCache::new(
                NonZeroUsize::new(HISTORICAL_COMMITTEE_CACHE_SIZE)
                    .expect("HISTORICAL_COMMITTEE_CACHE_SIZE is non-zero"),
            )),
        }
    }
}

impl HistoricalCommitteeCache {
    pub fn get(&self, id: &AttestationShufflingId) -> Option<Arc<CommitteeCache>> {
        self.committees.lock().get(id).cloned()
    }

    pub fn insert(&self, id: AttestationShufflingId, cache: Arc<CommitteeCache>) {
        self.committees.lock().put(id, cache);
    }
}
