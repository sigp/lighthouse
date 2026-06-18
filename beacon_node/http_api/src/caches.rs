use hashlink::lru_cache::LruCache;
use parking_lot::Mutex;
use std::sync::Arc;
use types::{AttestationShufflingId, CommitteeCache, Epoch};

/// See `shuffling_cache::DEFAULT_CACHE_SIZE` for rationale
pub const DEFAULT_HISTORICAL_COMMITTEE_CACHE_SIZE: usize = 16;

/// Indexes the `HistoricalCommitteeCache`. We can compute committees for very old epochs, and we
/// can't retrieve the decision root cheaply from a state. For those cases we allow the cache to
/// key those committees by finalized epoch.
#[derive(Eq, Hash, PartialEq)]
pub enum HistoricalShufflingId {
    FinalizedEpoch(Epoch),
    ShufflingId(AttestationShufflingId),
}

/// Dedicated cache for attestation committees, used exclusively by the HTTP API.
///
/// This may contain committees for finalized and unfinalized epochs. The name is slightly
/// missleading :)
pub struct HistoricalCommitteeCache {
    committees: Mutex<LruCache<HistoricalShufflingId, Arc<CommitteeCache>>>,
}

impl HistoricalCommitteeCache {
    pub fn new(size: usize) -> Self {
        Self {
            committees: Mutex::new(LruCache::new(size)),
        }
    }
}

impl HistoricalCommitteeCache {
    pub fn get(&self, id: &HistoricalShufflingId) -> Option<Arc<CommitteeCache>> {
        self.committees.lock().get(id).cloned()
    }

    pub fn insert(&self, id: HistoricalShufflingId, cache: Arc<CommitteeCache>) {
        self.committees.lock().insert(id, cache);
    }
}
