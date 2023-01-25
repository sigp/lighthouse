use crate::{metrics, BeaconChainError};
use lru::LruCache;
use oneshot_broadcast::{oneshot, Receiver, Sender};
use std::sync::Arc;
use types::{beacon_state::CommitteeCache, AttestationShufflingId, Epoch, Hash256};

/// The size of the LRU cache that stores committee caches for quicker verification.
///
/// Each entry should be `8 + 800,000 = 800,008` bytes in size with 100k validators. (8-byte hash +
/// 100k indices). Therefore, this cache should be approx `16 * 800,008 = 12.8 MB`. (Note: this
/// ignores a few extra bytes in the caches that should be insignificant compared to the indices).
const CACHE_SIZE: usize = 16;

/// The maximum number of concurrent committee cache "promises" that can be issued. In effect, this
/// limits the number of concurrent states that can be loaded into memory for the committee cache.
/// This prevents excessive memory usage at the cost of rejecting some attestations.
///
/// We set this value to 2 since states can be quite large and have a significant impact on memory
/// usage. A healthy network cannot have more than a few committee caches and those caches should
/// always be inserted during block import. Unstable networks with a high degree of forking might
/// see some attestations dropped due to this concurrency limit, however I propose that this is
/// better than low-resource nodes going OOM.
const MAX_CONCURRENT_PROMISES: usize = 2;

#[derive(Clone)]
pub enum CacheItem {
    /// A committee.
    Committee(Arc<CommitteeCache>),
    /// A promise for a future committee.
    Promise(Receiver<Arc<CommitteeCache>>),
}

impl CacheItem {
    pub fn is_promise(&self) -> bool {
        matches!(self, CacheItem::Promise(_))
    }

    pub fn wait(self) -> Result<Arc<CommitteeCache>, BeaconChainError> {
        match self {
            CacheItem::Committee(cache) => Ok(cache),
            CacheItem::Promise(receiver) => receiver
                .recv()
                .map_err(BeaconChainError::CommitteePromiseFailed),
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
            item @ Some(CacheItem::Committee(_)) => {
                metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
                item.cloned()
            }
            // The cache contains a promise for the committee cache. Check to see if the promise has
            // already been resolved, without waiting for it.
            item @ Some(CacheItem::Promise(receiver)) => match receiver.try_recv() {
                // The promise has already been resolved. Replace the entry in the cache with a
                // `Committee` entry and then return the committee.
                Ok(Some(committee)) => {
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_PROMISE_HITS);
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
                    let ready = CacheItem::Committee(committee);
                    self.cache.put(key.clone(), ready.clone());
                    Some(ready)
                }
                // The promise has not yet been resolved. Return the promise so the caller can await
                // it.
                Ok(None) => {
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_PROMISE_HITS);
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
                    item.cloned()
                }
                // The sender has been dropped without sending a committee. There was most likely an
                // error computing the committee cache. Drop the key from the cache and return
                // `None` so the caller can recompute the committee.
                //
                // It's worth noting that this is the only place where we removed unresolved
                // promises from the cache. This means unresolved promises will only be removed if
                // we try to access them again. This is OK, since the promises don't consume much
                // memory and the nature of the LRU cache means that future, relevant entries will
                // still be added to the cache. We expect that *all* promises should be resolved,
                // unless there is a programming or database error.
                Err(oneshot_broadcast::Error::SenderDropped) => {
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_PROMISE_FAILS);
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

    pub fn insert_committee_cache<T: ToArcCommitteeCache>(
        &mut self,
        key: AttestationShufflingId,
        committee_cache: &T,
    ) {
        if self
            .cache
            .get(&key)
            // Replace the committee if it's not present or if it's a promise. A bird in the hand is
            // worth two in the promise-bush!
            .map_or(true, CacheItem::is_promise)
        {
            self.cache.put(
                key,
                CacheItem::Committee(committee_cache.to_arc_committee_cache()),
            );
        }
    }

    pub fn create_promise(
        &mut self,
        key: AttestationShufflingId,
    ) -> Result<Sender<Arc<CommitteeCache>>, BeaconChainError> {
        let num_active_promises = self
            .cache
            .iter()
            .filter(|(_, item)| item.is_promise())
            .count();
        if num_active_promises >= MAX_CONCURRENT_PROMISES {
            return Err(BeaconChainError::MaxCommitteePromises(num_active_promises));
        }

        let (sender, receiver) = oneshot();
        self.cache.put(key, CacheItem::Promise(receiver));
        Ok(sender)
    }
}

/// A helper trait to allow lazy-cloning of the committee cache when inserting into the cache.
pub trait ToArcCommitteeCache {
    fn to_arc_committee_cache(&self) -> Arc<CommitteeCache>;
}

impl ToArcCommitteeCache for CommitteeCache {
    fn to_arc_committee_cache(&self) -> Arc<CommitteeCache> {
        Arc::new(self.clone())
    }
}

impl ToArcCommitteeCache for Arc<CommitteeCache> {
    fn to_arc_committee_cache(&self) -> Arc<CommitteeCache> {
        self.clone()
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

// Disable tests in debug since the beacon chain harness is slow unless in release.
#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::EphemeralHarnessType;
    use types::*;

    type BeaconChainHarness =
        crate::test_utils::BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>>;

    /// Returns two different committee caches for testing.
    fn committee_caches() -> (Arc<CommitteeCache>, Arc<CommitteeCache>) {
        let harness = BeaconChainHarness::builder(MinimalEthSpec)
            .default_spec()
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .build();
        let (mut state, _) = harness.get_current_state_and_root();
        state
            .build_committee_cache(RelativeEpoch::Current, &harness.chain.spec)
            .unwrap();
        state
            .build_committee_cache(RelativeEpoch::Next, &harness.chain.spec)
            .unwrap();
        let committee_a = state
            .committee_cache(RelativeEpoch::Current)
            .unwrap()
            .clone();
        let committee_b = state.committee_cache(RelativeEpoch::Next).unwrap().clone();
        assert!(committee_a != committee_b);
        (Arc::new(committee_a), Arc::new(committee_b))
    }

    /// Builds a deterministic but incoherent shuffling ID from a `u64`.
    fn shuffling_id(id: u64) -> AttestationShufflingId {
        AttestationShufflingId {
            shuffling_epoch: id.into(),
            shuffling_decision_block: Hash256::from_low_u64_be(id),
        }
    }

    #[test]
    fn resolved_promise() {
        let (committee_a, _) = committee_caches();
        let id_a = shuffling_id(1);
        let mut cache = ShufflingCache::new();

        // Create a promise.
        let sender = cache.create_promise(id_a.clone()).unwrap();

        // Retrieve the newly created promise.
        let item = cache.get(&id_a).unwrap();
        assert!(
            matches!(item, CacheItem::Promise(_)),
            "the item should be a promise"
        );

        // Resolve the promise.
        sender.send(committee_a.clone());

        // Ensure the promise has been resolved.
        let item = cache.get(&id_a).unwrap();
        assert!(
            matches!(item, CacheItem::Committee(committee) if committee == committee_a),
            "the promise should be resolved"
        );
        assert_eq!(cache.cache.len(), 1, "the cache should have one entry");
    }

    #[test]
    fn unresolved_promise() {
        let id_a = shuffling_id(1);
        let mut cache = ShufflingCache::new();

        // Create a promise.
        let sender = cache.create_promise(id_a.clone()).unwrap();

        // Retrieve the newly created promise.
        let item = cache.get(&id_a).unwrap();
        assert!(
            matches!(item, CacheItem::Promise(_)),
            "the item should be a promise"
        );

        // Drop the sender without resolving the promise, simulating an error computing the
        // committee.
        drop(sender);

        // Ensure the key now indicates an empty slot.
        assert!(cache.get(&id_a).is_none(), "the slot should be empty");
        assert!(cache.cache.is_empty(), "the cache should be empty");
    }

    #[test]
    fn two_promises() {
        let (committee_a, committee_b) = committee_caches();
        let (id_a, id_b) = (shuffling_id(1), shuffling_id(2));
        let mut cache = ShufflingCache::new();

        // Create promise A.
        let sender_a = cache.create_promise(id_a.clone()).unwrap();

        // Retrieve promise A.
        let item = cache.get(&id_a).unwrap();
        assert!(
            matches!(item, CacheItem::Promise(_)),
            "item a should be a promise"
        );

        // Create promise B.
        let sender_b = cache.create_promise(id_b.clone()).unwrap();

        // Retrieve promise B.
        let item = cache.get(&id_b).unwrap();
        assert!(
            matches!(item, CacheItem::Promise(_)),
            "item b should be a promise"
        );

        // Resolve promise A.
        sender_a.send(committee_a.clone());
        // Ensure promise A has been resolved.
        let item = cache.get(&id_a).unwrap();
        assert!(
            matches!(item, CacheItem::Committee(committee) if committee == committee_a),
            "promise A should be resolved"
        );

        // Resolve promise B.
        sender_b.send(committee_b.clone());
        // Ensure promise B has been resolved.
        let item = cache.get(&id_b).unwrap();
        assert!(
            matches!(item, CacheItem::Committee(committee) if committee == committee_b),
            "promise B should be resolved"
        );

        // Check both entries again.
        assert!(
            matches!(cache.get(&id_a).unwrap(), CacheItem::Committee(committee) if committee == committee_a),
            "promise A should remain resolved"
        );
        assert!(
            matches!(cache.get(&id_b).unwrap(), CacheItem::Committee(committee) if committee == committee_b),
            "promise B should remain resolved"
        );
        assert_eq!(cache.cache.len(), 2, "the cache should have two entries");
    }

    #[test]
    fn too_many_promises() {
        let mut cache = ShufflingCache::new();

        for i in 0..MAX_CONCURRENT_PROMISES {
            cache.create_promise(shuffling_id(i as u64)).unwrap();
        }

        // Ensure that the next promise returns an error. It is important for the application to
        // dump his ass when he can't keep his promises, you're a queen and you deserve better.
        assert!(matches!(
            cache.create_promise(shuffling_id(MAX_CONCURRENT_PROMISES as u64)),
            Err(BeaconChainError::MaxCommitteePromises(
                MAX_CONCURRENT_PROMISES
            ))
        ));
        assert_eq!(
            cache.cache.len(),
            MAX_CONCURRENT_PROMISES,
            "the cache should have two entries"
        );
    }
}
