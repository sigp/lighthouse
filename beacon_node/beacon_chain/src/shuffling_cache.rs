use std::collections::HashMap;
use std::sync::Arc;

use itertools::Itertools;
use slog::{debug, Logger};

use oneshot_broadcast::{oneshot, Receiver, Sender};
use slot_clock::SlotClock;
use types::{beacon_state::CommitteeCache, AttestationShufflingId, Epoch, EthSpec, Hash256};

use crate::{metrics, BeaconChainError, BeaconChainTypes};

/// The size of the cache that stores committee caches for quicker verification.
///
/// Each entry should be `8 + 800,000 = 800,008` bytes in size with 100k validators. (8-byte hash +
/// 100k indices). Therefore, this cache should be approx `16 * 800,008 = 12.8 MB`. (Note: this
/// ignores a few extra bytes in the caches that should be insignificant compared to the indices).
pub const DEFAULT_CACHE_SIZE: usize = 16;

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

/// Provides a cache for `CommitteeCache`.
///
/// It has been named `ShufflingCache` because `CommitteeCacheCache` is a bit weird and looks like
/// a find/replace error.
pub struct ShufflingCache<T: BeaconChainTypes> {
    cache: HashMap<AttestationShufflingId, CacheItem>,
    cache_size: usize,
    head_shuffling_decision_root: Hash256,
    slot_clock: T::SlotClock,
    logger: Logger,
}

impl<T: BeaconChainTypes> ShufflingCache<T> {
    pub fn new(
        cache_size: usize,
        head_shuffling_decision_root: Hash256,
        slot_clock: T::SlotClock,
        logger: Logger,
    ) -> Self {
        Self {
            cache: HashMap::new(),
            cache_size,
            head_shuffling_decision_root,
            slot_clock,
            logger,
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
                    self.insert_cache_item(key.clone(), ready.clone());
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
                // memory. We expect that *all* promises should be resolved, unless there is a
                // programming or database error.
                Err(oneshot_broadcast::Error::SenderDropped) => {
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_PROMISE_FAILS);
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_MISSES);
                    self.cache.remove(key);
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
        self.cache.contains_key(key)
    }

    pub fn insert_committee_cache<C: ToArcCommitteeCache>(
        &mut self,
        key: AttestationShufflingId,
        committee_cache: &C,
    ) {
        if self
            .cache
            .get(&key)
            // Replace the committee if it's not present or if it's a promise. A bird in the hand is
            // worth two in the promise-bush!
            .map_or(true, CacheItem::is_promise)
        {
            self.insert_cache_item(
                key,
                CacheItem::Committee(committee_cache.to_arc_committee_cache()),
            );
        }
    }

    /// Prunes the cache first before inserting a new cache item.
    fn insert_cache_item(&mut self, key: AttestationShufflingId, cache_item: CacheItem) {
        self.prune_cache();
        self.cache.insert(key, cache_item);
    }

    /// Prunes the `cache` to keep the size below the `cache_size` limit, based on the following preferences:
    /// - Entries from more recent epochs are preferred over older ones.
    /// - Entries in the canonical chain are preferred,when two entries have the same epoch.
    /// - "Enshrined" shuffling (i.e. shuffling key the head block at the current wall-clock epoch)
    ///   must not be pruned.
    fn prune_cache(&mut self) {
        if self.cache.len() >= self.cache_size {
            let prune_count = self.cache.len() - self.cache_size + 1;
            let shuffling_ids_to_prune = self
                .cache
                .keys()
                .cloned()
                .sorted_by_key(|key| key.shuffling_epoch)
                .filter(|key| {
                    if let Some(current_epoch) = self.get_current_epoch() {
                        key.shuffling_epoch != current_epoch
                            || key.shuffling_decision_block != self.head_shuffling_decision_root
                    } else {
                        true
                    }
                })
                .take(prune_count)
                .collect::<Vec<_>>();

            for shuffling_id in shuffling_ids_to_prune.iter() {
                self.cache.remove(shuffling_id);
            }

            debug!(
                self.logger,
                "Removed old shuffling from cache";
                "count" => shuffling_ids_to_prune.len()
            );
        }
    }

    fn get_current_epoch(&self) -> Option<Epoch> {
        self.slot_clock
            .now()
            .map(|s| s.epoch(T::EthSpec::slots_per_epoch()))
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
        self.insert_cache_item(key, CacheItem::Promise(receiver));
        Ok(sender)
    }

    /// Inform the cache that the shuffling decision root for the head has changed.
    ///
    /// The shuffling that matches this `head_shuffling_decision_root` and the current epoch will
    /// never be ejected from the cache during `Self::insert_cache_item`.
    pub fn update_head_shuffling_decision_root(&mut self, head_shuffling_decision_root: Hash256) {
        self.head_shuffling_decision_root = head_shuffling_decision_root;
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
    use std::time::Duration;

    use slot_clock::{SlotClock, TestingSlotClock};
    use task_executor::test_utils::null_logger;
    use types::*;

    use crate::test_utils::EphemeralHarnessType;

    use super::*;

    type E = MinimalEthSpec;
    type TestBeaconChainType = EphemeralHarnessType<E>;
    type BeaconChainHarness = crate::test_utils::BeaconChainHarness<TestBeaconChainType>;
    const TEST_CACHE_SIZE: usize = 3;

    // Creates a new shuffling cache for testing
    fn new_shuffling_cache() -> ShufflingCache<TestBeaconChainType> {
        let slot_duration = Duration::from_secs(12);
        let slot_clock = TestingSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);
        let shuffling_block_root = Hash256::from_low_u64_be(0);
        let logger = null_logger().unwrap();
        ShufflingCache::new(TEST_CACHE_SIZE, shuffling_block_root, slot_clock, logger)
    }

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
        let mut cache = new_shuffling_cache();

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
        let mut cache = new_shuffling_cache();

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
        let mut cache = new_shuffling_cache();

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
        let mut cache = new_shuffling_cache();

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

    #[test]
    fn should_insert_committee_cache() {
        let mut cache = new_shuffling_cache();
        let id_a = shuffling_id(1);
        let (committee_cache_a, _) = committee_caches();
        cache.insert_committee_cache(id_a.clone(), &committee_cache_a);
        assert!(cache.contains(&id_a), "should insert committee cache");
    }

    #[test]
    fn should_prune_committee_cache_with_lowest_epoch() {
        let mut cache = new_shuffling_cache();
        let shuffling_id_and_committee_caches = (0..(TEST_CACHE_SIZE + 1))
            .map(|i| (shuffling_id(i as u64), Arc::new(CommitteeCache::default())))
            .collect::<Vec<_>>();

        // Advance slot clock to epoch `TEST_CACHE_SIZE`.
        cache
            .slot_clock
            .set_slot(E::slots_per_epoch() * TEST_CACHE_SIZE as u64);

        for (shuffling_id, committee_cache) in shuffling_id_and_committee_caches.iter() {
            cache.insert_committee_cache(shuffling_id.clone(), committee_cache);
        }

        for i in 1..(TEST_CACHE_SIZE + 1) {
            assert!(
                cache.contains(&shuffling_id_and_committee_caches.get(i).unwrap().0),
                "should contain recent epoch shuffling ids"
            );
        }

        assert!(
            !cache.contains(&shuffling_id_and_committee_caches.get(0).unwrap().0),
            "should not contain oldest epoch shuffling id"
        );
    }

    #[test]
    fn should_not_override_enshrined_head_state_shuffling() {
        let mut cache = new_shuffling_cache();

        // Advance slot clock to epoch `TEST_CACHE_SIZE`.
        let current_epoch = Epoch::from(TEST_CACHE_SIZE);
        cache
            .slot_clock
            .set_slot(current_epoch.start_slot(E::slots_per_epoch()).as_u64());

        // Set head shuffling decision root and insert this shuffling to cache.
        let head_shuffling_decision_root = Hash256::random();
        cache.head_shuffling_decision_root = head_shuffling_decision_root;

        // Insert "enshrined" head state shuffling. Should not be overridden by other shufflings.
        let committee_cache = Arc::new(CommitteeCache::default());
        let enshrined_shuffling_id = AttestationShufflingId {
            shuffling_epoch: current_epoch,
            shuffling_decision_block: head_shuffling_decision_root,
        };
        cache.insert_committee_cache(enshrined_shuffling_id.clone(), &committee_cache);

        // Insert an entry for the same epoch, but different decision root.
        cache.insert_committee_cache(
            AttestationShufflingId {
                shuffling_epoch: current_epoch,
                shuffling_decision_block: Hash256::from_low_u64_be(TEST_CACHE_SIZE as u64),
            },
            &committee_cache,
        );

        // Insert an entry for a newer epoch, and same decision root.
        cache.insert_committee_cache(
            AttestationShufflingId {
                shuffling_epoch: current_epoch + 1,
                shuffling_decision_block: head_shuffling_decision_root,
            },
            &committee_cache,
        );

        // Insert a few entries of newer epochs and different decision roots.
        for i in 0..TEST_CACHE_SIZE {
            let shuffling_id = AttestationShufflingId {
                shuffling_epoch: current_epoch + 1,
                shuffling_decision_block: Hash256::from_low_u64_be(i as u64),
            };
            cache.insert_committee_cache(shuffling_id, &committee_cache);
        }

        assert!(
            cache.contains(&enshrined_shuffling_id),
            "should not remove enshrined shuffling id."
        );
    }

    #[test]
    #[ignore = "not implemented yet"]
    fn should_prune_committee_cache_prefer_canonical_chain_entries() {}
}
