use promise_cache::{PromiseCache, Protect};
use slog::{debug, Logger};
use types::{
    beacon_state::CommitteeCache, AttestationShufflingId, BeaconState, Epoch, EthSpec, Hash256,
    RelativeEpoch,
};

/// The size of the cache that stores committee caches for quicker verification.
///
/// Each entry should be `8 + 800,000 = 800,008` bytes in size with 100k validators. (8-byte hash +
/// 100k indices). Therefore, this cache should be approx `16 * 800,008 = 12.8 MB`. (Note: this
/// ignores a few extra bytes in the caches that should be insignificant compared to the indices).
///
/// The cache size also determines the maximum number of concurrent committee cache "promises" that
/// can be issued. In effect, this limits the number of concurrent states that can be loaded into
/// memory for the committee cache. This prevents excessive memory usage at the cost of rejecting
/// some attestations.
///
/// We set this value to 2 since states can be quite large and have a significant impact on memory
/// usage. A healthy network cannot have more than a few committee caches and those caches should
/// always be inserted during block import. Unstable networks with a high degree of forking might
/// see some attestations dropped due to this concurrency limit, however I propose that this is
/// better than low-resource nodes going OOM.
pub const DEFAULT_CACHE_SIZE: usize = 16;

impl Protect<AttestationShufflingId> for BlockShufflingIds {
    type SortKey = Epoch;

    fn sort_key(&self, k: &AttestationShufflingId) -> Epoch {
        k.shuffling_epoch
    }

    fn protect_from_eviction(&self, shuffling_id: &AttestationShufflingId) -> bool {
        Some(shuffling_id) == self.id_for_epoch(shuffling_id.shuffling_epoch).as_ref()
    }

    fn notify_eviction(&self, shuffling_id: &AttestationShufflingId, logger: &Logger) {
        debug!(
            logger,
            "Removing old shuffling from cache";
            "shuffling_epoch" => shuffling_id.shuffling_epoch,
            "shuffling_decision_block" => ?shuffling_id.shuffling_decision_block
        );
    }
}

pub type ShufflingCache = PromiseCache<AttestationShufflingId, CommitteeCache, BlockShufflingIds>;

/// Contains the shuffling IDs for a beacon block.
#[derive(Debug, Clone)]
pub struct BlockShufflingIds {
    pub current: AttestationShufflingId,
    pub next: AttestationShufflingId,
    pub previous: Option<AttestationShufflingId>,
    pub block_root: Hash256,
}

impl BlockShufflingIds {
    /// Returns the shuffling ID for the given epoch.
    ///
    /// Returns `None` if `epoch` is prior to `self.previous?.shuffling_epoch` or
    /// `self.current.shuffling_epoch` (if `previous` is `None`).
    pub fn id_for_epoch(&self, epoch: Epoch) -> Option<AttestationShufflingId> {
        if epoch == self.current.shuffling_epoch {
            Some(self.current.clone())
        } else if self
            .previous
            .as_ref()
            .map_or(false, |id| id.shuffling_epoch == epoch)
        {
            self.previous.clone()
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

    pub fn try_from_head<T: EthSpec>(
        head_block_root: Hash256,
        head_state: &BeaconState<T>,
    ) -> Result<Self, String> {
        let get_shuffling_id = |relative_epoch| {
            AttestationShufflingId::new(head_block_root, head_state, relative_epoch).map_err(|e| {
                format!(
                    "Unable to get attester shuffling decision slot for the epoch {:?}: {:?}",
                    relative_epoch, e
                )
            })
        };

        Ok(Self {
            current: get_shuffling_id(RelativeEpoch::Current)?,
            next: get_shuffling_id(RelativeEpoch::Next)?,
            previous: Some(get_shuffling_id(RelativeEpoch::Previous)?),
            block_root: head_block_root,
        })
    }
}

// Disable tests in debug since the beacon chain harness is slow unless in release.
#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::EphemeralHarnessType;
    use promise_cache::{CacheItem, PromiseCacheError};
    use std::sync::Arc;
    use task_executor::test_utils::null_logger;
    use types::*;

    type E = MinimalEthSpec;
    type TestBeaconChainType = EphemeralHarnessType<E>;
    type BeaconChainHarness = crate::test_utils::BeaconChainHarness<TestBeaconChainType>;
    const TEST_CACHE_SIZE: usize = 5;

    // Creates a new shuffling cache for testing
    fn new_shuffling_cache() -> ShufflingCache {
        let current_epoch = 8;
        let head_shuffling_ids = BlockShufflingIds {
            current: shuffling_id(current_epoch),
            next: shuffling_id(current_epoch + 1),
            previous: Some(shuffling_id(current_epoch - 1)),
            block_root: Hash256::from_low_u64_le(0),
        };
        let logger = null_logger().unwrap();
        ShufflingCache::new(TEST_CACHE_SIZE, head_shuffling_ids, logger)
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
        (committee_a, committee_b)
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
            matches!(item, CacheItem::Complete(committee) if committee == committee_a),
            "the promise should be resolved"
        );
        assert_eq!(cache.len(), 1, "the cache should have one entry");
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
        assert!(cache.is_empty(), "the cache should be empty");
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
            matches!(item, CacheItem::Complete(committee) if committee == committee_a),
            "promise A should be resolved"
        );

        // Resolve promise B.
        sender_b.send(committee_b.clone());
        // Ensure promise B has been resolved.
        let item = cache.get(&id_b).unwrap();
        assert!(
            matches!(item, CacheItem::Complete(committee) if committee == committee_b),
            "promise B should be resolved"
        );

        // Check both entries again.
        assert!(
            matches!(cache.get(&id_a).unwrap(), CacheItem::Complete(committee) if committee == committee_a),
            "promise A should remain resolved"
        );
        assert!(
            matches!(cache.get(&id_b).unwrap(), CacheItem::Complete(committee) if committee == committee_b),
            "promise B should remain resolved"
        );
        assert_eq!(cache.len(), 2, "the cache should have two entries");
    }

    #[test]
    fn too_many_promises() {
        let mut cache = new_shuffling_cache();

        for i in 0..cache.max_concurrent_promises() {
            cache.create_promise(shuffling_id(i as u64)).unwrap();
        }

        // Ensure that the next promise returns an error. It is important for the application to
        // dump his ass when he can't keep his promises, you're a queen and you deserve better.
        assert!(matches!(
            cache.create_promise(shuffling_id(cache.max_concurrent_promises() as u64)),
            Err(PromiseCacheError::MaxConcurrentPromises(n))
                if n == cache.max_concurrent_promises()
        ));
        assert_eq!(
            cache.len(),
            cache.max_concurrent_promises(),
            "the cache should have two entries"
        );
    }

    #[test]
    fn should_insert_committee_cache() {
        let mut cache = new_shuffling_cache();
        let id_a = shuffling_id(1);
        let committee_cache_a = Arc::new(CommitteeCache::default());
        cache.insert_value(id_a.clone(), &committee_cache_a);
        assert!(
            matches!(cache.get(&id_a).unwrap(), CacheItem::Complete(committee_cache) if committee_cache == committee_cache_a),
            "should insert committee cache"
        );
    }

    #[test]
    fn should_prune_committee_cache_with_lowest_epoch() {
        let mut cache = new_shuffling_cache();
        let shuffling_id_and_committee_caches = (0..(TEST_CACHE_SIZE + 1))
            .map(|i| (shuffling_id(i as u64), Arc::new(CommitteeCache::default())))
            .collect::<Vec<_>>();

        for (shuffling_id, committee_cache) in shuffling_id_and_committee_caches.iter() {
            cache.insert_value(shuffling_id.clone(), committee_cache);
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
        assert_eq!(cache.len(), TEST_CACHE_SIZE, "should limit cache size");
    }

    #[test]
    fn should_retain_head_state_shufflings() {
        let mut cache = new_shuffling_cache();
        let current_epoch = 10;
        let committee_cache = Arc::new(CommitteeCache::default());

        // Insert a few entries for next the epoch with different decision roots.
        for i in 0..TEST_CACHE_SIZE {
            let shuffling_id = AttestationShufflingId {
                shuffling_epoch: (current_epoch + 1).into(),
                shuffling_decision_block: Hash256::from_low_u64_be(current_epoch + i as u64),
            };
            cache.insert_value(shuffling_id, &committee_cache);
        }

        // Now, update the head shuffling ids
        let head_shuffling_ids = BlockShufflingIds {
            current: shuffling_id(current_epoch),
            next: shuffling_id(current_epoch + 1),
            previous: Some(shuffling_id(current_epoch - 1)),
            block_root: Hash256::from_low_u64_le(42),
        };
        cache.update_protector(head_shuffling_ids.clone());

        // Insert head state shuffling ids. Should not be overridden by other shuffling ids.
        cache.insert_value(head_shuffling_ids.current.clone(), &committee_cache);
        cache.insert_value(head_shuffling_ids.next.clone(), &committee_cache);
        cache.insert_value(
            head_shuffling_ids.previous.clone().unwrap(),
            &committee_cache,
        );

        // Insert a few entries for older epochs.
        for i in 0..TEST_CACHE_SIZE {
            let shuffling_id = AttestationShufflingId {
                shuffling_epoch: Epoch::from(i),
                shuffling_decision_block: Hash256::from_low_u64_be(i as u64),
            };
            cache.insert_value(shuffling_id, &committee_cache);
        }

        assert!(
            cache.contains(&head_shuffling_ids.current),
            "should retain head shuffling id for the current epoch."
        );
        assert!(
            cache.contains(&head_shuffling_ids.next),
            "should retain head shuffling id for the next epoch."
        );
        assert!(
            cache.contains(&head_shuffling_ids.previous.unwrap()),
            "should retain head shuffling id for previous epoch."
        );
        assert_eq!(cache.len(), TEST_CACHE_SIZE, "should limit cache size");
    }
}
