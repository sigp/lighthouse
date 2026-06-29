use std::collections::HashMap;
use std::sync::Arc;

use itertools::Itertools;
use oneshot_broadcast::{Receiver, Sender, oneshot};
use parking_lot::RwLock;
use state_processing::state_advance::partial_state_advance;
use tracing::debug;
use types::{
    AttestationShufflingId, BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, Hash256, PTC,
    RelativeEpoch, Slot, state::CommitteeCache,
};

use crate::{
    BeaconChainError, BeaconChainTypes, BeaconStore, canonical_head::CanonicalHead, metrics,
};

/// The size of the cache that stores shufflings for quicker verification.
///
/// Each entry should be around `8 * 2M + 128KB ~= 16 MB` in size with 2M validators
/// and 32 512-validator PTCs. Therefore, this cache should be approx
/// `16 * 16 MB ~= 256 MB`. (Note: this ignores a few extra bytes in the
/// caches that should be insignificant compared to the indices).
pub const DEFAULT_CACHE_SIZE: usize = 16;

/// The maximum number of concurrent shuffling "promises" that can be issued. In effect, this
/// limits the number of concurrent states that can be loaded into memory for the shuffling.
/// This prevents excessive memory usage at the cost of rejecting some attestations.
///
/// We set this value to 2 since states can be quite large and have a significant impact on memory
/// usage. A healthy network cannot have more than a few committee caches and those caches should
/// always be inserted during block import. Unstable networks with a high degree of forking might
/// see some attestations dropped due to this concurrency limit, however I propose that this is
/// better than low-resource nodes going OOM.
const MAX_CONCURRENT_PROMISES: usize = 2;

#[derive(Clone)]
pub struct CachedShuffling<E: EthSpec> {
    pub committee_cache: Arc<CommitteeCache>,
    pub ptcs: CachedPTCs<E>,
}

#[derive(Clone)]
pub enum CachedPTCs<E: EthSpec> {
    PreGloas,
    PostGloas(Vec<PTC<E>>, Epoch),
}

impl<E: EthSpec> CachedPTCs<E> {
    /// Returns `None` at the Gloas fork boundary (pre-Gloas state, Gloas shuffling epoch); the
    /// on-demand miss path in `with_cached_shuffling` handles those.
    pub fn try_from_state(
        state: &BeaconState<E>,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Option<Self>, BeaconChainError> {
        if shuffling_requires_ptcs(epoch, spec) {
            if !state.fork_name_unchecked().gloas_enabled() {
                return Ok(None);
            }
            let ptcs = epoch
                .slot_iter(E::slots_per_epoch())
                .map(|slot| state.get_ptc(slot, spec))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(Self::PostGloas(ptcs, epoch)))
        } else {
            Ok(Some(Self::PreGloas))
        }
    }
}

impl<E: EthSpec> CachedShuffling<E> {
    pub fn new(committee_cache: Arc<CommitteeCache>, ptcs: CachedPTCs<E>) -> Self {
        Self {
            committee_cache,
            ptcs,
        }
    }

    pub fn ptc_for_slot(&self, slot: Slot) -> Result<PTC<E>, BeaconChainError> {
        match &self.ptcs {
            CachedPTCs::PreGloas => Err(BeaconChainError::AttesterCacheNoPtcPreGloas { slot }),
            &CachedPTCs::PostGloas(ref ptcs, epoch) => {
                if slot.epoch(E::slots_per_epoch()) != epoch {
                    Err(BeaconChainError::AttesterCachePtcOutOfBounds { slot, epoch })
                } else {
                    ptcs.get(slot.as_usize() % E::slots_per_epoch() as usize)
                        .cloned()
                        .ok_or(BeaconChainError::AttesterCachePtcOutOfBounds { slot, epoch })
                }
            }
        }
    }
}

fn shuffling_requires_ptcs(shuffling_epoch: Epoch, spec: &ChainSpec) -> bool {
    spec.fork_name_at_epoch(shuffling_epoch).gloas_enabled()
}

#[derive(Clone)]
pub enum CacheItem<E: EthSpec> {
    /// A cached shuffling.
    Committee(CachedShuffling<E>),
    /// A promise for a future cached shuffling.
    Promise(Receiver<CachedShuffling<E>>),
}

impl<E: EthSpec> CacheItem<E> {
    pub fn is_promise(&self) -> bool {
        matches!(self, CacheItem::Promise(_))
    }

    pub fn wait(self) -> Result<CachedShuffling<E>, BeaconChainError> {
        match self {
            CacheItem::Committee(cache) => Ok(cache),
            CacheItem::Promise(receiver) => receiver
                .recv()
                .map_err(BeaconChainError::CommitteePromiseFailed),
        }
    }
}

/// Provides a cache for `CommitteeCache` and the associated optional PTCs.
///
/// It has been named `ShufflingCache` because `CommitteeCacheCache` is a bit weird and looks like
/// a find/replace error.
pub struct ShufflingCache<E: EthSpec> {
    cache: HashMap<AttestationShufflingId, CacheItem<E>>,
    cache_size: usize,
    head_shuffling_ids: BlockShufflingIds,
}

impl<E: EthSpec> ShufflingCache<E> {
    pub fn new(cache_size: usize, head_shuffling_ids: BlockShufflingIds) -> Self {
        Self {
            cache: HashMap::new(),
            cache_size,
            head_shuffling_ids,
        }
    }

    pub fn get(&mut self, key: &AttestationShufflingId) -> Option<CacheItem<E>> {
        match self.cache.get(key) {
            // The cache contained the shuffling, return it.
            item @ Some(CacheItem::Committee(_)) => {
                metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
                item.cloned()
            }
            // The cache contains a promise for the shuffling. Check to see if the promise has
            // already been resolved, without waiting for it.
            item @ Some(CacheItem::Promise(receiver)) => match receiver.try_recv() {
                // The promise has already been resolved. Replace the entry in the cache with a
                // `Committee` entry and then return the cached shuffling.
                Ok(Some(cached_shuffling)) => {
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_PROMISE_HITS);
                    metrics::inc_counter(&metrics::SHUFFLING_CACHE_HITS);
                    let ready = CacheItem::Committee(cached_shuffling);
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
                // The sender has been dropped without sending a shuffling. There was most likely an
                // error computing the shuffling. Drop the key from the cache and return
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
            // The cache does not have this shuffling and it's not already promised to be computed.
            None => {
                metrics::inc_counter(&metrics::SHUFFLING_CACHE_MISSES);
                None
            }
        }
    }

    pub fn contains(&self, key: &AttestationShufflingId) -> bool {
        self.cache.contains_key(key)
    }

    /// Check that all entries for Gloas epochs have PTCs.
    #[cfg(test)]
    pub fn check_gloas_ptcs_invariant(&self, spec: &ChainSpec) -> bool {
        self.cache.iter().all(|(key, item)| {
            if shuffling_requires_ptcs(key.shuffling_epoch, spec) {
                match item {
                    CacheItem::Committee(cached_shuffling) => {
                        matches!(cached_shuffling.ptcs, CachedPTCs::PostGloas(..))
                    }
                    CacheItem::Promise(_) => true,
                }
            } else {
                true
            }
        })
    }

    pub fn insert_committee_cache(
        &mut self,
        key: AttestationShufflingId,
        cached_shuffling: CachedShuffling<E>,
    ) {
        match self.cache.get(&key) {
            Some(CacheItem::Committee(_)) => {
                // Calculation is deterministic, so no need to replace the existing entry.
            }
            // A bird in the hand is worth two in the promise-bush!
            Some(CacheItem::Promise(_)) | None => {
                self.insert_cache_item(key, CacheItem::Committee(cached_shuffling));
            }
        }
    }

    /// Prunes the cache first before inserting a new cache item.
    fn insert_cache_item(&mut self, key: AttestationShufflingId, cache_item: CacheItem<E>) {
        self.prune_cache();
        self.cache.insert(key, cache_item);
    }

    /// Prunes the `cache` to keep the size below the `cache_size` limit, based on the following
    /// preferences:
    /// - Entries from more recent epochs are preferred over older ones.
    /// - Entries with shuffling ids matching the head's previous, current, and future epochs must
    ///   not be pruned.
    fn prune_cache(&mut self) {
        let target_cache_size = self.cache_size.saturating_sub(1);
        if let Some(prune_count) = self.cache.len().checked_sub(target_cache_size) {
            let shuffling_ids_to_prune = self
                .cache
                .keys()
                .sorted_by_key(|key| key.shuffling_epoch)
                .filter(|shuffling_id| {
                    Some(shuffling_id)
                        != self
                            .head_shuffling_ids
                            .id_for_epoch(shuffling_id.shuffling_epoch)
                            .as_ref()
                            .as_ref()
                })
                .take(prune_count)
                .cloned()
                .collect::<Vec<_>>();

            for shuffling_id in shuffling_ids_to_prune.iter() {
                debug!(
                    shuffling_epoch = %shuffling_id.shuffling_epoch,
                    shuffling_decision_block = ?shuffling_id.shuffling_decision_block,
                    "Removing old shuffling from cache"
                );
                self.cache.remove(shuffling_id);
            }
        }
    }

    pub fn create_promise(
        &mut self,
        key: AttestationShufflingId,
    ) -> Result<Sender<CachedShuffling<E>>, BeaconChainError> {
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

    /// Inform the cache that the shuffling decision roots for the head has changed.
    ///
    /// The shufflings for the head's previous, current, and future epochs will never be ejected from
    /// the cache during `Self::insert_cache_item`.
    pub fn update_head_shuffling_ids(&mut self, head_shuffling_ids: BlockShufflingIds) {
        self.head_shuffling_ids = head_shuffling_ids;
    }
}

pub fn with_cached_shuffling<T, F, R, Error>(
    canonical_head: &CanonicalHead<T>,
    shuffling_cache_lock: &RwLock<ShufflingCache<T::EthSpec>>,
    store: &BeaconStore<T>,
    spec: &ChainSpec,
    head_block_root: Hash256,
    shuffling_epoch: Epoch,
    map_fn: F,
) -> Result<R, Error>
where
    T: BeaconChainTypes,
    F: Fn(&CachedShuffling<T::EthSpec>, Hash256) -> Result<R, Error>,
    Error: From<BeaconChainError>,
{
    let head_block = canonical_head
        .fork_choice_read_lock()
        .get_block(&head_block_root)
        .ok_or(BeaconChainError::MissingBeaconBlock(head_block_root))?;

    let shuffling_id = BlockShufflingIds {
        current: head_block.current_epoch_shuffling_id.clone(),
        next: head_block.next_epoch_shuffling_id.clone(),
        previous: None,
        block_root: head_block.root,
    }
    .id_for_epoch(shuffling_epoch)
    .ok_or_else(|| BeaconChainError::InvalidShufflingId {
        shuffling_epoch,
        head_block_epoch: head_block.slot.epoch(T::EthSpec::slots_per_epoch()),
    })?;

    let mut shuffling_cache = {
        let _ = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SHUFFLING_CACHE_WAIT_TIMES);
        shuffling_cache_lock.write()
    };

    if let Some(cache_item) = shuffling_cache.get(&shuffling_id) {
        drop(shuffling_cache);

        let cached_shuffling = cache_item.wait()?;
        map_fn(&cached_shuffling, shuffling_id.shuffling_decision_block)
    } else {
        // Create an entry in the cache that "promises" this value will eventually be computed.
        // This avoids the case where multiple threads attempt to produce the same value at the
        // same time.
        //
        // Creating the promise whilst we hold the `shuffling_cache` lock will prevent the same
        // promise from being created twice.
        let sender = shuffling_cache.create_promise(shuffling_id.clone())?;

        // Drop the shuffling cache to avoid holding the lock for any longer than required.
        drop(shuffling_cache);

        debug!(
            shuffling_id = ?shuffling_epoch,
            head_block_root = head_block_root.to_string(),
            "Committee cache miss"
        );

        // If the block's state will be so far ahead of `shuffling_epoch` that even its previous
        // epoch committee cache will be too new, then error. Callers of this function shouldn't be
        // requesting such old shufflings for this `head_block_root`.
        let head_block_epoch = head_block.slot.epoch(T::EthSpec::slots_per_epoch());
        if head_block_epoch > shuffling_epoch + 1 {
            return Err(BeaconChainError::InvalidStateForShuffling {
                state_epoch: head_block_epoch,
                shuffling_epoch,
            }
            .into());
        }

        let state_read_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_READ_TIMES);

        let cached_head = canonical_head.cached_head();
        let head_state_opt = if cached_head.head_block_root() == head_block_root {
            Some((
                cached_head.snapshot.beacon_state.clone(),
                cached_head.head_state_root(),
            ))
        } else {
            None
        };

        // Compute the `target_slot` to advance the block's state to.
        //
        // Since there's a one-epoch look-ahead on the attester shuffling, it suffices to only
        // advance into the first slot of the epoch prior to `shuffling_epoch`.
        //
        // If the `head_block` is already ahead of that slot, then we should load the state at that
        // slot, as we've determined above that the `shuffling_epoch` cache will not be too far in
        // the past.
        let mut target_slot = std::cmp::max(
            shuffling_epoch
                .saturating_sub(1_u64)
                .start_slot(T::EthSpec::slots_per_epoch()),
            head_block.slot,
        );
        if spec.gloas_fork_epoch == Some(shuffling_epoch) {
            target_slot = std::cmp::max(
                target_slot,
                shuffling_epoch.start_slot(T::EthSpec::slots_per_epoch()),
            );
        }

        // If the head state is useful for this request, use it. Otherwise, read a state from disk
        // that is advanced as close as possible to `target_slot`.
        let (mut state, state_root) = if let Some((state, state_root)) = head_state_opt {
            (state, state_root)
        } else {
            let (state_root, state) = store
                .get_advanced_hot_state(head_block_root, target_slot, head_block.state_root)
                .map_err(BeaconChainError::DBError)?
                .ok_or(BeaconChainError::MissingBeaconState(head_block.state_root))?;
            (state, state_root)
        };

        metrics::stop_timer(state_read_timer);
        let state_skip_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_SKIP_TIMES);

        // If the state is still in an earlier epoch, advance it to the `target_slot` so that its
        // next epoch committee cache matches the `shuffling_epoch`.
        let advance_to_gloas_fork = spec.gloas_fork_epoch == Some(shuffling_epoch)
            && state.current_epoch() < shuffling_epoch;
        if state.current_epoch() + 1 < shuffling_epoch || advance_to_gloas_fork {
            // Advance the state into the required slot, using the "partial" method since the state
            // roots are not relevant for the shuffling.
            partial_state_advance(&mut state, Some(state_root), target_slot, spec)
                .map_err(BeaconChainError::from)?;
        }
        metrics::stop_timer(state_skip_timer);

        let committee_building_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_COMMITTEE_BUILDING_TIMES);

        let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), shuffling_epoch)
            .map_err(BeaconChainError::IncorrectStateForAttestation)?;

        state
            .build_committee_cache(relative_epoch, spec)
            .map_err(BeaconChainError::from)?;

        let committee_cache = state
            .committee_cache(relative_epoch)
            .map_err(BeaconChainError::from)?
            .clone();
        // The state has been advanced through the upgrade if needed, so `try_from_state`
        // cannot return None here.
        let ptcs = CachedPTCs::try_from_state(&state, shuffling_epoch, spec)?.ok_or(
            BeaconChainError::BeaconStateError(BeaconStateError::IncorrectStateVariant),
        )?;
        let shuffling_decision_block = shuffling_id.shuffling_decision_block;
        let cached_shuffling = CachedShuffling::new(committee_cache, ptcs);

        shuffling_cache_lock
            .write()
            .insert_committee_cache(shuffling_id, cached_shuffling.clone());

        metrics::stop_timer(committee_building_timer);

        sender.send(cached_shuffling.clone());

        map_fn(&cached_shuffling, shuffling_decision_block)
    }
}

/// Contains the shuffling IDs for a beacon block.
#[derive(Clone)]
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
            .is_some_and(|id| id.shuffling_epoch == epoch)
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

    pub fn try_from_head<E: EthSpec>(
        head_block_root: Hash256,
        head_state: &BeaconState<E>,
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
    use fixed_bytes::FixedBytesExtended;
    use types::*;

    use crate::test_utils::EphemeralHarnessType;
    use logging::create_test_tracing_subscriber;

    use super::*;

    type E = MinimalEthSpec;
    type TestBeaconChainType = EphemeralHarnessType<E>;
    type BeaconChainHarness = crate::test_utils::BeaconChainHarness<TestBeaconChainType>;
    const TEST_CACHE_SIZE: usize = 5;

    // Creates a new shuffling cache for testing
    fn new_shuffling_cache() -> ShufflingCache<E> {
        create_test_tracing_subscriber();

        let current_epoch = 8;
        let head_shuffling_ids = BlockShufflingIds {
            current: shuffling_id(current_epoch),
            next: shuffling_id(current_epoch + 1),
            previous: Some(shuffling_id(current_epoch - 1)),
            block_root: Hash256::from_low_u64_le(0),
        };

        ShufflingCache::new(TEST_CACHE_SIZE, head_shuffling_ids)
    }

    fn cached_shuffling(committee_cache: Arc<CommitteeCache>) -> CachedShuffling<E> {
        CachedShuffling::new(committee_cache, CachedPTCs::PreGloas)
    }

    /// Returns two different committee caches for testing.
    fn committee_caches() -> (Arc<CommitteeCache>, Arc<CommitteeCache>) {
        let harness = BeaconChainHarness::builder(MinimalEthSpec)
            .default_spec()
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .build();
        let mut state = harness.get_current_state();
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
        sender.send(cached_shuffling(committee_a.clone()));

        // Ensure the promise has been resolved.
        let item = cache.get(&id_a).unwrap();
        assert!(
            matches!(item, CacheItem::Committee(cached_shuffling) if cached_shuffling.committee_cache == committee_a),
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
        sender_a.send(cached_shuffling(committee_a.clone()));
        // Ensure promise A has been resolved.
        let item = cache.get(&id_a).unwrap();
        assert!(
            matches!(item, CacheItem::Committee(cached_shuffling) if cached_shuffling.committee_cache == committee_a),
            "promise A should be resolved"
        );

        // Resolve promise B.
        sender_b.send(cached_shuffling(committee_b.clone()));
        // Ensure promise B has been resolved.
        let item = cache.get(&id_b).unwrap();
        assert!(
            matches!(item, CacheItem::Committee(cached_shuffling) if cached_shuffling.committee_cache == committee_b),
            "promise B should be resolved"
        );

        // Check both entries again.
        assert!(
            matches!(cache.get(&id_a).unwrap(), CacheItem::Committee(cached_shuffling) if cached_shuffling.committee_cache == committee_a),
            "promise A should remain resolved"
        );
        assert!(
            matches!(cache.get(&id_b).unwrap(), CacheItem::Committee(cached_shuffling) if cached_shuffling.committee_cache == committee_b),
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
        let committee_cache_a = Arc::new(CommitteeCache::default());
        cache.insert_committee_cache(id_a.clone(), cached_shuffling(committee_cache_a.clone()));
        assert!(
            matches!(cache.get(&id_a).unwrap(), CacheItem::Committee(cached_shuffling) if cached_shuffling.committee_cache == committee_cache_a),
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
            cache.insert_committee_cache(
                shuffling_id.clone(),
                cached_shuffling(committee_cache.clone()),
            );
        }

        for i in 1..(TEST_CACHE_SIZE + 1) {
            assert!(
                cache.contains(&shuffling_id_and_committee_caches.get(i).unwrap().0),
                "should contain recent epoch shuffling ids"
            );
        }

        assert!(
            !cache.contains(&shuffling_id_and_committee_caches.first().unwrap().0),
            "should not contain oldest epoch shuffling id"
        );
        assert_eq!(
            cache.cache.len(),
            cache.cache_size,
            "should limit cache size"
        );
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
            cache.insert_committee_cache(shuffling_id, cached_shuffling(committee_cache.clone()));
        }

        // Now, update the head shuffling ids
        let head_shuffling_ids = BlockShufflingIds {
            current: shuffling_id(current_epoch),
            next: shuffling_id(current_epoch + 1),
            previous: Some(shuffling_id(current_epoch - 1)),
            block_root: Hash256::from_low_u64_le(42),
        };
        cache.update_head_shuffling_ids(head_shuffling_ids.clone());

        // Insert head state shuffling ids. Should not be overridden by other shuffling ids.
        cache.insert_committee_cache(
            head_shuffling_ids.current.clone(),
            cached_shuffling(committee_cache.clone()),
        );
        cache.insert_committee_cache(
            head_shuffling_ids.next.clone(),
            cached_shuffling(committee_cache.clone()),
        );
        cache.insert_committee_cache(
            head_shuffling_ids.previous.clone().unwrap(),
            cached_shuffling(committee_cache.clone()),
        );

        // Insert a few entries for older epochs.
        for i in 0..TEST_CACHE_SIZE {
            let shuffling_id = AttestationShufflingId {
                shuffling_epoch: Epoch::from(i),
                shuffling_decision_block: Hash256::from_low_u64_be(i as u64),
            };
            cache.insert_committee_cache(shuffling_id, cached_shuffling(committee_cache.clone()));
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
        assert_eq!(
            cache.cache.len(),
            cache.cache_size,
            "should limit cache size"
        );
    }

    /// Pre-Gloas state across the Gloas fork: epoch G-1 returns `Some(PreGloas)`, epoch G and
    /// G+1 return `None` (the boundary skip).
    #[test]
    fn try_from_state_skips_at_gloas_boundary() {
        create_test_tracing_subscriber();

        let mut spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let gloas_fork_epoch = Epoch::new(2);
        spec.gloas_fork_epoch = Some(gloas_fork_epoch);

        let harness = BeaconChainHarness::builder(MinimalEthSpec)
            .spec(Arc::new(spec.clone()))
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .build();
        let state = harness.get_current_state();
        assert!(!state.fork_name_unchecked().gloas_enabled());

        for (epoch, expect_pre_gloas) in [
            (gloas_fork_epoch - 1, true),
            (gloas_fork_epoch, false),
            (gloas_fork_epoch + 1, false),
        ] {
            let result = CachedPTCs::<E>::try_from_state(&state, epoch, &spec)
                .expect("must not error at the boundary");
            if expect_pre_gloas {
                assert!(
                    matches!(result, Some(CachedPTCs::PreGloas)),
                    "epoch {}: expected Some(PreGloas)",
                    epoch
                );
            } else {
                assert!(result.is_none(), "epoch {}: expected None", epoch);
            }
        }
    }
}
