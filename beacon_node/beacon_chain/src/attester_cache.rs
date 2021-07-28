//! This module provides the `AttesterCache`, a cache designed for reducing state-reads when
//! validators produce `AttestationData`.
//!
//! This cache is required *as well as* the `ShufflingCache` since the `ShufflingCache` does not
//! provide any information about the `state.current_justified_checkpoint`. It is not trivial to add
//! the justified checkpoint to the `ShufflingCache` since that cache is keyed by shuffling decision
//! root, which is not suitable for the justified checkpoint. Whilst we can know the shuffling for
//! epoch `n` during `n - 1`, we *cannot* know the justified checkpoint. Instead, we *must* perform
//! `per_epoch_processing` to transform the state from epoch `n - 1` to epoch `n` so that rewards
//! and penalties can be computed and the `state.current_justified_checkpoint` can be updated.

use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use parking_lot::RwLock;
use state_processing::state_advance::{partial_state_advance, Error as StateAdvanceError};
use std::collections::HashMap;
use std::ops::Range;
use types::{
    beacon_state::{
        compute_committee_index_in_epoch, compute_committee_range_in_epoch, epoch_committee_count,
    },
    BeaconState, BeaconStateError, ChainSpec, Checkpoint, Epoch, EthSpec, Hash256, RelativeEpoch,
    Slot,
};

type JustifiedCheckpoint = Checkpoint;
type CommitteeLength = usize;
type CommitteeIndex = u64;
type CacheHashMap = HashMap<AttesterCacheKey, AttesterCacheValue>;

/// The maximum number of `AttesterCacheValues` to be kept in memory.
///
/// Each `AttesterCacheValues` is very small (~16 bytes) and the cache will generally be kept small
/// by pruning on finality.
///
/// The value provided here is much larger than will be used during ideal network conditions,
/// however we make it large since the values are so small.
const MAX_CACHE_LEN: usize = 1_024;

#[derive(Debug)]
pub enum Error {
    BeaconState(BeaconStateError),
    // Boxed to avoid an infinite-size recursion issue.
    BeaconChain(Box<BeaconChainError>),
    MissingBeaconState(Hash256),
    FailedToTransitionState(StateAdvanceError),
    CannotAttestToFutureState {
        state_slot: Slot,
        request_slot: Slot,
    },
    /// Indicates a cache inconsistency.
    WrongEpoch {
        request_epoch: Epoch,
        epoch: Epoch,
    },
    InvalidCommitteeIndex {
        committee_index: u64,
    },
    /// Indicates an inconsistency with the beacon state committees.
    InverseRange {
        range: Range<usize>,
    },
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconState(e)
    }
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChain(Box::new(e))
    }
}

/// Stores the minimal amount of data required to compute the committee length for any committee at any
/// slot in a given `epoch`.
struct CommitteeLengths {
    /// The `epoch` to which the lengths pertain.
    epoch: Epoch,
    /// The length of the shuffling in `self.epoch`.
    active_validator_indices_len: usize,
}

impl CommitteeLengths {
    /// Instantiate `Self` using `state.current_epoch()`.
    fn new<T: EthSpec>(state: &BeaconState<T>, spec: &ChainSpec) -> Result<Self, Error> {
        let active_validator_indices_len = if let Ok(committee_cache) =
            state.committee_cache(RelativeEpoch::Current)
        {
            committee_cache.active_validator_indices().len()
        } else {
            // Building the cache like this avoids taking a mutable reference to `BeaconState`.
            let committee_cache = state.initialize_committee_cache(state.current_epoch(), spec)?;
            committee_cache.active_validator_indices().len()
        };

        Ok(Self {
            epoch: state.current_epoch(),
            active_validator_indices_len,
        })
    }

    /// Get the length of the committee at the given `slot` and `committee_index`.
    fn get<T: EthSpec>(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
        spec: &ChainSpec,
    ) -> Result<CommitteeLength, Error> {
        let slots_per_epoch = T::slots_per_epoch();
        let request_epoch = slot.epoch(slots_per_epoch);

        // Sanity check.
        if request_epoch != self.epoch {
            return Err(Error::WrongEpoch {
                request_epoch,
                epoch: self.epoch,
            });
        }

        let slots_per_epoch = slots_per_epoch as usize;
        let committees_per_slot =
            T::get_committee_count_per_slot(self.active_validator_indices_len, spec)?;
        let index_in_epoch = compute_committee_index_in_epoch(
            slot,
            slots_per_epoch,
            committees_per_slot,
            committee_index as usize,
        );
        let range = compute_committee_range_in_epoch(
            epoch_committee_count(committees_per_slot, slots_per_epoch),
            index_in_epoch,
            self.active_validator_indices_len,
        )
        .ok_or(Error::InvalidCommitteeIndex { committee_index })?;

        range
            .end
            .checked_sub(range.start)
            .ok_or(Error::InverseRange { range })
    }
}

/// Provides the following information for some epoch:
///
/// - The `state.current_justified_checkpoint` value.
/// - The committee lengths for all indices and slots.
///
/// These values are used during attestation production.
pub struct AttesterCacheValue {
    current_justified_checkpoint: Checkpoint,
    committee_lengths: CommitteeLengths,
}

impl AttesterCacheValue {
    /// Instantiate `Self` using `state.current_epoch()`.
    pub fn new<T: EthSpec>(state: &BeaconState<T>, spec: &ChainSpec) -> Result<Self, Error> {
        let current_justified_checkpoint = state.current_justified_checkpoint();
        let committee_lengths = CommitteeLengths::new(state, spec)?;
        Ok(Self {
            current_justified_checkpoint,
            committee_lengths,
        })
    }

    /// Get the justified checkpoint and committee length for some `slot` and `committee_index`.
    fn get<T: EthSpec>(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
        spec: &ChainSpec,
    ) -> Result<(JustifiedCheckpoint, CommitteeLength), Error> {
        self.committee_lengths
            .get::<T>(slot, committee_index, spec)
            .map(|committee_length| (self.current_justified_checkpoint, committee_length))
    }
}

/// The `AttesterCacheKey` is fundamentally the same thing as the proposer shuffling decision root,
/// however here we use it as an identity for both of the following values:
///
/// 1. The `state.current_justified_checkpoint`.
/// 2. The attester shuffling.
///
/// This struct relies upon the premise that the `state.current_justified_checkpoint` in epoch `n`
/// is determined by the root of the latest block in epoch `n - 1`. Notably, this is identical to
/// how the proposer shuffling is keyed in `BeaconProposerCache`.
///
/// It is also safe, but not maximally efficient, to key the attester shuffling with the same
/// strategy. For better shuffling keying strategies, see the `ShufflingCache`.
#[derive(Eq, PartialEq, Hash, Clone, Copy)]
pub struct AttesterCacheKey {
    /// The epoch from which the justified checkpoint should be observed.
    ///
    /// Attestations which use `self.epoch` as `target.epoch` should use this key.
    epoch: Epoch,
    /// The root of the block at the last slot of `self.epoch - 1`.
    decision_root: Hash256,
}

impl AttesterCacheKey {
    /// Instantiate `Self` to key `state.current_epoch()`.
    ///
    /// The `latest_block_root` should be the latest block that has been applied to `state`. This
    /// parameter is required since the state does not store the block root for any block with the
    /// same slot as `state.slot()`.
    ///
    /// ## Errors
    ///
    /// May error if `epoch` is out of the range of `state.block_roots`.
    pub fn new<T: EthSpec>(
        epoch: Epoch,
        state: &BeaconState<T>,
        latest_block_root: Hash256,
    ) -> Result<Self, Error> {
        let slots_per_epoch = T::slots_per_epoch();
        let decision_slot = epoch.start_slot(slots_per_epoch).saturating_sub(1_u64);

        let decision_root = if decision_slot.epoch(slots_per_epoch) == epoch {
            // This scenario is only possible during the genesis epoch. In this scenario, all-zeros
            // is used as an alias to the genesis block.
            Hash256::zero()
        } else if epoch > state.current_epoch() {
            // If the requested epoch is higher than the current epoch, the latest block will always
            // be the decision root.
            latest_block_root
        } else {
            *state.get_block_root(decision_slot)?
        };

        Ok(Self {
            epoch,
            decision_root,
        })
    }
}

/// Provides a cache for the justified checkpoint and committee length when producing an
/// attestation.
///
/// See the module-level documentation for more information.
#[derive(Default)]
pub struct AttesterCache {
    cache: RwLock<CacheHashMap>,
}

impl AttesterCache {
    /// Get the justified checkpoint and committee length for the `slot` and `committee_index` in
    /// the state identified by the cache `key`.
    pub fn get<T: EthSpec>(
        &self,
        key: &AttesterCacheKey,
        slot: Slot,
        committee_index: CommitteeIndex,
        spec: &ChainSpec,
    ) -> Result<Option<(JustifiedCheckpoint, CommitteeLength)>, Error> {
        self.cache
            .read()
            .get(key)
            .map(|cache_item| cache_item.get::<T>(slot, committee_index, spec))
            .transpose()
    }

    /// Cache the `state.current_epoch()` values if they are not already present in the state.
    pub fn maybe_cache_state<T: EthSpec>(
        &self,
        state: &BeaconState<T>,
        latest_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let key = AttesterCacheKey::new(state.current_epoch(), state, latest_block_root)?;
        let mut cache = self.cache.write();
        if !cache.contains_key(&key) {
            let cache_item = AttesterCacheValue::new(state, spec)?;
            Self::insert_respecting_max_len(&mut cache, key, cache_item);
        }
        Ok(())
    }

    /// Read the state identified by `state_root` from the database, advance it to the required
    /// slot, use it to prime the cache and return the values for the provided `slot` and
    /// `committee_index`.
    ///
    /// ## Notes
    ///
    /// This function takes a write-lock on the internal cache. Prefer attempting a `Self::get` call
    /// before running this function as `Self::get` only takes a read-lock and is therefore less
    /// likely to create contention.
    pub fn load_and_cache_state<T: BeaconChainTypes>(
        &self,
        state_root: Hash256,
        key: AttesterCacheKey,
        slot: Slot,
        committee_index: CommitteeIndex,
        chain: &BeaconChain<T>,
    ) -> Result<(JustifiedCheckpoint, CommitteeLength), Error> {
        let spec = &chain.spec;
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let epoch = slot.epoch(slots_per_epoch);

        // Take a write-lock on the cache before starting the state read.
        //
        // Whilst holding the write-lock during the state read will create contention, it prevents
        // the scenario where multiple requests from separate threads cause duplicate state reads.
        let mut cache = self.cache.write();

        // Try the cache to see if someone has already primed it between the time the function was
        // called and when the cache write-lock was obtained. This avoids performing duplicate state
        // reads.
        if let Some(value) = cache
            .get(&key)
            .map(|cache_item| cache_item.get::<T::EthSpec>(slot, committee_index, spec))
            .transpose()?
        {
            return Ok(value);
        }

        let mut state: BeaconState<T::EthSpec> = chain
            .get_state(&state_root, None)?
            .ok_or(Error::MissingBeaconState(state_root))?;

        if state.slot() > slot {
            // This indicates an internal inconsistency.
            return Err(Error::CannotAttestToFutureState {
                state_slot: state.slot(),
                request_slot: slot,
            });
        } else if state.current_epoch() < epoch {
            // Only perform a "partial" state advance since we do not require the state roots to be
            // accurate.
            partial_state_advance(
                &mut state,
                Some(state_root),
                epoch.start_slot(slots_per_epoch),
                spec,
            )
            .map_err(Error::FailedToTransitionState)?;
            state.build_committee_cache(RelativeEpoch::Current, spec)?;
        }

        let cache_item = AttesterCacheValue::new(&state, spec)?;
        let value = cache_item.get::<T::EthSpec>(slot, committee_index, spec)?;
        Self::insert_respecting_max_len(&mut cache, key, cache_item);
        Ok(value)
    }

    /// Insert a value to `cache`, ensuring it does not exceed the maximum length.
    ///
    /// If the cache is already full, the item with the lowest epoch will be removed.
    fn insert_respecting_max_len(
        cache: &mut CacheHashMap,
        key: AttesterCacheKey,
        value: AttesterCacheValue,
    ) {
        while cache.len() >= MAX_CACHE_LEN {
            if let Some(oldest) = cache
                .iter()
                .map(|(key, _)| *key)
                .min_by_key(|key| key.epoch)
            {
                cache.remove(&oldest);
            } else {
                break;
            }
        }

        cache.insert(key, value);
    }

    /// Remove all entries where the `key.epoch` is lower than the given `epoch`.
    ///
    /// Generally, the provided `epoch` should be the finalized epoch.
    pub fn prune_below(&self, epoch: Epoch) {
        self.cache.write().retain(|target, _| target.epoch >= epoch);
    }
}
