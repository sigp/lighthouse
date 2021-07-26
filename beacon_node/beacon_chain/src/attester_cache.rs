//! This module provides the `AttesterCache`, a cache designed for reducing state-reads when
//! validators produce `AttestationData`.
//!
//! This cache is required *as well as* the `ShufflingCache` since the `ShufflingCache` does not
//! provide any information about the `state.current_justified_checkpoint`. It is not trivial to add
//! the justified checkpoint to the `ShufflingCache` since that cache keyed by shuffling decision
//! root, which is not suitable for the justified checkpoint. Whilst we can know the shuffling for
//! epoch `n` during `n - 1`, we *cannot* know the justified checkpoint. Instead, we *must* perform
//! `per_epoch_processing` to transform the state from epoch `n - 1` to epoch `n` so that rewards
//! and penalties can be computed and the `state.current_justified_checkpoint` can be updated.

use parking_lot::RwLock;
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

/// The maximum number of `AttesterCacheValues` to be kept in memory.
const MAX_CACHE_LEN: usize = 64;

#[derive(Debug)]
pub enum Error {
    BeaconState(BeaconStateError),
    WrongEpoch { request_epoch: Epoch, epoch: Epoch },
    SlotTooLow { slot: Slot, first_slot: Slot },
    SlotTooHigh { slot: Slot, first_slot: Slot },
    InvalidCommitteeIndex { committee_index: u64 },
    InverseRange { range: Range<usize> },
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconState(e)
    }
}

struct CommitteeLengths {
    epoch: Epoch,
    active_validator_indices_len: usize,
}

impl CommitteeLengths {
    fn new<T: EthSpec>(state: &BeaconState<T>) -> Result<Self, Error> {
        let committee_cache = state.committee_cache(RelativeEpoch::Current)?;
        let active_validator_indices_len = committee_cache.active_validator_indices().len();

        Ok(Self {
            epoch: state.current_epoch(),
            active_validator_indices_len,
        })
    }

    fn get<T: EthSpec>(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
        spec: &ChainSpec,
    ) -> Result<CommitteeLength, Error> {
        let slots_per_epoch = T::slots_per_epoch();
        let request_epoch = slot.epoch(slots_per_epoch);
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

pub struct AttesterCacheValue {
    current_justified_checkpoint: Checkpoint,
    committee_lengths: CommitteeLengths,
}

impl AttesterCacheValue {
    pub fn new<T: EthSpec>(state: &BeaconState<T>) -> Result<Self, Error> {
        let current_justified_checkpoint = state.current_justified_checkpoint();
        let committee_lengths = CommitteeLengths::new(state)?;
        Ok(Self {
            current_justified_checkpoint,
            committee_lengths,
        })
    }

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

/// The `AttesterCacheKey` is fundamentally the same thing as the shuffling decision roots, however
/// it provides a unique key for both of the following values:
///
/// 1. The `state.current_justified_checkpoint`.
/// 2. The attester shuffling.
///
/// This struct relies upon the premise that the `state.current_justified_checkpoint` in epoch `n`
/// is determined by the root of the latest block in epoch `n - 1`. Notably, this is identical to
/// how the proposer shuffling is keyed in `BeaconProposerCache`.
///
/// It is also safe, but not maximally efficient, to key the attester shuffling by the same block
/// root. For better shuffling keying strategies, see the `ShufflingCache`.
#[derive(PartialEq, Hash, Clone, Copy)]
pub struct AttesterCacheKey {
    /// The epoch from which the justified checkpoint should be observed.
    epoch: Epoch,
    /// The root of the block at the last slot of `self.epoch - 1`.
    decision_root: Hash256,
}

impl AttesterCacheKey {
    pub fn new<T: EthSpec>(epoch: Epoch, state: &BeaconState<T>) -> Result<Self, Error> {
        let decision_slot = epoch.start_slot(T::slots_per_epoch()).saturating_sub(1_u64);
        let decision_root = *state.get_block_root(decision_slot)?;
        Ok(Self {
            epoch,
            decision_root,
        })
    }
}

impl Eq for AttesterCacheKey {}

#[derive(Default)]
pub struct AttesterCache {
    cache: RwLock<HashMap<AttesterCacheKey, AttesterCacheValue>>,
}

impl AttesterCache {
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

    pub fn maybe_cache_state<T: EthSpec>(&self, state: &BeaconState<T>) -> Result<(), Error> {
        let key = AttesterCacheKey::new(state.current_epoch(), state)?;
        let key_exists = self.cache.read().contains_key(&key);
        if !key_exists {
            let cache_item = AttesterCacheValue::new(state)?;
            self.insert_respecting_max_len(key, cache_item);
        }
        Ok(())
    }

    pub fn cache_state_and_return_value<T: EthSpec>(
        &self,
        state: &BeaconState<T>,
        slot: Slot,
        index: CommitteeIndex,
        spec: &ChainSpec,
    ) -> Result<(JustifiedCheckpoint, CommitteeLength), Error> {
        let key = AttesterCacheKey::new(state.current_epoch(), state)?;
        let cache_item = AttesterCacheValue::new(state)?;
        let value = cache_item.get::<T>(slot, index, spec)?;
        self.insert_respecting_max_len(key, cache_item);
        Ok(value)
    }

    fn insert_respecting_max_len(&self, key: AttesterCacheKey, value: AttesterCacheValue) {
        let mut cache = self.cache.write();

        if cache.len() >= MAX_CACHE_LEN {
            while let Some(oldest) = cache
                .iter()
                .map(|(key, _)| key)
                .min_by_key(|key| key.epoch)
                .filter(|_| cache.len() >= MAX_CACHE_LEN)
                .copied()
            {
                cache.remove(&oldest);
            }
        }

        cache.insert(key, value);
    }

    pub fn prune_below(&self, epoch: Epoch) {
        self.cache.write().retain(|target, _| target.epoch >= epoch);
    }
}
