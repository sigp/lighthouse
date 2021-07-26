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
use types::{
    BeaconState, BeaconStateError, Checkpoint, Epoch, EthSpec, Hash256, RelativeEpoch, Slot,
};

type JustifiedCheckpoint = Checkpoint;
type CommitteeLength = usize;
type CommitteeIndex = u64;

/// The maximum number of `AttesterCacheValues` to be kept in memory.
const MAX_CACHE_LEN: usize = 64;

#[derive(Debug)]
pub enum Error {
    BeaconState(BeaconStateError),
    SlotTooLow {
        slot: Slot,
        first_slot: Slot,
    },
    SlotTooHigh {
        slot: Slot,
        first_slot: Slot,
    },
    InvalidCommitteeIndex {
        slot_offset: usize,
        committee_index: u64,
    },
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconState(e)
    }
}

struct CommitteeLengths {
    first_slot: Slot,
    lengths: Vec<CommitteeLength>,
    slot_offsets: Vec<usize>,
}

impl CommitteeLengths {
    fn new<T: EthSpec>(state: &BeaconState<T>) -> Result<Self, Error> {
        let slots_per_epoch = T::slots_per_epoch();
        let current_epoch = state.current_epoch();
        let committee_cache = state.committee_cache(RelativeEpoch::Current)?;
        let committees_per_slot = committee_cache.committees_per_slot();

        let mut lengths = Vec::with_capacity((committees_per_slot * slots_per_epoch) as usize);
        let mut slot_offsets = Vec::with_capacity(slots_per_epoch as usize);

        for slot in current_epoch.slot_iter(slots_per_epoch) {
            slot_offsets.push(lengths.len());
            for index in 0..committees_per_slot {
                let length = state
                    .get_beacon_committee(slot, index as u64)?
                    .committee
                    .len();
                lengths.push(length);
            }
        }

        Ok(Self {
            first_slot: current_epoch.start_slot(slots_per_epoch),
            lengths,
            slot_offsets,
        })
    }

    fn get(&self, slot: Slot, committee_index: CommitteeIndex) -> Result<CommitteeLength, Error> {
        let first_slot = self.first_slot;
        let relative_slot = slot
            .as_usize()
            .checked_sub(first_slot.as_usize())
            .ok_or(Error::SlotTooLow { slot, first_slot })?;
        let slot_offset = *self
            .slot_offsets
            .get(relative_slot)
            .ok_or(Error::SlotTooHigh { slot, first_slot })?;
        slot_offset
            .checked_add(committee_index as usize)
            .and_then(|lengths_index| self.lengths.get(lengths_index).copied())
            .ok_or(Error::InvalidCommitteeIndex {
                slot_offset,
                committee_index,
            })
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

    fn get(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<(JustifiedCheckpoint, CommitteeLength), Error> {
        self.committee_lengths
            .get(slot, committee_index)
            .map(|committee_length| (self.current_justified_checkpoint, committee_length))
    }
}

#[derive(PartialEq, Hash, Clone, Copy)]
pub struct AttesterCacheKey {
    epoch: Epoch,
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
    pub fn get(
        &self,
        key: &AttesterCacheKey,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<Option<(JustifiedCheckpoint, CommitteeLength)>, Error> {
        self.cache
            .read()
            .get(key)
            .map(|cache_item| cache_item.get(slot, committee_index))
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
    ) -> Result<(JustifiedCheckpoint, CommitteeLength), Error> {
        let key = AttesterCacheKey::new(state.current_epoch(), state)?;
        let cache_item = AttesterCacheValue::new(state)?;
        let value = cache_item.get(slot, index)?;
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
