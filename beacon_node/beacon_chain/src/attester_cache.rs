use parking_lot::RwLock;
use std::collections::HashMap;
use types::{
    BeaconState, BeaconStateError, Checkpoint, Epoch, EthSpec, Hash256, RelativeEpoch, Slot,
};

type TargetCheckpoint = Checkpoint;
type JustifiedCheckpoint = Checkpoint;
type CommitteeLength = usize;
type CommitteeIndex = u64;

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

pub struct CacheItem {
    current_justified_checkpoint: Checkpoint,
    committee_lengths: CommitteeLengths,
}

impl CacheItem {
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

#[derive(Default)]
pub struct AttesterCache {
    cache: RwLock<HashMap<TargetCheckpoint, CacheItem>>,
}

impl AttesterCache {
    pub fn get(
        &self,
        target: &TargetCheckpoint,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<Option<(JustifiedCheckpoint, CommitteeLength)>, Error> {
        self.cache
            .read()
            .get(target)
            .map(|cache_item| cache_item.get(slot, committee_index))
            .transpose()
    }

    pub fn maybe_cache_state<T: EthSpec>(
        &self,
        state: &BeaconState<T>,
        latest_beacon_block_root: Hash256,
    ) -> Result<(), Error> {
        let target = get_state_target(state, latest_beacon_block_root)?;
        let key_exists = self.cache.read().contains_key(&target);
        if !key_exists {
            let cache_item = CacheItem::new(state)?;
            self.cache.write().insert(target, cache_item);
        }
        Ok(())
    }

    pub fn cache_state_and_return_value<T: EthSpec>(
        &self,
        state: &BeaconState<T>,
        latest_beacon_block_root: Hash256,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<(JustifiedCheckpoint, CommitteeLength), Error> {
        let target = get_state_target(state, latest_beacon_block_root)?;
        let cache_item = CacheItem::new(state)?;
        let value = cache_item.get(slot, index)?;
        self.cache.write().insert(target, cache_item);
        Ok(value)
    }

    pub fn prune_below(&self, epoch: Epoch) {
        self.cache.write().retain(|target, _| target.epoch >= epoch);
    }
}

fn get_state_target<T: EthSpec>(
    state: &BeaconState<T>,
    latest_beacon_block_root: Hash256,
) -> Result<Checkpoint, BeaconStateError> {
    let target_epoch = state.current_epoch();
    let target_slot = target_epoch.start_slot(T::slots_per_epoch());
    let target_root = if state.slot() <= target_slot {
        latest_beacon_block_root
    } else {
        *state.get_block_root(target_slot)?
    };

    Ok(Checkpoint {
        epoch: target_epoch,
        root: target_root,
    })
}
