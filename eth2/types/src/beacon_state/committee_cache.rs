use super::BeaconState;
use crate::*;
use core::num::NonZeroUsize;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::ops::Range;
use swap_or_not_shuffle::shuffle_list;

mod tests;

/// Computes and stores the shuffling for an epoch. Provides various getters to allow callers to
/// read the committees for the given epoch.
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct CommitteeCache {
    initialized_epoch: Option<Epoch>,
    shuffling: Vec<usize>,
    shuffling_positions: Vec<Option<NonZeroUsize>>,
    committees_per_slot: u64,
    slots_per_epoch: u64,
}

impl CommitteeCache {
    /// Return a new, fully initialized cache.
    ///
    /// Spec v0.11.1
    pub fn initialized<T: EthSpec>(
        state: &BeaconState<T>,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<CommitteeCache, Error> {
        RelativeEpoch::from_epoch(state.current_epoch(), epoch)
            .map_err(|_| Error::EpochOutOfBounds)?;

        // May cause divide-by-zero errors.
        if T::slots_per_epoch() == 0 {
            return Err(Error::ZeroSlotsPerEpoch);
        }

        let active_validator_indices = get_active_validator_indices(&state.validators, epoch);

        if active_validator_indices.is_empty() {
            return Err(Error::InsufficientValidators);
        }

        let committees_per_slot =
            T::get_committee_count_per_slot(active_validator_indices.len(), spec) as u64;

        let seed = state.get_seed(epoch, Domain::BeaconAttester, spec)?;

        let shuffling = shuffle_list(
            active_validator_indices,
            spec.shuffle_round_count,
            &seed[..],
            false,
        )
        .ok_or_else(|| Error::UnableToShuffle)?;

        // The use of `NonZeroUsize` reduces the maximum number of possible validators by one.
        if state.validators.len() > usize::max_value() - 1 {
            return Err(Error::TooManyValidators);
        }

        let mut shuffling_positions = vec![None; state.validators.len()];
        for (i, v) in shuffling.iter().enumerate() {
            shuffling_positions[*v] = NonZeroUsize::new(i + 1);
        }

        Ok(CommitteeCache {
            initialized_epoch: Some(epoch),
            shuffling,
            shuffling_positions,
            committees_per_slot,
            slots_per_epoch: T::slots_per_epoch(),
        })
    }

    /// Returns `true` if the cache has been initialized at the supplied `epoch`.
    ///
    /// An non-initialized cache does not provide any useful information.
    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        Some(epoch) == self.initialized_epoch
    }

    /// Returns the **shuffled** list of active validator indices for the initialized epoch.
    ///
    /// These indices are not in ascending order.
    ///
    /// Always returns `&[]` for a non-initialized epoch.
    ///
    /// Spec v0.11.1
    pub fn active_validator_indices(&self) -> &[usize] {
        &self.shuffling
    }

    /// Returns the shuffled list of active validator indices for the initialized epoch.
    ///
    /// Always returns `&[]` for a non-initialized epoch.
    ///
    /// Spec v0.11.1
    pub fn shuffling(&self) -> &[usize] {
        &self.shuffling
    }

    /// Get the Beacon committee for the given `slot` and `index`.
    ///
    /// Return `None` if the cache is uninitialized, or the `slot` or `index` is out of range.
    pub fn get_beacon_committee(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Option<BeaconCommittee> {
        if self.initialized_epoch.is_none()
            || !self.is_initialized_at(slot.epoch(self.slots_per_epoch))
            || index >= self.committees_per_slot
        {
            return None;
        }

        let committee_index =
            (slot.as_u64() % self.slots_per_epoch) * self.committees_per_slot + index;
        let committee = self.compute_committee(committee_index as usize)?;

        Some(BeaconCommittee {
            slot,
            index,
            committee,
        })
    }

    /// Get all the Beacon committees at a given `slot`.
    pub fn get_beacon_committees_at_slot(&self, slot: Slot) -> Result<Vec<BeaconCommittee>, Error> {
        if self.initialized_epoch.is_none() {
            return Err(Error::CommitteeCacheUninitialized(None));
        }

        (0..self.committees_per_slot())
            .map(|index| {
                self.get_beacon_committee(slot, index)
                    .ok_or(Error::NoCommittee { slot, index })
            })
            .collect()
    }

    /// Returns all committees for `self.initialized_epoch`.
    pub fn get_all_beacon_committees(&self) -> Result<Vec<BeaconCommittee>, Error> {
        let initialized_epoch = self
            .initialized_epoch
            .ok_or_else(|| Error::CommitteeCacheUninitialized(None))?;

        initialized_epoch.slot_iter(self.slots_per_epoch).try_fold(
            Vec::with_capacity(self.slots_per_epoch as usize),
            |mut vec, slot| {
                vec.append(&mut self.get_beacon_committees_at_slot(slot)?);
                Ok(vec)
            },
        )
    }

    /// Returns the `AttestationDuty` for the given `validator_index`.
    ///
    /// Returns `None` if the `validator_index` does not exist, does not have duties or `Self` is
    /// non-initialized.
    pub fn get_attestation_duties(&self, validator_index: usize) -> Option<AttestationDuty> {
        let i = self.shuffled_position(validator_index)?;

        (0..self.epoch_committee_count())
            .map(|nth_committee| (nth_committee, self.compute_committee_range(nth_committee)))
            .find(|(_, range)| {
                if let Some(range) = range {
                    range.start <= i && range.end > i
                } else {
                    false
                }
            })
            .and_then(|(nth_committee, range)| {
                let (slot, index) = self.convert_to_slot_and_index(nth_committee as u64)?;
                let range = range?;
                let committee_position = i - range.start;
                let committee_len = range.end - range.start;

                Some(AttestationDuty {
                    slot,
                    index,
                    committee_position,
                    committee_len,
                })
            })
    }

    /// Convert an index addressing the list of all epoch committees into a slot and per-slot index.
    fn convert_to_slot_and_index(
        &self,
        global_committee_index: u64,
    ) -> Option<(Slot, CommitteeIndex)> {
        let epoch_start_slot = self.initialized_epoch?.start_slot(self.slots_per_epoch);
        let slot_offset = global_committee_index / self.committees_per_slot;
        let index = global_committee_index % self.committees_per_slot;
        Some((epoch_start_slot + slot_offset, index))
    }

    /// Returns the number of active validators in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.11.1
    pub fn active_validator_count(&self) -> usize {
        self.shuffling.len()
    }

    /// Returns the total number of committees in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.11.1
    pub fn epoch_committee_count(&self) -> usize {
        self.committees_per_slot as usize * self.slots_per_epoch as usize
    }

    /// Returns the number of committees per slot for this cache's epoch.
    pub fn committees_per_slot(&self) -> u64 {
        self.committees_per_slot
    }

    /// Returns a slice of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// Spec v0.11.1
    fn compute_committee(&self, index: usize) -> Option<&[usize]> {
        Some(&self.shuffling[self.compute_committee_range(index)?])
    }

    /// Returns a range of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// To avoid a divide-by-zero, returns `None` if `self.committee_count` is zero.
    ///
    /// Will also return `None` if the index is out of bounds.
    ///
    /// Spec v0.11.1
    fn compute_committee_range(&self, index: usize) -> Option<Range<usize>> {
        let count = self.epoch_committee_count();
        if count == 0 || index >= count {
            return None;
        }

        let num_validators = self.shuffling.len();
        let start = (num_validators * index) / count;
        let end = (num_validators * (index + 1)) / count;

        Some(start..end)
    }

    /// Returns the index of some validator in `self.shuffling`.
    ///
    /// Always returns `None` for a non-initialized epoch.
    fn shuffled_position(&self, validator_index: usize) -> Option<usize> {
        self.shuffling_positions
            .get(validator_index)?
            .and_then(|p| Some(p.get() - 1))
    }
}

/// Returns a list of all `validators` indices where the validator is active at the given
/// `epoch`.
///
/// Spec v0.11.1
pub fn get_active_validator_indices(validators: &[Validator], epoch: Epoch) -> Vec<usize> {
    let mut active = Vec::with_capacity(validators.len());

    for (index, validator) in validators.iter().enumerate() {
        if validator.is_active_at(epoch) {
            active.push(index)
        }
    }

    active.shrink_to_fit();

    active
}
