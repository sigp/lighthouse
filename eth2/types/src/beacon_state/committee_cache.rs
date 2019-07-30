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
    shuffling_start_shard: u64,
    shard_count: u64,
    committee_count: usize,
    slots_per_epoch: u64,
}

impl CommitteeCache {
    /// Return a new, fully initialized cache.
    ///
    /// Spec v0.8.1
    pub fn initialized<T: EthSpec>(
        state: &BeaconState<T>,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<CommitteeCache, Error> {
        let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), epoch)
            .map_err(|_| Error::EpochOutOfBounds)?;

        // May cause divide-by-zero errors.
        if T::slots_per_epoch() == 0 {
            return Err(Error::ZeroSlotsPerEpoch);
        }

        let active_validator_indices = get_active_validator_indices(&state.validators, epoch);

        if active_validator_indices.is_empty() {
            return Err(Error::InsufficientValidators);
        }

        let committee_count =
            T::get_committee_count(active_validator_indices.len(), spec.target_committee_size)
                as usize;

        let shuffling_start_shard =
            Self::compute_start_shard(state, relative_epoch, active_validator_indices.len(), spec);

        let seed = state.get_seed(epoch, spec)?;

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
            shuffling_start_shard,
            shuffling,
            shard_count: T::shard_count() as u64,
            committee_count,
            slots_per_epoch: T::slots_per_epoch(),
            shuffling_positions,
        })
    }

    /// Compute the shard which must be attested to first in a given relative epoch.
    ///
    /// The `active_validator_count` must be the number of validators active at `relative_epoch`.
    ///
    /// Spec v0.8.1
    pub fn compute_start_shard<T: EthSpec>(
        state: &BeaconState<T>,
        relative_epoch: RelativeEpoch,
        active_validator_count: usize,
        spec: &ChainSpec,
    ) -> u64 {
        match relative_epoch {
            RelativeEpoch::Current => state.start_shard,
            RelativeEpoch::Previous => {
                let shard_delta =
                    T::get_shard_delta(active_validator_count, spec.target_committee_size);

                (state.start_shard + T::ShardCount::to_u64() - shard_delta)
                    % T::ShardCount::to_u64()
            }
            RelativeEpoch::Next => {
                let current_active_validators =
                    get_active_validator_count(&state.validators, state.current_epoch());
                let shard_delta =
                    T::get_shard_delta(current_active_validators, spec.target_committee_size);

                (state.start_shard + shard_delta) % T::ShardCount::to_u64()
            }
        }
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
    /// Spec v0.8.1
    pub fn active_validator_indices(&self) -> &[usize] {
        &self.shuffling
    }

    /// Returns the shuffled list of active validator indices for the initialized epoch.
    ///
    /// Always returns `&[]` for a non-initialized epoch.
    ///
    /// Spec v0.8.1
    pub fn shuffling(&self) -> &[usize] {
        &self.shuffling
    }

    /// Return `Some(CrosslinkCommittee)` if the given shard has a committee during the given
    /// `epoch`.
    ///
    /// Always returns `None` for a non-initialized epoch.
    ///
    /// Spec v0.8.1
    pub fn get_crosslink_committee_for_shard(&self, shard: Shard) -> Option<CrosslinkCommittee> {
        if shard >= self.shard_count || self.initialized_epoch.is_none() {
            return None;
        }

        let committee_index =
            (shard + self.shard_count - self.shuffling_start_shard) % self.shard_count;
        let committee = self.compute_committee(committee_index as usize)?;
        let slot = self.crosslink_slot_for_shard(shard)?;

        Some(CrosslinkCommittee {
            shard,
            committee,
            slot,
        })
    }

    /// Returns the `AttestationDuty` for the given `validator_index`.
    ///
    /// Returns `None` if the `validator_index` does not exist, does not have duties or `Self` is
    /// non-initialized.
    pub fn get_attestation_duties(&self, validator_index: usize) -> Option<AttestationDuty> {
        let i = self.shuffled_position(validator_index)?;

        (0..self.committee_count)
            .map(|nth_committee| (nth_committee, self.compute_committee_range(nth_committee)))
            .find(|(_, range)| {
                if let Some(range) = range {
                    (range.start <= i) && (range.end > i)
                } else {
                    false
                }
            })
            .and_then(|(nth_committee, range)| {
                let shard = (self.shuffling_start_shard + nth_committee as u64) % self.shard_count;
                let slot = self.crosslink_slot_for_shard(shard)?;
                let range = range?;
                let committee_index = i - range.start;
                let committee_len = range.end - range.start;

                Some(AttestationDuty {
                    slot,
                    shard,
                    committee_index,
                    committee_len,
                })
            })
    }

    /// Returns the number of active validators in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.8.1
    pub fn active_validator_count(&self) -> usize {
        self.shuffling.len()
    }

    /// Returns the total number of committees in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.8.1
    pub fn epoch_committee_count(&self) -> usize {
        self.committee_count
    }

    /// Returns the shard assigned to the first committee in the initialized epoch.
    ///
    /// Always returns `u64::default()` for a non-initialized epoch.
    pub fn epoch_start_shard(&self) -> u64 {
        self.shuffling_start_shard
    }

    /// Returns all crosslink committees, if any, for the given slot in the initialized epoch.
    ///
    /// Returns `None` if `slot` is not in the initialized epoch, or if `Self` is not initialized.
    ///
    /// Spec v0.8.1
    pub fn get_crosslink_committees_for_slot(&self, slot: Slot) -> Option<Vec<CrosslinkCommittee>> {
        let position = self
            .initialized_epoch?
            .position(slot, self.slots_per_epoch)?;
        let committees_per_slot = self.committee_count / self.slots_per_epoch as usize;
        let position = position * committees_per_slot;

        if position >= self.committee_count {
            None
        } else {
            let mut committees = Vec::with_capacity(committees_per_slot);

            for index in position..position + committees_per_slot {
                let committee = self.compute_committee(index)?;
                let shard = (self.shuffling_start_shard + index as u64) % self.shard_count;

                committees.push(CrosslinkCommittee {
                    committee,
                    shard,
                    slot,
                });
            }

            Some(committees)
        }
    }

    /// Returns the first committee of the first slot of the initialized epoch.
    ///
    /// Always returns `None` for a non-initialized epoch.
    ///
    /// Spec v0.8.1
    pub fn first_committee_at_slot(&self, slot: Slot) -> Option<&[usize]> {
        self.get_crosslink_committees_for_slot(slot)?
            .first()
            .and_then(|cc| Some(cc.committee))
    }

    /// Returns a slice of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// Spec v0.8.1
    fn compute_committee(&self, index: usize) -> Option<&[usize]> {
        Some(&self.shuffling[self.compute_committee_range(index)?])
    }

    /// Returns a range of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// To avoid a divide-by-zero, returns `None` if `self.committee_count` is zero.
    ///
    /// Will also return `None` if the index is out of bounds.
    ///
    /// Spec v0.8.1
    fn compute_committee_range(&self, index: usize) -> Option<Range<usize>> {
        if self.committee_count == 0 || index >= self.committee_count {
            return None;
        }

        let num_validators = self.shuffling.len();
        let count = self.committee_count;

        let start = (num_validators * index) / count;
        let end = (num_validators * (index + 1)) / count;

        Some(start..end)
    }

    /// Returns the `slot` that `shard` will be crosslink-ed in during the initialized epoch.
    ///
    /// Always returns `None` for a non-initialized epoch.
    ///
    /// Spec v0.8.1
    fn crosslink_slot_for_shard(&self, shard: u64) -> Option<Slot> {
        let offset = (shard + self.shard_count - self.shuffling_start_shard) % self.shard_count;
        Some(
            self.initialized_epoch?.start_slot(self.slots_per_epoch)
                + offset / (self.committee_count as u64 / self.slots_per_epoch),
        )
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
/// Spec v0.8.1
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

/// Returns the count of all `validators` indices where the validator is active at the given
/// `epoch`.
///
/// Spec v0.8.1
fn get_active_validator_count(validators: &[Validator], epoch: Epoch) -> usize {
    validators.iter().filter(|v| v.is_active_at(epoch)).count()
}
