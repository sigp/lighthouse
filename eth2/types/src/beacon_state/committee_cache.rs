use super::BeaconState;
use crate::*;
use honey_badger_split::SplitExt;
use serde_derive::{Deserialize, Serialize};
use swap_or_not_shuffle::shuffle_list;

#[derive(Debug, PartialEq)]
pub enum Error {
    EpochOutOfBounds,
    UnableToShuffle,
    UnableToGenerateSeed,
}

mod tests;

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct CommitteeCache {
    /// `Some(epoch)` if the cache is initialized, where `epoch` is the cache it holds.
    initialized_epoch: Option<Epoch>,
    shuffling_start_shard: u64,
    shuffling: Vec<usize>,
    shard_count: u64,
    committee_count: usize,
    slots_per_epoch: u64,
    /// Maps validator index to a slot, shard and committee index for attestation.
    pub attestation_duties: Vec<Option<AttestationDuty>>,
}

impl CommitteeCache {
    /// Return a new, fully initialized cache.
    pub fn initialized<T: EthSpec>(
        state: &BeaconState<T>,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<CommitteeCache, BeaconStateError> {
        let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), epoch)
            .map_err(|_| BeaconStateError::EpochOutOfBounds)?;

        let active_validator_indices =
            get_active_validator_indices(&state.validator_registry, epoch);

        if active_validator_indices.is_empty() {
            return Err(BeaconStateError::InsufficientValidators);
        }

        let committee_count = T::get_epoch_committee_count(active_validator_indices.len()) as usize;

        let shuffling_start_shard = match relative_epoch {
            RelativeEpoch::Current => state.latest_start_shard,
            RelativeEpoch::Previous => {
                let committees_in_previous_epoch =
                    T::get_epoch_committee_count(active_validator_indices.len()) as u64;

                (state.latest_start_shard + T::shard_count() as u64 - committees_in_previous_epoch)
                    % T::shard_count() as u64
            }
            RelativeEpoch::Next => {
                let current_active_validators =
                    get_active_validator_count(&state.validator_registry, state.current_epoch());
                let committees_in_current_epoch =
                    T::get_epoch_committee_count(current_active_validators) as u64;

                (state.latest_start_shard + committees_in_current_epoch) % T::shard_count() as u64
            }
        };

        let seed = state.generate_seed(epoch, spec)?;

        let shuffling = shuffle_list(
            active_validator_indices,
            spec.shuffle_round_count,
            &seed[..],
            false,
        )
        .ok_or_else(|| Error::UnableToShuffle)?;

        let mut cache = CommitteeCache {
            initialized_epoch: Some(epoch),
            shuffling_start_shard,
            shuffling,
            shard_count: T::shard_count() as u64,
            committee_count,
            slots_per_epoch: T::slots_per_epoch(),
            attestation_duties: vec![None; state.validator_registry.len()],
        };

        cache.build_attestation_duties();

        Ok(cache)
    }

    fn build_attestation_duties(&mut self) {
        for (i, committee) in self
            .shuffling
            .honey_badger_split(self.committee_count)
            .enumerate()
        {
            let shard = (self.shuffling_start_shard + i as u64) % self.shard_count;

            let slot = self.crosslink_slot_for_shard(shard).unwrap();

            for (committee_index, validator_index) in committee.iter().enumerate() {
                self.attestation_duties[*validator_index] = Some(AttestationDuty {
                    slot,
                    shard,
                    committee_index,
                    committee_len: committee.len(),
                });
            }
        }
    }

    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        Some(epoch) == self.initialized_epoch
    }

    pub fn active_validator_indices(&self) -> &[usize] {
        &self.shuffling
    }

    /// Return `Some(CrosslinkCommittee)` if the given shard has a committee during the given
    /// `epoch`.
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

    pub fn active_validator_count(&self) -> usize {
        self.shuffling.len()
    }

    pub fn epoch_committee_count(&self) -> usize {
        self.committee_count
    }

    pub fn epoch_start_shard(&self) -> u64 {
        self.shuffling_start_shard
    }

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

    pub fn first_committee_at_slot(&self, slot: Slot) -> Option<&[usize]> {
        self.get_crosslink_committees_for_slot(slot)?
            .first()
            .and_then(|cc| Some(cc.committee))
    }

    fn compute_committee(&self, index: usize) -> Option<&[usize]> {
        if self.initialized_epoch.is_none() {
            return None;
        }

        let num_validators = self.shuffling.len();
        let count = self.committee_count;

        // Note: `count != 0` is enforced in the constructor.
        let start = (num_validators * index) / count;
        let end = (num_validators * (index + 1)) / count;

        Some(&self.shuffling[start..end])
    }

    fn crosslink_slot_for_shard(&self, shard: u64) -> Option<Slot> {
        let offset = (shard + self.shard_count - self.shuffling_start_shard) % self.shard_count;
        Some(
            self.initialized_epoch?.start_slot(self.slots_per_epoch)
                + offset / (self.committee_count as u64 / self.slots_per_epoch),
        )
    }
}

/// Returns a list of all `validator_registry` indices where the validator is active at the given
/// `epoch`.
///
/// Spec v0.6.1
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

pub fn get_active_validator_count(validators: &[Validator], epoch: Epoch) -> usize {
    validators.iter().filter(|v| v.is_active_at(epoch)).count()
}
