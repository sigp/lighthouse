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
pub struct EpochCache {
    /// `Some(epoch)` if the cache is initialized, where `epoch` is the cache it holds.
    pub initialized_epoch: Option<Epoch>,
    /// All crosslink committees.
    pub crosslink_committees: Vec<CrosslinkCommittee>,
    /// Maps a shard to `self.epoch_crosslink_committees`.
    pub shard_crosslink_committees: Vec<Option<usize>>,
    /// Maps a slot to `self.epoch_crosslink_committees`.
    pub slot_crosslink_committees: Vec<Option<usize>>,
    /// Maps validator index to a slot, shard and committee index for attestation.
    pub attestation_duties: Vec<Option<AttestationDuty>>,
    /// Indices of all active validators in the epoch
    pub active_validator_indices: Vec<usize>,
}

impl EpochCache {
    /// Return a new, fully initialized cache.
    pub fn initialized<T: EthSpec>(
        state: &BeaconState<T>,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<EpochCache, BeaconStateError> {
        if (epoch < state.previous_epoch()) || (epoch > state.next_epoch()) {
            return Err(BeaconStateError::EpochOutOfBounds);
        }

        let active_validator_indices =
            get_active_validator_indices(&state.validator_registry, epoch);

        let epoch_committee_count = state.get_epoch_committee_count(epoch, spec);

        let crosslink_committees = compute_epoch_committees(
            epoch,
            state,
            active_validator_indices.clone(),
            epoch_committee_count,
            spec,
        )?;

        let mut shard_crosslink_committees = vec![None; T::shard_count()];
        let mut slot_crosslink_committees = vec![None; spec.slots_per_epoch as usize];
        let mut attestation_duties = vec![None; state.validator_registry.len()];

        for (i, crosslink_committee) in crosslink_committees.iter().enumerate() {
            shard_crosslink_committees[crosslink_committee.shard as usize] = Some(i);

            let slot_index = epoch
                .position(crosslink_committee.slot, spec.slots_per_epoch)
                .ok_or_else(|| BeaconStateError::SlotOutOfBounds)?;
            slot_crosslink_committees[slot_index] = Some(i);

            // Loop through each validator in the committee and store its attestation duties.
            for (committee_index, validator_index) in
                crosslink_committee.committee.iter().enumerate()
            {
                let attestation_duty = AttestationDuty {
                    slot: crosslink_committee.slot,
                    shard: crosslink_committee.shard,
                    committee_index,
                    committee_len: crosslink_committee.committee.len(),
                };
                attestation_duties[*validator_index] = Some(attestation_duty);
            }
        }

        dbg!(&shard_crosslink_committees);

        Ok(EpochCache {
            initialized_epoch: Some(epoch),
            crosslink_committees,
            attestation_duties,
            shard_crosslink_committees,
            slot_crosslink_committees,
            active_validator_indices,
        })
    }

    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        Some(epoch) == self.initialized_epoch
    }

    /// Return `Some(CrosslinkCommittee)` if the given shard has a committee during the given
    /// `epoch`.
    pub fn get_crosslink_committee_for_shard(&self, shard: Shard) -> Option<&CrosslinkCommittee> {
        if shard > self.shard_crosslink_committees.len() as u64 {
            None
        } else {
            let i = self.shard_crosslink_committees[shard as usize]?;
            Some(&self.crosslink_committees[i])
        }
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

pub fn compute_epoch_committees<T: EthSpec>(
    epoch: Epoch,
    state: &BeaconState<T>,
    active_validator_indices: Vec<usize>,
    epoch_committee_count: u64,
    spec: &ChainSpec,
) -> Result<Vec<CrosslinkCommittee>, BeaconStateError> {
    let seed = state.generate_seed(epoch, spec)?;

    // The shuffler fails on a empty list, so if there are no active validator indices, simply
    // return an empty list.
    let shuffled_active_validator_indices = if active_validator_indices.is_empty() {
        vec![]
    } else {
        shuffle_list(
            active_validator_indices,
            spec.shuffle_round_count,
            &seed[..],
            false,
        )
        .ok_or_else(|| Error::UnableToShuffle)?
    };

    let epoch_start_shard = state.get_epoch_start_shard(epoch, spec)?;

    Ok(shuffled_active_validator_indices
        .honey_badger_split(epoch_committee_count as usize)
        .enumerate()
        .map(|(index, committee)| {
            let shard = (epoch_start_shard + index as u64) % spec.shard_count;

            dbg!(index);
            dbg!(shard);

            let slot = crosslink_committee_slot(
                shard,
                epoch,
                epoch_start_shard,
                epoch_committee_count,
                spec,
            );
            CrosslinkCommittee {
                slot,
                shard,
                committee: committee.to_vec(),
            }
        })
        .collect())
}

fn crosslink_committee_slot(
    shard: u64,
    epoch: Epoch,
    epoch_start_shard: u64,
    epoch_committee_count: u64,
    spec: &ChainSpec,
) -> Slot {
    // Excerpt from `get_attestation_slot` in the spec.
    let offset = (shard + spec.shard_count - epoch_start_shard) % spec.shard_count;
    epoch.start_slot(spec.slots_per_epoch) + offset / (epoch_committee_count / spec.slots_per_epoch)
}
