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
    /// All crosslink committees for an epoch.
    pub epoch_crosslink_committees: EpochCrosslinkCommittees,
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
        seed: Hash256,
        epoch_start_shard: u64,
        spec: &ChainSpec,
    ) -> Result<EpochCache, Error> {
        if epoch != state.previous_epoch(spec) && epoch != state.current_epoch(spec) {
            return Err(Error::EpochOutOfBounds);
        }

        let active_validator_indices =
            get_active_validator_indices(&state.validator_registry, epoch);

        let epoch_crosslink_committees = EpochCrosslinkCommittees::new(
            epoch,
            active_validator_indices.clone(),
            seed,
            epoch_start_shard,
            state.get_epoch_committee_count(epoch, spec),
            spec,
        );

        // Loop through all the validators in the committees and create the following map:
        //
        // `attestation_duties`: maps `ValidatorIndex` to `AttestationDuty`.
        let mut attestation_duties = vec![None; state.validator_registry.len()];
        for crosslink_committee in epoch_crosslink_committees.crosslink_committees.iter() {
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

        Ok(EpochCache {
            initialized_epoch: Some(epoch),
            epoch_crosslink_committees,
            attestation_duties,
            active_validator_indices,
        })
    }

    /// Return a vec of `CrosslinkCommittee` for a given slot.
    pub fn get_crosslink_committees_at_slot(
        &self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Option<&Vec<CrosslinkCommittee>> {
        self.epoch_crosslink_committees
            .get_crosslink_committees_at_slot(slot, spec)
    }

    /// Return `Some(CrosslinkCommittee)` if the given shard has a committee during the given
    /// `epoch`.
    pub fn get_crosslink_committee_for_shard(
        &self,
        shard: Shard,
        spec: &ChainSpec,
    ) -> Option<&CrosslinkCommittee> {
        if shard > self.shard_committee_indices.len() as u64 {
            None
        } else {
            let (slot, committee) = self.shard_committee_indices[shard as usize]?;
            let slot_committees = self.get_crosslink_committees_at_slot(slot, spec)?;
            slot_committees.get(committee)
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

/// Contains all `CrosslinkCommittees` for an epoch.
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct EpochCrosslinkCommittees {
    /// The epoch the committees are present in.
    epoch: Epoch,
    /// Committees indexed by the `index` parameter of `compute_committee` from the spec.
    ///
    /// The length of the vector is equal to the number of committees in the epoch
    /// i.e. `state.get_epoch_committee_count(self.epoch)`
    pub crosslink_committees: Vec<CrosslinkCommittee>,
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

impl EpochCrosslinkCommittees {
    fn new(
        epoch: Epoch,
        active_validator_indices: Vec<usize>,
        seed: Hash256,
        epoch_start_shard: u64,
        epoch_committee_count: u64,
        spec: &ChainSpec,
    ) -> Self {
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

        let committee_size =
            shuffled_active_validator_indices.len() / epoch_committee_count as usize;

        let crosslink_committees = shuffled_active_validator_indices
            .into_iter()
            .chunks(committee_size)
            .enumerate()
            .map(|(index, committee)| {
                let shard = (epoch_start_start_shard + index) % spec.shard_count;
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
            .collect();

        Ok(Self {
            epoch,
            crosslink_committees,
        })
    }

    /// Return a vec of `CrosslinkCommittee` for a given slot.
    fn get_crosslink_committees_at_slot(
        &self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Option<&Vec<CrosslinkCommittee>> {
        let epoch_start_slot = self.epoch.start_slot(spec.slots_per_epoch);
        let epoch_end_slot = self.epoch.end_slot(spec.slots_per_epoch);

        if (epoch_start_slot <= slot) && (slot <= epoch_end_slot) {
            let index = slot - epoch_start_slot;
            self.crosslink_committees.get(index.as_usize())
        } else {
            None
        }
    }
}
