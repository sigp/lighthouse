use super::BeaconState;
use crate::*;
use honey_badger_split::SplitExt;
use serde_derive::{Deserialize, Serialize};
use swap_or_not_shuffle::shuffle_list;

#[derive(Debug, PartialEq)]
pub enum Error {
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
    /// Maps a shard to an index of `self.committees`.
    pub shard_committee_indices: Vec<Option<(Slot, usize)>>,
    /// Indices of all active validators in the epoch
    pub active_validator_indices: Vec<usize>,
}

impl EpochCache {
    /// Return a new, fully initialized cache.
    pub fn initialized(
        state: &BeaconState,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<EpochCache, Error> {
        let epoch = relative_epoch.into_epoch(state.slot.epoch(spec.slots_per_epoch));

        let active_validator_indices =
            get_active_validator_indices(&state.validator_registry, epoch);

        let builder = match relative_epoch {
            RelativeEpoch::Previous => EpochCrosslinkCommitteesBuilder::for_previous_epoch(
                state,
                active_validator_indices.clone(),
                spec,
            ),
            RelativeEpoch::Current => EpochCrosslinkCommitteesBuilder::for_current_epoch(
                state,
                active_validator_indices.clone(),
                spec,
            ),
            RelativeEpoch::NextWithRegistryChange => {
                EpochCrosslinkCommitteesBuilder::for_next_epoch(
                    state,
                    active_validator_indices.clone(),
                    true,
                    spec,
                )?
            }
            RelativeEpoch::NextWithoutRegistryChange => {
                EpochCrosslinkCommitteesBuilder::for_next_epoch(
                    state,
                    active_validator_indices.clone(),
                    false,
                    spec,
                )?
            }
        };
        let epoch_crosslink_committees = builder.build(spec)?;

        // Loop through all the validators in the committees and create the following maps:
        //
        // 1. `attestation_duties`: maps `ValidatorIndex` to `AttestationDuty`.
        // 2. `shard_committee_indices`: maps `Shard` into a `CrosslinkCommittee` in
        //    `EpochCrosslinkCommittees`.
        let mut attestation_duties = vec![None; state.validator_registry.len()];
        let mut shard_committee_indices = vec![None; spec.shard_count as usize];
        for (i, slot_committees) in epoch_crosslink_committees
            .crosslink_committees
            .iter()
            .enumerate()
        {
            let slot = epoch.start_slot(spec.slots_per_epoch) + i as u64;

            for (j, crosslink_committee) in slot_committees.iter().enumerate() {
                let shard = crosslink_committee.shard;

                shard_committee_indices[shard as usize] = Some((slot, j));

                for (k, validator_index) in crosslink_committee.committee.iter().enumerate() {
                    let attestation_duty = AttestationDuty {
                        slot,
                        shard,
                        committee_index: k,
                        committee_len: crosslink_committee.committee.len(),
                    };
                    attestation_duties[*validator_index] = Some(attestation_duty)
                }
            }
        }

        Ok(EpochCache {
            initialized_epoch: Some(epoch),
            epoch_crosslink_committees,
            attestation_duties,
            shard_committee_indices,
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
/// Spec v0.5.1
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
    /// Each commitee for each slot of the epoch.
    pub crosslink_committees: Vec<Vec<CrosslinkCommittee>>,
}

impl EpochCrosslinkCommittees {
    /// Return a new instances where all slots have zero committees.
    fn new(epoch: Epoch, spec: &ChainSpec) -> Self {
        Self {
            epoch,
            crosslink_committees: vec![vec![]; spec.slots_per_epoch as usize],
        }
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

/// Builds an `EpochCrosslinkCommittees` object.
pub struct EpochCrosslinkCommitteesBuilder {
    epoch: Epoch,
    shuffling_start_shard: Shard,
    shuffling_seed: Hash256,
    active_validator_indices: Vec<usize>,
    committees_per_epoch: u64,
}

impl EpochCrosslinkCommitteesBuilder {
    /// Instantiates a builder that will build for the `state`'s previous epoch.
    pub fn for_previous_epoch(
        state: &BeaconState,
        active_validator_indices: Vec<usize>,
        spec: &ChainSpec,
    ) -> Self {
        Self {
            epoch: state.previous_epoch(spec),
            shuffling_start_shard: state.previous_shuffling_start_shard,
            shuffling_seed: state.previous_shuffling_seed,
            committees_per_epoch: spec.get_epoch_committee_count(active_validator_indices.len()),
            active_validator_indices,
        }
    }

    /// Instantiates a builder that will build for the `state`'s next epoch.
    pub fn for_current_epoch(
        state: &BeaconState,
        active_validator_indices: Vec<usize>,
        spec: &ChainSpec,
    ) -> Self {
        Self {
            epoch: state.current_epoch(spec),
            shuffling_start_shard: state.current_shuffling_start_shard,
            shuffling_seed: state.current_shuffling_seed,
            committees_per_epoch: spec.get_epoch_committee_count(active_validator_indices.len()),
            active_validator_indices,
        }
    }

    /// Instantiates a builder that will build for the `state`'s next epoch.
    ///
    /// Note: there are two possible epoch builds for the next epoch, one where there is a registry
    /// change and one where there is not.
    pub fn for_next_epoch(
        state: &BeaconState,
        active_validator_indices: Vec<usize>,
        registry_change: bool,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let current_epoch = state.current_epoch(spec);
        let next_epoch = state.next_epoch(spec);
        let committees_per_epoch = spec.get_epoch_committee_count(active_validator_indices.len());

        let epochs_since_last_registry_update =
            current_epoch - state.validator_registry_update_epoch;

        let (seed, shuffling_start_shard) = if registry_change {
            let next_seed = state
                .generate_seed(next_epoch, spec)
                .map_err(|_| Error::UnableToGenerateSeed)?;
            (
                next_seed,
                (state.current_shuffling_start_shard + committees_per_epoch) % spec.shard_count,
            )
        } else if (epochs_since_last_registry_update > 1)
            & epochs_since_last_registry_update.is_power_of_two()
        {
            let next_seed = state
                .generate_seed(next_epoch, spec)
                .map_err(|_| Error::UnableToGenerateSeed)?;
            (next_seed, state.current_shuffling_start_shard)
        } else {
            (
                state.current_shuffling_seed,
                state.current_shuffling_start_shard,
            )
        };

        Ok(Self {
            epoch: state.next_epoch(spec),
            shuffling_start_shard,
            shuffling_seed: seed,
            active_validator_indices,
            committees_per_epoch,
        })
    }

    /// Consumes the builder, returning a fully-build `EpochCrosslinkCommittee`.
    pub fn build(self, spec: &ChainSpec) -> Result<EpochCrosslinkCommittees, Error> {
        // The shuffler fails on a empty list, so if there are no active validator indices, simply
        // return an empty list.
        let shuffled_active_validator_indices = if self.active_validator_indices.is_empty() {
            vec![]
        } else {
            shuffle_list(
                self.active_validator_indices,
                spec.shuffle_round_count,
                &self.shuffling_seed[..],
                false,
            )
            .ok_or_else(|| Error::UnableToShuffle)?
        };

        let mut committees: Vec<Vec<usize>> = shuffled_active_validator_indices
            .honey_badger_split(self.committees_per_epoch as usize)
            .map(|slice: &[usize]| slice.to_vec())
            .collect();

        let mut epoch_crosslink_committees = EpochCrosslinkCommittees::new(self.epoch, spec);
        let mut shard = self.shuffling_start_shard;

        let committees_per_slot = (self.committees_per_epoch / spec.slots_per_epoch) as usize;

        for (i, slot) in self.epoch.slot_iter(spec.slots_per_epoch).enumerate() {
            for j in (0..committees.len())
                .skip(i * committees_per_slot)
                .take(committees_per_slot)
            {
                let crosslink_committee = CrosslinkCommittee {
                    slot,
                    shard,
                    committee: committees[j].drain(..).collect(),
                };
                epoch_crosslink_committees.crosslink_committees[i].push(crosslink_committee);

                shard += 1;
                shard %= spec.shard_count;
            }
        }

        Ok(epoch_crosslink_committees)
    }
}
