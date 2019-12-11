use crate::max_cover::MaxCover;
use state_processing::common::{get_attesting_indices, get_base_reward};
use std::collections::HashMap;
use std::convert::TryInto;
use types::{Attestation, BeaconState, BitList, ChainSpec, EthSpec};

pub struct AttMaxCover<'a, T: EthSpec> {
    /// Underlying attestation.
    att: &'a Attestation<T>,
    /// Mapping of validator indices and their rewards.
    fresh_validators_rewards: HashMap<u64, u64>,
}

impl<'a, T: EthSpec> AttMaxCover<'a, T> {
    pub fn new(
        att: &'a Attestation<T>,
        state: &BeaconState<T>,
        spec: &ChainSpec,
        total_active_balance: u64,
    ) -> Self {
        let fresh_validators = earliest_attestation_validators(att, state);
        let indices = get_attesting_indices(state, &att.data, &fresh_validators)
            .expect("should have returned valid indices");
        let fresh_validators_rewards: HashMap<u64, u64> = indices
            .iter()
            .cloned()
            .map(|validator_index| validator_index as u64)
            .zip(indices.iter().cloned().map(|validator_index| {
                get_base_reward(state, validator_index, total_active_balance, spec)
                    .expect("should have returned base reward for validator")
                    / spec.proposer_reward_quotient
            }))
            .collect();
        Self {
            att,
            fresh_validators_rewards,
        }
    }
}

impl<'a, T: EthSpec> MaxCover for AttMaxCover<'a, T> {
    type Object = Attestation<T>;
    type Set = HashMap<u64, u64>;

    fn object(&self) -> Attestation<T> {
        self.att.clone()
    }

    fn covering_set(&self) -> &HashMap<u64, u64> {
        &self.fresh_validators_rewards
    }

    /// Sneaky: we keep all the attestations together in one bucket, even though
    /// their aggregation bitfields refer to different committees. In order to avoid
    /// confusing committees when updating covering sets, we update only those attestations
    /// whose slot and index match the attestation being included in the solution, by the logic
    /// that a slot and index uniquely identify a committee.
    fn update_covering_set(
        &mut self,
        best_att: &Attestation<T>,
        covered_validators: &HashMap<u64, u64>,
    ) {
        if self.att.data.slot == best_att.data.slot && self.att.data.index == best_att.data.index {
            for key in covered_validators.keys() {
                let _ = self.fresh_validators_rewards.remove(key);
            }
        }
    }

    fn score(&self) -> usize {
        let size: u64 = self.fresh_validators_rewards.values().sum();
        (size as u64).try_into().unwrap()
    }
}

/// Extract the validators for which `attestation` would be their earliest in the epoch.
///
/// The reward paid to a proposer for including an attestation is proportional to the number
/// of validators for which the included attestation is their first in the epoch. The attestation
/// is judged against the state's `current_epoch_attestations` or `previous_epoch_attestations`
/// depending on when it was created, and all those validators who have already attested are
/// removed from the `aggregation_bits` before returning it.
// TODO: This could be optimised with a map from validator index to whether that validator has
// attested in each of the current and previous epochs. Currently quadratic in number of validators.
pub fn earliest_attestation_validators<T: EthSpec>(
    attestation: &Attestation<T>,
    state: &BeaconState<T>,
) -> BitList<T::MaxValidatorsPerCommittee> {
    // Bitfield of validators whose attestations are new/fresh.
    let mut new_validators = attestation.aggregation_bits.clone();

    let state_attestations = if attestation.data.target.epoch == state.current_epoch() {
        &state.current_epoch_attestations
    } else if attestation.data.target.epoch == state.previous_epoch() {
        &state.previous_epoch_attestations
    } else {
        return BitList::with_capacity(0).unwrap();
    };

    state_attestations
        .iter()
        // In a single epoch, an attester should only be attesting for one slot and index.
        // TODO: we avoid including slashable attestations in the state here,
        // but maybe we should do something else with them (like construct slashings).
        .filter(|existing_attestation| {
            existing_attestation.data.slot == attestation.data.slot
                && existing_attestation.data.index == attestation.data.index
        })
        .for_each(|existing_attestation| {
            // Remove the validators who have signed the existing attestation (they are not new)
            new_validators.difference_inplace(&existing_attestation.aggregation_bits);
        });

    new_validators
}
