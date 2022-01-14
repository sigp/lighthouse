use crate::max_cover::MaxCover;
use state_processing::common::{
    altair, base, get_attestation_participation_flag_indices, get_attesting_indices,
};
use std::collections::HashMap;
use types::{
    beacon_state::BeaconStateBase,
    consts::altair::{PARTICIPATION_FLAG_WEIGHTS, WEIGHT_DENOMINATOR},
    Attestation, BeaconState, BitList, ChainSpec, EthSpec,
};

#[derive(Debug, Clone)]
pub struct AttMaxCover<'a, T: EthSpec> {
    /// Underlying attestation.
    pub att: &'a Attestation<T>,
    /// Mapping of validator indices and their rewards.
    pub fresh_validators_rewards: HashMap<u64, u64>,
}

impl<'a, T: EthSpec> AttMaxCover<'a, T> {
    pub fn new(
        att: &'a Attestation<T>,
        state: &BeaconState<T>,
        total_active_balance: u64,
        spec: &ChainSpec,
    ) -> Option<Self> {
        if let BeaconState::Base(ref base_state) = state {
            Self::new_for_base(att, state, base_state, total_active_balance, spec)
        } else {
            Self::new_for_altair(att, state, total_active_balance, spec)
        }
    }

    /// Initialise an attestation cover object for base/phase0 hard fork.
    pub fn new_for_base(
        att: &'a Attestation<T>,
        state: &BeaconState<T>,
        base_state: &BeaconStateBase<T>,
        total_active_balance: u64,
        spec: &ChainSpec,
    ) -> Option<Self> {
        let fresh_validators = earliest_attestation_validators(att, state, base_state);
        let committee = state
            .get_beacon_committee(att.data.slot, att.data.index)
            .ok()?;
        let indices = get_attesting_indices::<T>(committee.committee, &fresh_validators).ok()?;
        let fresh_validators_rewards: HashMap<u64, u64> = indices
            .iter()
            .map(|i| *i as u64)
            .flat_map(|validator_index| {
                let reward = base::get_base_reward(
                    state,
                    validator_index as usize,
                    total_active_balance,
                    spec,
                )
                .ok()?
                .checked_div(spec.proposer_reward_quotient)?;
                Some((validator_index, reward))
            })
            .collect();
        Some(Self {
            att,
            fresh_validators_rewards,
        })
    }

    /// Initialise an attestation cover object for Altair or later.
    pub fn new_for_altair(
        att: &'a Attestation<T>,
        state: &BeaconState<T>,
        total_active_balance: u64,
        spec: &ChainSpec,
    ) -> Option<Self> {
        let committee = state
            .get_beacon_committee(att.data.slot, att.data.index)
            .ok()?;
        let attesting_indices =
            get_attesting_indices::<T>(committee.committee, &att.aggregation_bits).ok()?;

        let participation_list = if att.data.target.epoch == state.current_epoch() {
            state.current_epoch_participation().ok()?
        } else if att.data.target.epoch == state.previous_epoch() {
            state.previous_epoch_participation().ok()?
        } else {
            return None;
        };

        let inclusion_delay = state.slot().as_u64().checked_sub(att.data.slot.as_u64())?;
        let att_participation_flags =
            get_attestation_participation_flag_indices(state, &att.data, inclusion_delay, spec)
                .ok()?;

        let fresh_validators_rewards = attesting_indices
            .iter()
            .filter_map(|&index| {
                let mut proposer_reward_numerator = 0;
                let participation = participation_list.get(index)?;

                let base_reward =
                    altair::get_base_reward(state, index, total_active_balance, spec).ok()?;

                for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                    if att_participation_flags.contains(&flag_index)
                        && !participation.has_flag(flag_index).ok()?
                    {
                        proposer_reward_numerator += base_reward.checked_mul(*weight)?;
                    }
                }

                let proposer_reward = proposer_reward_numerator
                    .checked_div(WEIGHT_DENOMINATOR.checked_mul(spec.proposer_reward_quotient)?)?;

                Some((index as u64, proposer_reward)).filter(|_| proposer_reward != 0)
            })
            .collect();

        Some(Self {
            att,
            fresh_validators_rewards,
        })
    }
}

impl<'a, T: EthSpec> MaxCover for AttMaxCover<'a, T> {
    type Object = Attestation<T>;
    type Set = HashMap<u64, u64>;

    fn object(&self) -> &Attestation<T> {
        self.att
    }

    fn covering_set(&self) -> &HashMap<u64, u64> {
        &self.fresh_validators_rewards
    }

    /// Sneaky: we keep all the attestations together in one bucket, even though
    /// their aggregation bitfields refer to different committees. In order to avoid
    /// confusing committees when updating covering sets, we update only those attestations
    /// whose slot and index match the attestation being included in the solution, by the logic
    /// that a slot and index uniquely identify a committee.
    ///
    /// We completely remove any validator covered by another attestation. This is close to optimal
    /// because including two attestations on chain to satisfy different participation bits is
    /// impossible without the validator double voting. I.e. it is only suboptimal in the presence
    /// of slashable voting, which is rare.
    fn update_covering_set(
        &mut self,
        best_att: &Attestation<T>,
        covered_validators: &HashMap<u64, u64>,
    ) {
        if self.att.data.slot == best_att.data.slot && self.att.data.index == best_att.data.index {
            self.fresh_validators_rewards
                .retain(|k, _| !covered_validators.contains_key(k))
        }
    }

    fn score(&self) -> usize {
        self.fresh_validators_rewards.values().sum::<u64>() as usize
    }
}

/// Extract the validators for which `attestation` would be their earliest in the epoch.
///
/// The reward paid to a proposer for including an attestation is proportional to the number
/// of validators for which the included attestation is their first in the epoch. The attestation
/// is judged against the state's `current_epoch_attestations` or `previous_epoch_attestations`
/// depending on when it was created, and all those validators who have already attested are
/// removed from the `aggregation_bits` before returning it.
///
/// This isn't optimal, but with the Altair fork this code is obsolete and not worth upgrading.
pub fn earliest_attestation_validators<T: EthSpec>(
    attestation: &Attestation<T>,
    state: &BeaconState<T>,
    base_state: &BeaconStateBase<T>,
) -> BitList<T::MaxValidatorsPerCommittee> {
    // Bitfield of validators whose attestations are new/fresh.
    let mut new_validators = attestation.aggregation_bits.clone();

    let state_attestations = if attestation.data.target.epoch == state.current_epoch() {
        &base_state.current_epoch_attestations
    } else if attestation.data.target.epoch == state.previous_epoch() {
        &base_state.previous_epoch_attestations
    } else {
        return BitList::with_capacity(0).unwrap();
    };

    state_attestations
        .iter()
        // In a single epoch, an attester should only be attesting for one slot and index.
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
