use crate::attestation_storage::{CompactAttestationRef, CompactIndexedAttestation};
use crate::max_cover::MaxCover;
use crate::reward_cache::RewardCache;
use state_processing::common::{
    attesting_indices_base::get_attesting_indices, base, get_attestation_participation_flag_indices,
};
use std::collections::HashMap;
use types::{
    beacon_state::BeaconStateBase,
    consts::altair::{PARTICIPATION_FLAG_WEIGHTS, WEIGHT_DENOMINATOR},
    Attestation, BeaconState, BitList, ChainSpec, EthSpec,
};

#[derive(Debug, Clone)]
pub struct AttMaxCover<'a, E: EthSpec> {
    /// Underlying attestation.
    pub att: CompactAttestationRef<'a, E>,
    /// Mapping of validator indices and their rewards.
    pub fresh_validators_rewards: HashMap<u64, u64>,
}

impl<'a, E: EthSpec> AttMaxCover<'a, E> {
    pub fn new(
        att: CompactAttestationRef<'a, E>,
        state: &BeaconState<E>,
        reward_cache: &'a RewardCache,
        total_active_balance: u64,
        spec: &ChainSpec,
    ) -> Option<Self> {
        if let BeaconState::Base(ref base_state) = state {
            Self::new_for_base(att, state, base_state, total_active_balance, spec)
        } else {
            Self::new_for_altair_deneb(att, state, reward_cache, spec)
        }
    }

    /// Initialise an attestation cover object for base/phase0 hard fork.
    pub fn new_for_base(
        att: CompactAttestationRef<'a, E>,
        state: &BeaconState<E>,
        base_state: &BeaconStateBase<E>,
        total_active_balance: u64,
        spec: &ChainSpec,
    ) -> Option<Self> {
        let fresh_validators = earliest_attestation_validators(&att, state, base_state);
        let committee = state
            .get_beacon_committee(att.data.slot, att.data.index)
            .ok()?;
        let indices = get_attesting_indices::<E>(committee.committee, &fresh_validators).ok()?;
        let sqrt_total_active_balance = base::SqrtTotalActiveBalance::new(total_active_balance);
        let fresh_validators_rewards: HashMap<u64, u64> = indices
            .iter()
            .copied()
            .flat_map(|validator_index| {
                let effective_balance =
                    state.get_effective_balance(validator_index as usize).ok()?;
                let reward =
                    base::get_base_reward(effective_balance, sqrt_total_active_balance, spec)
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
    pub fn new_for_altair_deneb(
        att: CompactAttestationRef<'a, E>,
        state: &BeaconState<E>,
        reward_cache: &'a RewardCache,
        spec: &ChainSpec,
    ) -> Option<Self> {
        let att_data = att.attestation_data();

        let inclusion_delay = state.slot().as_u64().checked_sub(att_data.slot.as_u64())?;
        let att_participation_flags =
            get_attestation_participation_flag_indices(state, &att_data, inclusion_delay, spec)
                .ok()?;

        let fresh_validators_rewards = att
            .indexed
            .attesting_indices()
            .iter()
            .filter_map(|&index| {
                if reward_cache
                    .has_attested_in_epoch(index, att_data.target.epoch)
                    .ok()?
                {
                    return None;
                }

                let mut proposer_reward_numerator = 0;

                let base_reward = state.get_base_reward(index as usize).ok()?;

                for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                    if att_participation_flags.contains(&flag_index) {
                        proposer_reward_numerator += base_reward.checked_mul(*weight)?;
                    }
                }

                let proposer_reward = proposer_reward_numerator
                    .checked_div(WEIGHT_DENOMINATOR.checked_mul(spec.proposer_reward_quotient)?)?;

                Some((index, proposer_reward)).filter(|_| proposer_reward != 0)
            })
            .collect();

        Some(Self {
            att,
            fresh_validators_rewards,
        })
    }
}

impl<'a, E: EthSpec> MaxCover for AttMaxCover<'a, E> {
    type Object = Attestation<E>;
    type Intermediate = CompactAttestationRef<'a, E>;
    type Set = HashMap<u64, u64>;

    fn intermediate(&self) -> &CompactAttestationRef<'a, E> {
        &self.att
    }

    fn convert_to_object(att_ref: &CompactAttestationRef<'a, E>) -> Attestation<E> {
        att_ref.clone_as_attestation()
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
    ///
    /// Post-Electra this optimisation is still OK. The `self.att.data.index` will always be 0 for
    /// all Electra attestations, so when a new attestation is added to the solution, we will
    /// remove its validators from all attestations at the same slot. It may happen that the
    /// included attestation and the attestation being updated have no validators in common, in
    /// which case the `retain` will be a no-op. We could consider optimising this in future by only
    /// executing the `retain` when the `committee_bits` of the two attestations intersect.
    fn update_covering_set(
        &mut self,
        best_att: &CompactAttestationRef<'a, E>,
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
pub fn earliest_attestation_validators<E: EthSpec>(
    attestation: &CompactAttestationRef<E>,
    state: &BeaconState<E>,
    base_state: &BeaconStateBase<E>,
) -> BitList<E::MaxValidatorsPerCommittee> {
    // Bitfield of validators whose attestations are new/fresh.
    let mut new_validators = match attestation.indexed {
        CompactIndexedAttestation::Base(indexed_att) => indexed_att.aggregation_bits.clone(),
        // This code path is obsolete post altair fork, so we just return an empty bitlist here.
        CompactIndexedAttestation::Electra(_) => return BitList::with_capacity(0).unwrap(),
    };

    let state_attestations = if attestation.checkpoint.target_epoch == state.current_epoch() {
        &base_state.current_epoch_attestations
    } else if attestation.checkpoint.target_epoch == state.previous_epoch() {
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
