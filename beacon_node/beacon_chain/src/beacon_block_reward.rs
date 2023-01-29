use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use operation_pool::{SplitAttestation, earliest_attestation_validators};
use safe_arith::SafeArith;
use state_processing::{
    common::{
        altair,
        base,
        get_attestation_participation_flag_indices, get_attesting_indices_from_state, get_attesting_indices
    },
    per_block_processing::{
        altair::sync_committee::compute_sync_aggregate_rewards, get_slashable_indices,
    },
};
use store::consts::altair::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR};
use types::{BeaconBlockRef, BeaconState, BeaconStateError, ExecPayload, beacon_state::BeaconStateBase};

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_beacon_block_reward<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &mut BeaconState<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {
        let sync_aggregate_reward =
            self.compute_beacon_block_sync_aggregate_reward(block, state)?;

        let proposer_slashing_reward =
            self.compute_beacon_block_proposer_slashing_reward(block, state)?;

        let attester_slashing_reward =
            self.compute_beacon_block_attester_slashing_reward(block, state)?;

        let block_proposal_reward = if let BeaconState::Base(ref base_state) = state {
            // Will need to compute for pre-altair block as well
            self.compute_beacon_block_proposal_reward_base(block, state, base_state)?
        } else {
            self.compute_beacon_block_proposal_reward_altair(block, state)?
        };

        Ok(sync_aggregate_reward
            .safe_add(proposer_slashing_reward)?
            .safe_add(attester_slashing_reward)?
            .safe_add(block_proposal_reward)?)
    }

    fn compute_beacon_block_sync_aggregate_reward<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {
        if let Ok(sync_aggregate) = block.body().sync_aggregate() {
            let (_, proposer_reward_per_bit) = compute_sync_aggregate_rewards(state, &self.spec)
                .map_err(|_| BeaconChainError::BlockRewardSyncError)?;
            Ok(sync_aggregate.sync_committee_bits.num_set_bits() as u64 * proposer_reward_per_bit)
        } else {
            Ok(0)
        }
    }

    fn compute_beacon_block_proposer_slashing_reward<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {
        let mut proposer_slashing_reward = 0;

        let proposer_slashings = block.body().proposer_slashings();

        for proposer_slashing in proposer_slashings {
            proposer_slashing_reward.safe_add_assign(
                state
                    .get_validator(proposer_slashing.proposer_index() as usize)?
                    .effective_balance
                    .safe_div(self.spec.whistleblower_reward_quotient)?,
            )?;
        }

        Ok(proposer_slashing_reward)
    }

    fn compute_beacon_block_attester_slashing_reward<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {
        let mut attester_slashing_reward = 0;

        let attester_slashings = block.body().attester_slashings();

        for attester_slashing in attester_slashings {
            for attester_index in get_slashable_indices(state, attester_slashing)? {
                attester_slashing_reward.safe_add_assign(
                    state
                        .get_validator(attester_index as usize)?
                        .effective_balance
                        .safe_div(self.spec.whistleblower_reward_quotient)?,
                )?;
            }
        }

        Ok(attester_slashing_reward)
    }


    fn compute_beacon_block_proposal_reward_base<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
        base_state: &BeaconStateBase<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {

        let total_active_balance = state.get_total_active_balance()?;
        let mut total_proposer_reward = 0;
        let spec = &self.spec;

        let split_attestations = block
            .body()
            .attestations()
            .iter()
            .map(|att| {
                let attesting_indices = get_attesting_indices_from_state(state, att)?;
                Ok(SplitAttestation::new(att.clone(), attesting_indices))
            })
            .collect::<Result<Vec<_>, BeaconChainError>>()?;
        
        for split_attestation in split_attestations {
            let att = split_attestation.as_ref();
            let fresh_validators = earliest_attestation_validators(&att, state, base_state);
            let committee = state
                .get_beacon_committee(att.data.slot, att.data.index)?;
            let indices = get_attesting_indices::<T::EthSpec>(committee.committee, &fresh_validators)?;
            
            for validator_index in indices {
                let reward = base::get_base_reward(state, validator_index as usize, total_active_balance, spec)?
                    .safe_div(spec.proposer_reward_quotient)?;

                total_proposer_reward.safe_add_assign(reward)?;
            }
        }

        Ok(total_proposer_reward)
    }

    fn compute_beacon_block_proposal_reward_altair<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &mut BeaconState<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {
        let total_active_balance = state.get_total_active_balance()?;
        let base_reward_per_increment =
            altair::BaseRewardPerIncrement::new(total_active_balance, &self.spec)?;

        let mut total_proposer_reward = 0;

        let proposer_reward_denominator = WEIGHT_DENOMINATOR
            .safe_sub(PROPOSER_WEIGHT)?
            .safe_mul(WEIGHT_DENOMINATOR)?
            .safe_div(PROPOSER_WEIGHT)?;

        for attestation in block.body().attestations() {
            let data = &attestation.data;
            let inclusion_delay = state.slot().safe_sub(data.slot)?.as_u64();
            let participation_flag_indices = get_attestation_participation_flag_indices(
                state,
                data,
                inclusion_delay,
                &self.spec,
            )?;

            let attesting_indices = get_attesting_indices_from_state(&state, attestation)?;

            let mut proposer_reward_numerator = 0;
            for index in attesting_indices {
                let index = index as usize;
                for (flag_index, &weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                    let epoch_participation =
                        state.get_epoch_participation_mut(data.target.epoch)?;
                    let validator_participation = epoch_participation
                        .get_mut(index)
                        .ok_or(BeaconStateError::ParticipationOutOfBounds(index))?;

                    if participation_flag_indices.contains(&flag_index)
                        && !validator_participation.has_flag(flag_index)?
                    {
                        proposer_reward_numerator.safe_add_assign(
                            altair::get_base_reward(state, index, base_reward_per_increment, &self.spec)?
                                .safe_mul(weight)?,
                        )?;
                    }
                }
            }
            total_proposer_reward.safe_add_assign(proposer_reward_numerator.safe_div(proposer_reward_denominator)?)?;
        }

        Ok(total_proposer_reward)
    }
}
