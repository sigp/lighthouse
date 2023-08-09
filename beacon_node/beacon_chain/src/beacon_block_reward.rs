use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::StandardBlockReward;
use operation_pool::RewardCache;
use safe_arith::SafeArith;
use slog::error;
use state_processing::{
    common::{
        altair, get_attestation_participation_flag_indices, get_attesting_indices_from_state,
    },
    per_block_processing::{
        altair::sync_committee::compute_sync_aggregate_rewards, get_slashable_indices,
    },
};
use store::{
    consts::altair::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    RelativeEpoch,
};
use types::{AbstractExecPayload, BeaconBlockRef, BeaconState, BeaconStateError, Hash256};

type BeaconBlockSubRewardValue = u64;

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_beacon_block_reward<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        block_root: Hash256,
        state: &mut BeaconState<T::EthSpec>,
    ) -> Result<StandardBlockReward, BeaconChainError> {
        if block.slot() != state.slot() {
            return Err(BeaconChainError::BlockRewardSlotError);
        }

        state.build_committee_cache(RelativeEpoch::Previous, &self.spec)?;
        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        let proposer_index = block.proposer_index();

        let sync_aggregate_reward =
            self.compute_beacon_block_sync_aggregate_reward(block, state)?;

        let proposer_slashing_reward = self
            .compute_beacon_block_proposer_slashing_reward(block, state)
            .map_err(|e| {
                error!(
                self.log,
                "Error calculating proposer slashing reward";
                "error" => ?e
                );
                BeaconChainError::BlockRewardError
            })?;

        let attester_slashing_reward = self
            .compute_beacon_block_attester_slashing_reward(block, state)
            .map_err(|e| {
                error!(
                self.log,
                "Error calculating attester slashing reward";
                "error" => ?e
                );
                BeaconChainError::BlockRewardError
            })?;

        let block_attestation_reward = if let BeaconState::Base(_) = state {
            self.compute_beacon_block_attestation_reward_base(block, block_root, state)
                .map_err(|e| {
                    error!(
                    self.log,
                    "Error calculating base block attestation reward";
                    "error" => ?e
                    );
                    BeaconChainError::BlockRewardAttestationError
                })?
        } else {
            self.compute_beacon_block_attestation_reward_altair(block, state)
                .map_err(|e| {
                    error!(
                    self.log,
                    "Error calculating altair block attestation reward";
                    "error" => ?e
                    );
                    BeaconChainError::BlockRewardAttestationError
                })?
        };

        let total_reward = sync_aggregate_reward
            .safe_add(proposer_slashing_reward)?
            .safe_add(attester_slashing_reward)?
            .safe_add(block_attestation_reward)?;

        Ok(StandardBlockReward {
            proposer_index,
            total: total_reward,
            attestations: block_attestation_reward,
            sync_aggregate: sync_aggregate_reward,
            proposer_slashings: proposer_slashing_reward,
            attester_slashings: attester_slashing_reward,
        })
    }

    fn compute_beacon_block_sync_aggregate_reward<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
        if let Ok(sync_aggregate) = block.body().sync_aggregate() {
            let (_, proposer_reward_per_bit) = compute_sync_aggregate_rewards(state, &self.spec)
                .map_err(|_| BeaconChainError::BlockRewardSyncError)?;
            Ok(sync_aggregate.sync_committee_bits.num_set_bits() as u64 * proposer_reward_per_bit)
        } else {
            Ok(0)
        }
    }

    fn compute_beacon_block_proposer_slashing_reward<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
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

    fn compute_beacon_block_attester_slashing_reward<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
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

    fn compute_beacon_block_attestation_reward_base<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        block_root: Hash256,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
        // Call compute_block_reward in the base case
        // Since base does not have sync aggregate, we only grab attesation portion of the returned
        // value
        let mut reward_cache = RewardCache::default();
        let block_attestation_reward = self
            .compute_block_reward(block, block_root, state, &mut reward_cache, true)?
            .attestation_rewards
            .total;

        Ok(block_attestation_reward)
    }

    fn compute_beacon_block_attestation_reward_altair<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &mut BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
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

            let attesting_indices = get_attesting_indices_from_state(state, attestation)?;

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
                        validator_participation.add_flag(flag_index)?;
                        proposer_reward_numerator.safe_add_assign(
                            altair::get_base_reward(
                                state,
                                index,
                                base_reward_per_increment,
                                &self.spec,
                            )?
                            .safe_mul(weight)?,
                        )?;
                    }
                }
            }
            total_proposer_reward.safe_add_assign(
                proposer_reward_numerator.safe_div(proposer_reward_denominator)?,
            )?;
        }

        Ok(total_proposer_reward)
    }
}
