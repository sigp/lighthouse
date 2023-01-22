use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::{AttestationRewards, BlockReward, BlockRewardMeta};
use operation_pool::{AttMaxCover, MaxCover, RewardCache, SplitAttestation};
use safe_arith::SafeArith;
use ssz::Encode;
use state_processing::{
    common::{altair, base, get_attesting_indices_from_state},
    per_block_processing::{
        altair::sync_committee::compute_sync_aggregate_rewards, get_slashable_indices,
    },
};
use store::consts::altair::{PARTICIPATION_FLAG_WEIGHTS, WEIGHT_DENOMINATOR};
use types::{BeaconBlockRef, BeaconState, EthSpec, ExecPayload, Hash256};

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_beacon_block_reward<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        pre_state: &BeaconState<T::EthSpec>,
        post_state: &BeaconState<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {
        let sync_aggregate_reward =
            self.compute_beacon_block_sync_aggregate_reward(block, post_state)?;

        let proposer_slashing_reward =
            self.compute_beacon_block_proposer_slashing_reward(block, post_state)?;

        let attester_slashing_reward =
            self.compute_beacon_block_attester_slashing_reward(block, post_state)?;

        let block_proposal_reward = if let BeaconState::Base(ref base_state) = post_state {
            // Will need to compute for pre-altair block as well
            0
        } else {
            self.compute_beacon_block_proposal_reward_altair(block, pre_state, post_state)?
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

    fn compute_beacon_block_proposal_reward_altair<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        pre_state: &BeaconState<T::EthSpec>,
        post_state: &BeaconState<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {
        let pre_state_epoch_participation = pre_state.current_epoch_participation()?;
        let post_state_epoch_participation = post_state.current_epoch_participation()?;
        let total_active_balance = post_state.get_total_active_balance()?;
        let base_reward_per_increment =
            altair::BaseRewardPerIncrement::new(total_active_balance, &self.spec)?;
        let mut epoch_participation = vec![];

        // Calculate the change in epoch participation to obtain the most accurate participation
        // num_set_bits
        // Assert pre_state_epoch_participation.len = post_state_participation.len
        for i in 0..pre_state_epoch_participation.len() {
            let pre_state_participation_flags = pre_state_epoch_participation[i].as_ssz_bytes();
            let post_state_participation_flags = post_state_epoch_participation[i].as_ssz_bytes();
            let mut participation_flags = vec![];

            for j in 0..pre_state_participation_flags.len() {
                let pre_bit = pre_state_participation_flags[j];
                let post_bit = post_state_participation_flags[j];

                if pre_bit != post_bit {
                    participation_flags.push(post_bit);
                } else {
                    participation_flags.push(0);
                }
            }

            epoch_participation.push(participation_flags);
        }

        Ok(epoch_participation
            .iter()
            .enumerate()
            .filter_map(|(validator_index, participation_flags)| {
                let mut proposer_reward_numerator: u64 = 0;
                let base_reward = altair::get_base_reward(
                    post_state,
                    validator_index,
                    base_reward_per_increment,
                    &self.spec,
                )
                .ok()?;

                for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                    if participation_flags[flag_index] == 1 {
                        proposer_reward_numerator += base_reward.checked_mul(*weight)?;
                    }
                }
                Some(proposer_reward_numerator.checked_div(
                    WEIGHT_DENOMINATOR.checked_mul(self.spec.proposer_reward_quotient)?,
                )?)
            })
            .sum())
    }
}
