use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::{AttestationRewards, BlockReward, BlockRewardMeta};
use operation_pool::{AttMaxCover, MaxCover, RewardCache, SplitAttestation};
use safe_arith::SafeArith;
use state_processing::{
    common::get_attesting_indices_from_state,
    per_block_processing::{
        altair::sync_committee::compute_sync_aggregate_rewards, get_slashable_indices,
    },
};
use types::{BeaconBlockRef, BeaconState, EthSpec, ExecPayload, Hash256};

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_beacon_block_reward<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BlockReward, BeaconChainError> {
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
        let proposer_slashing_reward = 0;

        let proposer_slashings = block.body().proposer_slashings();

        for proposer_slashing in proposer_slashings {
            proposer_slashing_reward.safe_add_assign(
                state
                    .get_validator(proposer_slashing.proposer_index() as usize)?
                    .effective_balance
                    .safe_div(self.spec.whistleblower_reward_quotient)?,
            );
        }

        Ok(proposer_slashing_reward)
    }

    fn compute_beacon_block_attester_slashing_reward<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {
        let attester_slashing_reward = 0;

        let attester_slashings = block.body().attester_slashings();

        for attester_slashing in attester_slashings {
            for attester_index in get_slashable_indices(state, attester_slashing)? {
                attester_slashing_reward.safe_add_assign(
                    state
                        .get_validator(attester_index as usize)?
                        .effective_balance
                        .safe_div(self.spec.whistleblower_reward_quotient)?,
                );
            }
        }

        Ok(attester_slashing_reward)
    }
}
