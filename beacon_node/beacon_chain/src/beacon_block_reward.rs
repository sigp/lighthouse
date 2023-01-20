use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::{AttestationRewards, BlockReward, BlockRewardMeta};
use operation_pool::{AttMaxCover, MaxCover, RewardCache, SplitAttestation};
use state_processing::{
    common::get_attesting_indices_from_state,
    per_block_processing::altair::sync_committee::compute_sync_aggregate_rewards,
};
use types::{BeaconBlockRef, BeaconState, EthSpec, ExecPayload, Hash256};

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_beacon_block_reward<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BlockReward, BeaconChainError> {




    }

    fn compute_sync_aggregate_reward<Payload: ExecPayload<T::EthSpec>> (
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

    fn compute_proposer_slashing_reward<Payload: ExecPayload<T::EthSpec>> (
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<u64, BeaconChainError> {

        //TODO: need to take care using safe_add and safe_div
        block
            .body()
            .proposer_slashings()
            .iter()
            .map(|proposer_slashing| {
                state.get_validator(proposer_slashing.proposer_index).effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT
            })
            .sum()

    }
}
