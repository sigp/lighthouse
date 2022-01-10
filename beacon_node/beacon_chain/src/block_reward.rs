use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::{AttestationRewards, BlockReward, BlockRewardMeta};
use operation_pool::{AttMaxCover, MaxCover};
use state_processing::per_block_processing::altair::sync_committee::compute_sync_aggregate_rewards;
use types::{BeaconBlockRef, BeaconState, EthSpec, Hash256, RelativeEpoch};

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_block_reward(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec>,
        block_root: Hash256,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BlockReward, BeaconChainError> {
        if block.slot() != state.slot() {
            return Err(BeaconChainError::BlockRewardSlotError);
        }

        let active_indices = state.get_cached_active_validator_indices(RelativeEpoch::Current)?;
        let total_active_balance = state.get_total_balance(active_indices, &self.spec)?;
        let mut per_attestation_rewards = block
            .body()
            .attestations()
            .iter()
            .map(|att| {
                AttMaxCover::new(att, state, total_active_balance, &self.spec)
                    .ok_or(BeaconChainError::BlockRewardAttestationError)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Update the attestation rewards for each previous attestation included.
        // This is O(n^2) in the number of attestations n.
        for i in 0..per_attestation_rewards.len() {
            let (updated, to_update) = per_attestation_rewards.split_at_mut(i + 1);
            let latest_att = &updated[i];

            for att in to_update {
                att.update_covering_set(latest_att.object(), latest_att.covering_set());
            }
        }

        let mut prev_epoch_total = 0;
        let mut curr_epoch_total = 0;

        for cover in &per_attestation_rewards {
            for &reward in cover.fresh_validators_rewards.values() {
                if cover.att.data.slot.epoch(T::EthSpec::slots_per_epoch()) == state.current_epoch()
                {
                    curr_epoch_total += reward;
                } else {
                    prev_epoch_total += reward;
                }
            }
        }

        let attestation_total = prev_epoch_total + curr_epoch_total;

        // Drop the covers.
        let per_attestation_rewards = per_attestation_rewards
            .into_iter()
            .map(|cover| cover.fresh_validators_rewards)
            .collect();

        let attestation_rewards = AttestationRewards {
            total: attestation_total,
            prev_epoch_total,
            curr_epoch_total,
            per_attestation_rewards,
        };

        // Sync committee rewards.
        let sync_committee_rewards = if let Ok(sync_aggregate) = block.body().sync_aggregate() {
            let (_, proposer_reward_per_bit) = compute_sync_aggregate_rewards(state, &self.spec)
                .map_err(|_| BeaconChainError::BlockRewardSyncError)?;
            sync_aggregate.sync_committee_bits.num_set_bits() as u64 * proposer_reward_per_bit
        } else {
            0
        };

        // Total, metadata
        let total = attestation_total + sync_committee_rewards;

        let meta = BlockRewardMeta {
            slot: block.slot(),
            parent_slot: state.latest_block_header().slot,
            proposer_index: block.proposer_index(),
            graffiti: block.body().graffiti().as_utf8_lossy(),
        };

        Ok(BlockReward {
            total,
            block_root,
            meta,
            attestation_rewards,
            sync_committee_rewards,
        })
    }
}
