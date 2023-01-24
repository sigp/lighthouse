use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};

use eth2::lighthouse::SyncCommitteeReward;
use safe_arith::SafeArith;
use slog::error;
use state_processing::per_block_processing::altair::sync_committee::compute_sync_aggregate_rewards;
use std::collections::HashMap;
use store::RelativeEpoch;
use types::{BeaconBlockRef, BeaconState, ExecPayload};

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_sync_committee_rewards<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &mut BeaconState<T::EthSpec>,
    ) -> Result<Vec<SyncCommitteeReward>, BeaconChainError> {
        if block.slot() != state.slot() {
            return Err(BeaconChainError::BlockRewardSlotError);
        }

        let spec = &self.spec;

        state.build_committee_cache(RelativeEpoch::Current, spec)?;

        let sync_aggregate = block.body().sync_aggregate()?;

        let sync_committee = state.current_sync_committee()?.clone();

        let sync_committee_indices = state.get_sync_committee_indices(&sync_committee)?;

        let (participant_reward_value, proposer_reward_per_bit) =
            compute_sync_aggregate_rewards(state, spec).map_err(|e| {
                error!(
                    self.log, "Error calculating sync aggregate rewards";
                    "error" => ?e
                );
                BeaconChainError::SyncCommitteeRewardsSyncError
            })?;

        let mut balances = HashMap::<usize, u64>::new();

        let mut total_proposer_rewards = 0;
        let proposer_index = state.get_beacon_proposer_index(block.slot(), spec)?;

        // Apply rewards to participant balances. Keep track of proposer rewards
        for (validator_index, participant_bit) in sync_committee_indices
            .iter()
            .zip(sync_aggregate.sync_committee_bits.iter())
        {
            let participant_balance = balances
                .entry(*validator_index)
                .or_insert_with(|| state.balances()[*validator_index]);

            if participant_bit {
                participant_balance.safe_add_assign(participant_reward_value)?;

                balances
                    .entry(proposer_index)
                    .or_insert_with(|| state.balances()[proposer_index])
                    .safe_add_assign(proposer_reward_per_bit)?;

                total_proposer_rewards.safe_add_assign(proposer_reward_per_bit)?;
            } else {
                *participant_balance = participant_balance.saturating_sub(participant_reward_value);
            }
        }

        Ok(balances
            .iter()
            .filter_map(|(i, new_balance)| {
                let reward = if *i != proposer_index {
                    *new_balance as i64 - state.balances()[*i] as i64
                } else if sync_committee_indices.contains(i) {
                    *new_balance as i64
                        - state.balances()[*i] as i64
                        - total_proposer_rewards as i64
                } else {
                    return None;
                };
                Some(SyncCommitteeReward {
                    validator_index: *i as u64,
                    reward,
                })
            })
            .collect())
    }
}
