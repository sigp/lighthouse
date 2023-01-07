use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};

use eth2::lighthouse::SyncCommitteeAttestationReward;
use state_processing::per_block_processing::altair::sync_committee::compute_sync_aggregate_rewards;
use types::{BeaconBlockRef, BeaconState, ExecPayload};
use std::collections::HashMap;

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_sync_committee_rewards<Payload: ExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &mut BeaconState<T::EthSpec>,
    ) -> Result<Vec<SyncCommitteeAttestationReward>, BeaconChainError> {
        if block.slot() != state.slot() {
            return Err(BeaconChainError::BlockRewardSlotError);
        }

        let spec = &self.spec;

        let sync_aggregate = block
            .body()
            .sync_aggregate()?;

        let sync_committee = state
            .current_sync_committee()?
            .clone();

        let sync_committee_indices = state
            .get_sync_committee_indices(&sync_committee)?;

        let (participant_reward_value, proposer_reward_per_bit) = compute_sync_aggregate_rewards(&state, spec)
            .map_err(|_| BeaconChainError::SyncCommitteeRewardsSyncError)?;

        let mut balances = sync_committee_indices
            .iter()
            .map(|i| (*i, state.balances()[*i]))
            .collect::<HashMap<usize, u64>>();

        let mut total_proposer_rewards = 0;
        let proposer_index = state.get_beacon_proposer_index(block.slot(), spec)?;
        balances.insert(proposer_index, state.balances()[proposer_index]);

        // Apply rewards to participant balances. Keep track of proposer rewards
        for (validator_index, participant_bit) in sync_committee_indices.iter().zip(sync_aggregate.sync_committee_bits.iter()) {
            let participant_balance = balances.get(validator_index);

            if participant_bit {
                if let Some(balance_value) = participant_balance {
                    balances.insert(*validator_index, balance_value + participant_reward_value);
                }
                *balances.get_mut(&proposer_index).unwrap() += proposer_reward_per_bit;
                total_proposer_rewards +=  proposer_reward_per_bit;
            } else {
                if let Some(balance_value) = participant_balance {
                    balances.insert(*validator_index, balance_value.saturating_sub(participant_reward_value));
                }
            }
        }

        if sync_committee.pubkeys.is_empty() { 
            Ok(Vec::new())
        } else {
            Ok(
                balances.iter().map(|(i, new_balance)| {
                    let reward = if *i != proposer_index {
                        *new_balance as i64 - state.balances()[*i] as i64
                    } else {
                        *new_balance as i64 - state.balances()[*i] as i64 - total_proposer_rewards as i64
                    };
                    SyncCommitteeAttestationReward {
                        validator_index: *i as u64,
                        reward
                    }
                })
                .collect()
            )
        }
    }
}
