use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::{AttestationRewards, BlockReward};
use operation_pool::{AttMaxCover, MaxCover};
use std::collections::HashMap;
use types::{BeaconBlockRef, BeaconState, EthSpec, Hash256, RelativeEpoch};

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_block_reward(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec>,
        block_root: Hash256,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BlockReward, BeaconChainError> {
        // FIXME(sproul): proper error
        assert_eq!(
            block.slot(),
            state.slot(),
            "state should be advanced to block slot"
        );

        let active_indices = state.get_cached_active_validator_indices(RelativeEpoch::Current)?;
        let total_active_balance = state.get_total_balance(active_indices, &self.spec)?;
        let mut per_attestation_rewards = block
            .body()
            .attestations()
            .iter()
            .map(|att| {
                // FIXME(sproul): handle error
                AttMaxCover::new(att, state, total_active_balance, &self.spec)
                    .expect("can construct max cover")
            })
            .collect::<Vec<_>>();

        // Update the attestation rewards for each previous attestation included.
        // This is O(n^2) in the number of attestations n.
        for i in 0..per_attestation_rewards.len() {
            let (updated, to_update) = per_attestation_rewards.split_at_mut(i + 1);
            let latest_att = &updated[i];

            for att in to_update {
                att.update_covering_set(latest_att.object(), latest_att.covering_set());
            }
        }

        let mut prev_epoch_rewards = HashMap::new();
        let mut curr_epoch_rewards = HashMap::new();

        for cover in &per_attestation_rewards {
            for (&validator_index, &reward) in &cover.fresh_validators_rewards {
                if reward != 0 {
                    if cover.att.data.slot.epoch(T::EthSpec::slots_per_epoch())
                        == state.current_epoch()
                    {
                        assert!(curr_epoch_rewards.insert(validator_index, reward).is_none());
                    } else {
                        assert!(prev_epoch_rewards.insert(validator_index, reward).is_none());
                    }
                }
            }
        }

        let prev_epoch_total = prev_epoch_rewards.values().sum::<u64>();
        let curr_epoch_total = curr_epoch_rewards.values().sum::<u64>();
        let total = prev_epoch_total + curr_epoch_total;

        // Drop the covers.
        let per_attestation_rewards = per_attestation_rewards
            .into_iter()
            .map(|cover| cover.fresh_validators_rewards)
            .collect();

        let attestation_rewards = AttestationRewards {
            total,
            prev_epoch_total,
            curr_epoch_total,
            prev_epoch_rewards,
            curr_epoch_rewards,
            per_attestation_rewards,
        };

        Ok(BlockReward {
            block_root,
            attestation_rewards,
        })
    }
}
