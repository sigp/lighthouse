use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::lighthouse::attestation_rewards::{IdealAttestationRewards, TotalAttestationRewards};
use eth2::lighthouse::StandardAttestationRewards;
use participation_cache::ParticipationCache;
use safe_arith::SafeArith;
use slog::{debug, Logger};
use state_processing::{
    common::altair::BaseRewardPerIncrement,
    per_epoch_processing::altair::{participation_cache, rewards_and_penalties::get_flag_weight},
};
use std::collections::HashMap;
use store::consts::altair::PARTICIPATION_FLAG_WEIGHTS;
use types::consts::altair::WEIGHT_DENOMINATOR;

use types::{Epoch, EthSpec};

use crate::{beacon_chain, BeaconChainError};

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_attestation_rewards(
        &self,
        epoch: Epoch,
        mut validators: Vec<usize>,
        log: Logger,
    ) -> Result<StandardAttestationRewards, BeaconChainError> {
        debug!(log, "computing attestation rewards"; "epoch" => epoch, "validator_count" => validators.len());

        //--- Get state ---//
        let spec = &self.spec;

        let _execution_optimistic = self.is_optimistic_or_invalid_head()?;

        let state_slot = (epoch + 1).end_slot(T::EthSpec::slots_per_epoch());

        let state_root = self.state_root_at_slot(state_slot)?;

        let state = self.get_state(&state_root.unwrap(), Some(state_slot))?;

        //--- Calculate ideal_rewards ---//
        let participation_cache = ParticipationCache::new(state.as_ref().unwrap(), spec)?;

        let previous_epoch = state.as_ref().unwrap().previous_epoch();

        let mut ideal_rewards_hashmap = HashMap::new();

        let total_rewards = Vec::new();

        for flag_index in PARTICIPATION_FLAG_WEIGHTS {
            let weight = get_flag_weight(flag_index.try_into().unwrap()).unwrap_or_default();

            let unslashed_participating_indices = participation_cache
                .get_unslashed_participating_indices(
                    flag_index.try_into().unwrap(),
                    previous_epoch,
                )?;

            let unslashed_participating_balance =
                unslashed_participating_indices.total_balance().unwrap();

            let unslashed_participating_increments =
                unslashed_participating_balance.safe_div(spec.effective_balance_increment)?;

            let total_active_balance = participation_cache.current_epoch_total_active_balance();

            let active_increments =
                total_active_balance.safe_div(spec.effective_balance_increment)?;

            let base_reward_per_increment =
                BaseRewardPerIncrement::new(total_active_balance, spec)?;

            for effective_balance_eth in 0..=32 {
                let base_reward =
                    effective_balance_eth.safe_mul(base_reward_per_increment.as_u64())?;

                let reward_numerator = base_reward
                    .safe_mul(weight)
                    .and_then(|reward_numerator| {
                        reward_numerator.safe_mul(unslashed_participating_increments)
                    })
                    .unwrap();

                let ideal_reward = reward_numerator
                    .safe_div(active_increments)
                    .and_then(|ideal_reward| ideal_reward.safe_div(WEIGHT_DENOMINATOR))?;
                match state {
                    Some(ref state) => {
                        if !state.is_in_inactivity_leak(previous_epoch, spec) {
                            ideal_rewards_hashmap
                                .insert((flag_index, effective_balance_eth), ideal_reward);
                        } else {
                            ideal_rewards_hashmap.insert((flag_index, effective_balance_eth), 0);
                        }
                    }
                    None => return Err(BeaconChainError::AttestationRewardsSyncError),
                }
                //--- Calculate total rewards ---//
                let mut total_rewards = Vec::new();

                if validators.is_empty() {
                    validators = participation_cache.eligible_validator_indices().to_vec();
                }

                for validator_index in &validators {
                    let eligible = state
                        .as_ref()
                        .expect("State variable is None")
                        .is_eligible_validator(previous_epoch, *validator_index)?;

                    let effective_balance = state
                        .as_ref()
                        .expect("State variable is None")
                        .get_effective_balance(*validator_index)
                        .unwrap();

                    let effective_balance_eth =
                        effective_balance.safe_div(spec.effective_balance_increment)?;

                    let mut head_reward = 0u64;
                    let mut target_reward = 0i64;
                    let mut source_reward = 0i64;

                    for flag_index in PARTICIPATION_FLAG_WEIGHTS {
                        if eligible {
                            let voted_correctly = participation_cache
                                .get_unslashed_participating_indices(
                                    flag_index.try_into().unwrap(),
                                    previous_epoch,
                                )
                                .is_ok();
                            if voted_correctly {
                                let reward = *ideal_rewards_hashmap
                                    .get(&(flag_index, effective_balance_eth))
                                    .unwrap_or(&0)
                                    as u64;

                                if flag_index == 0 {
                                    head_reward += reward;
                                } else if flag_index == 1 {
                                    target_reward += reward as i64;
                                } else if flag_index == 2 {
                                    source_reward += reward as i64;
                                }
                            } else {
                                let penalty = if flag_index == 1 || flag_index == 2 {
                                    !0 * base_reward
                                        .safe_mul(weight)?
                                        .safe_div(WEIGHT_DENOMINATOR)?
                                        as i64
                                } else {
                                    0
                                };
                                if flag_index == 1 {
                                    target_reward = penalty;
                                } else if flag_index == 0 {
                                    source_reward = penalty;
                                }
                            }
                        }
                    }
                    total_rewards.push(TotalAttestationRewards {
                        validator_index: *validator_index as u64,
                        head: head_reward as i64,
                        target: target_reward,
                        source: source_reward,
                    });
                }
            }
        }

        let ideal_rewards: Vec<IdealAttestationRewards> = ideal_rewards_hashmap
            .iter()
            .fold(
                HashMap::new(),
                |mut acc, ((flag_index, effective_balance_eth), ideal_reward)| {
                    let entry = acc.entry(*effective_balance_eth as u32).or_insert(
                        IdealAttestationRewards {
                            effective_balance: *effective_balance_eth,
                            head: 0,
                            target: 0,
                            source: 0,
                        },
                    );
                    match flag_index {
                        0 => entry.source += *ideal_reward,
                        1 => entry.target += *ideal_reward,
                        2 => entry.head += *ideal_reward,
                        _ => {}
                    }
                    acc
                },
            )
            .into_values()
            .collect();

        Ok(StandardAttestationRewards {
            ideal_rewards,
            total_rewards,
        })
    }
}
