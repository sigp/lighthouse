use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
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
use store::consts::altair::{
    PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
    TIMELY_TARGET_FLAG_INDEX,
};
use types::consts::altair::WEIGHT_DENOMINATOR;

use types::{Epoch, EthSpec};

use eth2::types::ValidatorId;

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_attestation_rewards(
        &self,
        epoch: Epoch,
        validators: Vec<ValidatorId>,
        log: Logger,
    ) -> Result<StandardAttestationRewards, BeaconChainError> {
        debug!(log, "computing attestation rewards"; "epoch" => epoch, "validator_count" => validators.len());

        // Get state
        let spec = &self.spec;

        let state_slot = (epoch + 1).end_slot(T::EthSpec::slots_per_epoch());

        let state_root = self
            .state_root_at_slot(state_slot)?
            .ok_or(BeaconChainError::NoStateForSlot(state_slot))?;

        let mut state = self
            .get_state(&state_root, Some(state_slot))?
            .ok_or(BeaconChainError::MissingBeaconState(state_root))?;

        // Calculate ideal_rewards
        let participation_cache = ParticipationCache::new(&state, spec)?;

        let previous_epoch = state.previous_epoch();

        let mut ideal_rewards_hashmap = HashMap::new();

        for flag_index in 0..PARTICIPATION_FLAG_WEIGHTS.len() {
            let weight = get_flag_weight(flag_index)
                .map_err(|_| BeaconChainError::AttestationRewardsError)?;

            let unslashed_participating_indices = participation_cache
                .get_unslashed_participating_indices(flag_index, previous_epoch)?;

            let unslashed_participating_balance =
                unslashed_participating_indices
                    .total_balance()
                    .map_err(|_| BeaconChainError::AttestationRewardsError)?;

            let unslashed_participating_increments =
                unslashed_participating_balance.safe_div(spec.effective_balance_increment)?;

            let total_active_balance = participation_cache.current_epoch_total_active_balance();

            let active_increments =
                total_active_balance.safe_div(spec.effective_balance_increment)?;

            let base_reward_per_increment =
                BaseRewardPerIncrement::new(total_active_balance, spec)?;

            for effective_balance_eth in 0..=32 {
                let effective_balance =
                    effective_balance_eth.safe_mul(spec.effective_balance_increment)?;
                let base_reward =
                    effective_balance_eth.safe_mul(base_reward_per_increment.as_u64())?;

                let penalty = -(base_reward.safe_mul(weight)?.safe_div(WEIGHT_DENOMINATOR)? as i64);

                let reward_numerator = base_reward
                    .safe_mul(weight)?
                    .safe_mul(unslashed_participating_increments)?;

                let ideal_reward = reward_numerator
                    .safe_div(active_increments)?
                    .safe_div(WEIGHT_DENOMINATOR)?;
                if !state.is_in_inactivity_leak(previous_epoch, spec) {
                    ideal_rewards_hashmap
                        .insert((flag_index, effective_balance), (ideal_reward, penalty));
                } else {
                    ideal_rewards_hashmap.insert((flag_index, effective_balance), (0, penalty));
                }
            }
        }

        // Calculate total_rewards
        let mut total_rewards: Vec<TotalAttestationRewards> = Vec::new();

        let validators = if validators.is_empty() {
            participation_cache.eligible_validator_indices().to_vec()
        } else {
            validators
                .into_iter()
                .map(|validator| match validator {
                    ValidatorId::Index(i) => Ok(i as usize),
                    ValidatorId::PublicKey(pubkey) => state
                        .get_validator_index(&pubkey)?
                        .ok_or(BeaconChainError::ValidatorPubkeyUnknown(pubkey)),
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        for validator_index in &validators {
            let eligible = state.is_eligible_validator(previous_epoch, *validator_index)?;
            let mut head_reward = 0u64;
            let mut target_reward = 0i64;
            let mut source_reward = 0i64;

            if eligible {
                let effective_balance = state.get_effective_balance(*validator_index)?;

                for flag_index in 0..PARTICIPATION_FLAG_WEIGHTS.len() {
                    let (ideal_reward, penalty) = ideal_rewards_hashmap
                        .get(&(flag_index, effective_balance))
                        .ok_or(BeaconChainError::AttestationRewardsError)?;
                    let voted_correctly = participation_cache
                        .get_unslashed_participating_indices(flag_index, previous_epoch)
                        .map_err(|_| BeaconChainError::AttestationRewardsError)?
                        .contains(*validator_index)
                        .map_err(|_| BeaconChainError::AttestationRewardsError)?;
                    if voted_correctly {
                        if flag_index == TIMELY_HEAD_FLAG_INDEX {
                            head_reward += ideal_reward;
                        } else if flag_index == TIMELY_TARGET_FLAG_INDEX {
                            target_reward += *ideal_reward as i64;
                        } else if flag_index == TIMELY_SOURCE_FLAG_INDEX {
                            source_reward += *ideal_reward as i64;
                        }
                    } else if flag_index == TIMELY_HEAD_FLAG_INDEX {
                        head_reward = 0;
                    } else if flag_index == TIMELY_TARGET_FLAG_INDEX {
                        target_reward = *penalty;
                    } else if flag_index == TIMELY_SOURCE_FLAG_INDEX {
                        source_reward = *penalty;
                    }
                }
            }
            total_rewards.push(TotalAttestationRewards {
                validator_index: *validator_index as u64,
                head: head_reward,
                target: target_reward,
                source: source_reward,
            });
        }

        // Convert hashmap to vector
        let mut ideal_rewards: Vec<IdealAttestationRewards> = ideal_rewards_hashmap
            .iter()
            .map(
                |((flag_index, effective_balance), (ideal_reward, _penalty))| {
                    (flag_index, effective_balance, ideal_reward)
                },
            )
            .fold(
                HashMap::new(),
                |mut acc, (flag_index, &effective_balance, ideal_reward)| {
                    let entry = acc
                        .entry(effective_balance)
                        .or_insert(IdealAttestationRewards {
                            effective_balance,
                            head: 0,
                            target: 0,
                            source: 0,
                        });
                    match *flag_index {
                        TIMELY_SOURCE_FLAG_INDEX => entry.source += ideal_reward,
                        TIMELY_TARGET_FLAG_INDEX => entry.target += ideal_reward,
                        TIMELY_HEAD_FLAG_INDEX => entry.head += ideal_reward,
                        _ => {}
                    }
                    acc
                },
            )
            .into_values()
            .collect::<Vec<IdealAttestationRewards>>();
        ideal_rewards.sort_by(|a, b| a.effective_balance.cmp(&b.effective_balance));

        Ok(StandardAttestationRewards {
            ideal_rewards,
            total_rewards,
        })
    }
}
