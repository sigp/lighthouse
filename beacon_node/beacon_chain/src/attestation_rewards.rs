use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::attestation_rewards::{IdealAttestationRewards, TotalAttestationRewards};
use eth2::lighthouse::StandardAttestationRewards;
use participation_cache::ParticipationCache;
use safe_arith::SafeArith;
use serde_utils::quoted_u64::Quoted;
use slog::debug;
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

use types::{BeaconState, Epoch, EthSpec};

use eth2::types::ValidatorId;
use state_processing::common::base::get_base_reward_from_effective_balance;
use state_processing::per_epoch_processing::base::rewards_and_penalties::{
    get_attestation_component_delta, get_attestation_deltas_all, get_attestation_deltas_subset,
    get_inactivity_penalty_delta, get_inclusion_delay_delta,
};
use state_processing::per_epoch_processing::base::validator_statuses::InclusionInfo;
use state_processing::per_epoch_processing::base::{
    TotalBalances, ValidatorStatus, ValidatorStatuses,
};

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_attestation_rewards(
        &self,
        epoch: Epoch,
        validators: Vec<ValidatorId>,
    ) -> Result<StandardAttestationRewards, BeaconChainError> {
        debug!(self.log, "computing attestation rewards"; "epoch" => epoch, "validator_count" => validators.len());

        // Get state
        let state_slot = (epoch + 1).end_slot(T::EthSpec::slots_per_epoch());

        let state_root = self
            .state_root_at_slot(state_slot)?
            .ok_or(BeaconChainError::NoStateForSlot(state_slot))?;

        let state = self
            .get_state(&state_root, Some(state_slot))?
            .ok_or(BeaconChainError::MissingBeaconState(state_root))?;

        match state {
            BeaconState::Base(_) => self.compute_attestation_rewards_base(state, validators),
            BeaconState::Altair(_) | BeaconState::Merge(_) | BeaconState::Capella(_) => {
                self.compute_attestation_rewards_altair(state, validators)
            }
        }
    }

    fn compute_attestation_rewards_base(
        &self,
        mut state: BeaconState<T::EthSpec>,
        validators: Vec<ValidatorId>,
    ) -> Result<StandardAttestationRewards, BeaconChainError> {
        let spec = &self.spec;
        let mut validator_statuses = ValidatorStatuses::new(&state, spec)?;
        validator_statuses.process_attestations(&state)?;

        let ideal_rewards =
            self.compute_ideal_rewards_base(&state, &validator_statuses.total_balances)?;

        let indices_to_attestation_delta = if validators.is_empty() {
            get_attestation_deltas_all(&state, &validator_statuses, spec)?
                .into_iter()
                .enumerate()
                .collect()
        } else {
            let validator_indices = Self::validators_ids_to_indices(&mut state, validators)?;
            get_attestation_deltas_subset(&state, &validator_statuses, &validator_indices, spec)?
        };

        let mut total_rewards = vec![];

        for (index, delta) in indices_to_attestation_delta.into_iter() {
            let head_delta = delta.head_delta;
            let head = (head_delta.rewards as i64).safe_sub(head_delta.penalties as i64)?;

            let target_delta = delta.target_delta;
            let target = (target_delta.rewards as i64).safe_sub(target_delta.penalties as i64)?;

            let source_delta = delta.source_delta;
            let source = (source_delta.rewards as i64).safe_sub(source_delta.penalties as i64)?;

            // No penalties associated with inclusion delay
            let inclusion_delay = delta.inclusion_delay_delta.rewards;
            let inactivity = delta.inactivity_penalty_delta.penalties.wrapping_neg() as i64;

            let rewards = TotalAttestationRewards {
                validator_index: index as u64,
                head,
                target,
                source,
                inclusion_delay: Some(Quoted {
                    value: inclusion_delay,
                }),
                inactivity,
            };

            total_rewards.push(rewards);
        }

        Ok(StandardAttestationRewards {
            ideal_rewards,
            total_rewards,
        })
    }

    fn compute_attestation_rewards_altair(
        &self,
        mut state: BeaconState<T::EthSpec>,
        validators: Vec<ValidatorId>,
    ) -> Result<StandardAttestationRewards, BeaconChainError> {
        let spec = &self.spec;

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

            for effective_balance_eth in 1..=self.max_effective_balance_increment_steps()? {
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
                if !state.is_in_inactivity_leak(previous_epoch, spec)? {
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
            Self::validators_ids_to_indices(&mut state, validators)?
        };

        for validator_index in &validators {
            let eligible = state.is_eligible_validator(previous_epoch, *validator_index)?;
            let mut head_reward = 0i64;
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
                            head_reward += *ideal_reward as i64;
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
                inclusion_delay: None,
                // TODO: altair calculation logic needs to be updated to include inactivity penalty
                inactivity: 0,
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
                            inclusion_delay: None,
                            // TODO: altair calculation logic needs to be updated to include inactivity penalty
                            inactivity: 0,
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

    fn max_effective_balance_increment_steps(&self) -> Result<u64, BeaconChainError> {
        let spec = &self.spec;
        let max_steps = spec
            .max_effective_balance
            .safe_div(spec.effective_balance_increment)?;
        Ok(max_steps)
    }

    fn validators_ids_to_indices(
        state: &mut BeaconState<T::EthSpec>,
        validators: Vec<ValidatorId>,
    ) -> Result<Vec<usize>, BeaconChainError> {
        let indices = validators
            .into_iter()
            .map(|validator| match validator {
                ValidatorId::Index(i) => Ok(i as usize),
                ValidatorId::PublicKey(pubkey) => state
                    .get_validator_index(&pubkey)?
                    .ok_or(BeaconChainError::ValidatorPubkeyUnknown(pubkey)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(indices)
    }

    fn compute_ideal_rewards_base(
        &self,
        state: &BeaconState<T::EthSpec>,
        total_balances: &TotalBalances,
    ) -> Result<Vec<IdealAttestationRewards>, BeaconChainError> {
        let spec = &self.spec;
        let previous_epoch = state.previous_epoch();
        let finality_delay = previous_epoch
            .safe_sub(state.finalized_checkpoint().epoch)?
            .as_u64();

        let ideal_validator_status = ValidatorStatus {
            is_previous_epoch_attester: true,
            is_slashed: false,
            inclusion_info: Some(InclusionInfo {
                delay: 1,
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut ideal_attestation_rewards_list = Vec::new();

        for effective_balance_step in 1..=self.max_effective_balance_increment_steps()? {
            let effective_balance =
                effective_balance_step.safe_mul(spec.effective_balance_increment)?;
            let base_reward = get_base_reward_from_effective_balance::<T::EthSpec>(
                effective_balance,
                total_balances.current_epoch(),
                spec,
            )?;

            // compute ideal head rewards
            let head = get_attestation_component_delta(
                true,
                total_balances.previous_epoch_head_attesters(),
                total_balances,
                base_reward,
                finality_delay,
                spec,
            )?
            .rewards;

            // compute ideal target rewards
            let target = get_attestation_component_delta(
                true,
                total_balances.previous_epoch_target_attesters(),
                total_balances,
                base_reward,
                finality_delay,
                spec,
            )?
            .rewards;

            // compute ideal source rewards
            let source = get_attestation_component_delta(
                true,
                total_balances.previous_epoch_attesters(),
                total_balances,
                base_reward,
                finality_delay,
                spec,
            )?
            .rewards;

            // compute ideal inclusion delay rewards
            let inclusion_delay =
                get_inclusion_delay_delta(&ideal_validator_status, base_reward, spec)?
                    .0
                    .rewards;

            // compute inactivity penalty
            let inactivity = get_inactivity_penalty_delta(
                &ideal_validator_status,
                base_reward,
                finality_delay,
                spec,
            )?
            .penalties
            .wrapping_neg() as i64;

            let ideal_attestation_rewards = IdealAttestationRewards {
                effective_balance,
                head,
                target,
                source,
                inclusion_delay: Some(Quoted {
                    value: inclusion_delay,
                }),
                inactivity,
            };

            ideal_attestation_rewards_list.push(ideal_attestation_rewards);
        }

        Ok(ideal_attestation_rewards_list)
    }
}
