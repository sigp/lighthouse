use super::ParticipationCache;
use crate::per_epoch_processing::{
    single_pass::{process_epoch_single_pass, SinglePassConfig},
    Delta, Error,
};
use safe_arith::SafeArith;
use types::consts::altair::{
    PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
    WEIGHT_DENOMINATOR,
};
use types::{BeaconState, ChainSpec, EthSpec};

/// Apply attester and proposer rewards.
///
/// This function should only be used for testing.
pub fn process_rewards_and_penalties_slow<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    process_epoch_single_pass(
        state,
        spec,
        SinglePassConfig {
            rewards_and_penalties: true,
            ..SinglePassConfig::disable_all()
        },
    )
}

/// Return the deltas for a given flag index by scanning through the participation flags.
///
/// Spec v1.1.0
pub fn get_flag_index_deltas<T: EthSpec>(
    deltas: &mut [Delta],
    state: &BeaconState<T>,
    flag_index: usize,
    total_active_balance: u64,
    participation_cache: &ParticipationCache,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let weight = get_flag_weight(flag_index)?;
    let unslashed_participating_balance =
        participation_cache.previous_epoch_flag_attesting_balance(flag_index)?;
    let unslashed_participating_increments =
        unslashed_participating_balance.safe_div(spec.effective_balance_increment)?;
    let active_increments = total_active_balance.safe_div(spec.effective_balance_increment)?;
    let previous_epoch = state.previous_epoch();

    for &index in participation_cache.eligible_validator_indices() {
        let validator = participation_cache.get_validator(index)?;
        let base_reward = validator.base_reward;

        let mut delta = Delta::default();

        if validator.is_unslashed_participating_index(flag_index)? {
            if !state.is_in_inactivity_leak(previous_epoch, spec) {
                let reward_numerator = base_reward
                    .safe_mul(weight)?
                    .safe_mul(unslashed_participating_increments)?;
                delta.reward(
                    reward_numerator.safe_div(active_increments.safe_mul(WEIGHT_DENOMINATOR)?)?,
                )?;
            }
        } else if flag_index != TIMELY_HEAD_FLAG_INDEX {
            delta.penalize(base_reward.safe_mul(weight)?.safe_div(WEIGHT_DENOMINATOR)?)?;
        }
        deltas
            .get_mut(index)
            .ok_or(Error::DeltaOutOfBounds(index))?
            .combine(delta)?;
    }
    Ok(())
}

/// Get the weight for a `flag_index` from the constant list of all weights.
pub fn get_flag_weight(flag_index: usize) -> Result<u64, Error> {
    PARTICIPATION_FLAG_WEIGHTS
        .get(flag_index)
        .copied()
        .ok_or(Error::InvalidFlagIndex(flag_index))
}

pub fn get_inactivity_penalty_deltas<T: EthSpec>(
    deltas: &mut [Delta],
    state: &BeaconState<T>,
    participation_cache: &ParticipationCache,
    spec: &ChainSpec,
) -> Result<(), Error> {
    for &index in participation_cache.eligible_validator_indices() {
        let validator = participation_cache.get_validator(index)?;
        let mut delta = Delta::default();

        if !validator.is_unslashed_participating_index(TIMELY_TARGET_FLAG_INDEX)? {
            let penalty_numerator = validator
                .effective_balance
                .safe_mul(state.get_inactivity_score(index)?)?;
            let penalty_denominator = spec
                .inactivity_score_bias
                .safe_mul(spec.inactivity_penalty_quotient_for_state(state))?;
            delta.penalize(penalty_numerator.safe_div(penalty_denominator)?)?;
        }
        deltas
            .get_mut(index)
            .ok_or(Error::DeltaOutOfBounds(index))?
            .combine(delta)?;
    }
    Ok(())
}
