use super::ParticipationCache;
use safe_arith::SafeArith;
use types::consts::altair::{
    PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
    WEIGHT_DENOMINATOR,
};
use types::{BeaconState, ChainSpec, EthSpec};

use crate::common::{altair::get_base_reward, decrease_balance, increase_balance};
use crate::per_epoch_processing::{Delta, Error};

/// Apply attester and proposer rewards.
///
/// Spec v1.1.0
pub fn process_rewards_and_penalties<T: EthSpec>(
    state: &mut BeaconState<T>,
    participation_cache: &ParticipationCache,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if state.current_epoch() == T::genesis_epoch() {
        return Ok(());
    }

    let mut deltas = vec![Delta::default(); state.validators().len()];

    let total_active_balance = participation_cache.current_epoch_total_active_balance();

    for flag_index in 0..PARTICIPATION_FLAG_WEIGHTS.len() {
        get_flag_index_deltas(
            &mut deltas,
            state,
            flag_index,
            total_active_balance,
            participation_cache,
            spec,
        )?;
    }

    get_inactivity_penalty_deltas(&mut deltas, state, participation_cache, spec)?;

    // Apply the deltas, erroring on overflow above but not on overflow below (saturating at 0
    // instead).
    for (i, delta) in deltas.into_iter().enumerate() {
        increase_balance(state, i, delta.rewards)?;
        decrease_balance(state, i, delta.penalties)?;
    }

    Ok(())
}

/// Return the deltas for a given flag index by scanning through the participation flags.
///
/// Spec v1.1.0
pub fn get_flag_index_deltas<T: EthSpec>(
    deltas: &mut Vec<Delta>,
    state: &BeaconState<T>,
    flag_index: usize,
    total_active_balance: u64,
    participation_cache: &ParticipationCache,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let previous_epoch = state.previous_epoch();
    let unslashed_participating_indices =
        participation_cache.get_unslashed_participating_indices(flag_index, previous_epoch)?;
    let weight = get_flag_weight(flag_index)?;
    let unslashed_participating_balance = unslashed_participating_indices.total_balance()?;
    let unslashed_participating_increments =
        unslashed_participating_balance.safe_div(spec.effective_balance_increment)?;
    let active_increments = total_active_balance.safe_div(spec.effective_balance_increment)?;

    for &index in participation_cache.eligible_validator_indices() {
        let base_reward = get_base_reward(state, index, total_active_balance, spec)?;
        let mut delta = Delta::default();

        if unslashed_participating_indices.contains(index as usize)? {
            if !state.is_in_inactivity_leak(spec) {
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
            .get_mut(index as usize)
            .ok_or(Error::DeltaOutOfBounds(index as usize))?
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
    deltas: &mut Vec<Delta>,
    state: &BeaconState<T>,
    participation_cache: &ParticipationCache,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let previous_epoch = state.previous_epoch();
    let matching_target_indices = participation_cache
        .get_unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, previous_epoch)?;
    for &index in participation_cache.eligible_validator_indices() {
        let mut delta = Delta::default();

        if !matching_target_indices.contains(index)? {
            let penalty_numerator = state
                .get_validator(index)?
                .effective_balance
                .safe_mul(state.get_inactivity_score(index)?)?;
            let penalty_denominator = spec
                .inactivity_score_bias
                .safe_mul(spec.inactivity_penalty_quotient_altair)?;
            delta.penalize(penalty_numerator.safe_div(penalty_denominator)?)?;
        }
        deltas
            .get_mut(index)
            .ok_or(Error::DeltaOutOfBounds(index))?
            .combine(delta)?;
    }
    Ok(())
}
