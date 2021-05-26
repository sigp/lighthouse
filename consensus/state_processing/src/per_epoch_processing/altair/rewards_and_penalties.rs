use safe_arith::SafeArith;
use types::consts::altair::{
    FLAG_INDICES_AND_WEIGHTS, TIMELY_TARGET_FLAG_INDEX, WEIGHT_DENOMINATOR,
};
use types::{BeaconState, ChainSpec, EthSpec};

use crate::common::{altair::get_base_reward, decrease_balance, increase_balance};
use crate::per_epoch_processing::{Delta, Error};

/// Apply attester and proposer rewards.
///
/// Spec v1.1.0
pub fn process_rewards_and_penalties<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if state.current_epoch() == T::genesis_epoch() {
        return Ok(());
    }

    let mut deltas = vec![Delta::default(); state.validators().len()];

    let total_active_balance = state.get_total_active_balance(spec)?;

    for (index, numerator) in FLAG_INDICES_AND_WEIGHTS.iter() {
        get_flag_index_deltas(
            &mut deltas,
            state,
            *index,
            *numerator,
            total_active_balance,
            spec,
        )?;
    }

    get_inactivity_penalty_deltas(&mut deltas, state, total_active_balance, spec)?;

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
    flag_index: u32,
    weight: u64,
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let unslashed_participating_indices =
        state.get_unslashed_participating_indices(flag_index, state.previous_epoch(), spec)?;
    let increment = spec.effective_balance_increment; //Factored out from balances to avoid uint64 overflow
    let unslashed_participating_increments = state
        .get_total_balance(&unslashed_participating_indices, spec)?
        .safe_div(increment)?;
    let active_increments = total_active_balance.safe_div(increment)?;

    for index in state.get_eligible_validator_indices()? {
        let base_reward = get_base_reward(state, index, total_active_balance, spec)?;
        let mut delta = Delta::default();

        if unslashed_participating_indices.contains(&(index as usize)) {
            if state.is_in_inactivity_leak(spec) {
                // This flag reward cancels the inactivity penalty corresponding to the flag index
                delta.reward(base_reward.safe_mul(weight)?.safe_div(WEIGHT_DENOMINATOR)?)?;
            } else {
                let reward_numerator = base_reward
                    .safe_mul(weight)?
                    .safe_mul(unslashed_participating_increments)?;
                delta.reward(
                    reward_numerator.safe_div(active_increments.safe_mul(WEIGHT_DENOMINATOR)?)?,
                )?;
            }
        } else {
            delta.penalize(base_reward.safe_mul(weight)?.safe_div(WEIGHT_DENOMINATOR)?)?;
        }
        deltas
            .get_mut(index as usize)
            .ok_or(Error::DeltaOutOfBounds(index as usize))?
            .combine(delta)?;
    }
    Ok(())
}

pub fn get_inactivity_penalty_deltas<T: EthSpec>(
    deltas: &mut Vec<Delta>,
    state: &BeaconState<T>,
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if state.is_in_inactivity_leak(spec) {
        let previous_epoch = state.previous_epoch();
        let matching_target_indices = state.get_unslashed_participating_indices(
            TIMELY_TARGET_FLAG_INDEX,
            previous_epoch,
            spec,
        )?;
        for index in state.get_eligible_validator_indices()? {
            let mut delta = Delta::default();

            for (_, weight) in FLAG_INDICES_AND_WEIGHTS.iter() {
                delta.penalize(
                    get_base_reward(state, index, total_active_balance, spec)?
                        .safe_mul(*weight)?
                        .safe_div(WEIGHT_DENOMINATOR)?,
                )?;
            }
            if !matching_target_indices.contains(&index) {
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
    }
    Ok(())
}
