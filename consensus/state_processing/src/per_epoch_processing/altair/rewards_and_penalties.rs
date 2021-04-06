use crate::common::altair::get_base_reward;
use crate::per_epoch_processing::Error;
use safe_arith::SafeArith;
use types::{BeaconState, ChainSpec, EthSpec};

//TODO: move to chainspec -- or constants file in types
pub const TIMELY_HEAD_FLAG_INDEX: u64 = 0;
pub const TIMELY_SOURCE_FLAG_INDEX: u64 = 1;
pub const TIMELY_TARGET_FLAG_INDEX: u64 = 2;
pub const TIMELY_HEAD_WEIGHT: u64 = 12;
pub const TIMELY_SOURCE_WEIGHT: u64 = 12;
pub const TIMELY_TARGET_WEIGHT: u64 = 24;
pub const SYNC_REWARD_WEIGHT: u64 = 8;
pub const WEIGHT_DENOMINATOR: u64 = 64;
pub const INACTIVITY_SCORE_BIAS: u64 = 4;
pub const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64 = u64::pow(2, 24).saturating_mul(3);

pub const FLAG_INDICES_AND_WEIGHTS: [(u64, u64); 3] = [
    (TIMELY_HEAD_FLAG_INDEX, TIMELY_HEAD_WEIGHT),
    (TIMELY_SOURCE_FLAG_INDEX, TIMELY_SOURCE_WEIGHT),
    (TIMELY_TARGET_FLAG_INDEX, TIMELY_TARGET_WEIGHT),
];

/// Use to track the changes to a validators balance.
#[derive(Default, Clone)]
pub struct Delta {
    rewards: u64,
    penalties: u64,
}

impl Delta {
    /// Reward the validator with the `reward`.
    pub fn reward(&mut self, reward: u64) -> Result<(), Error> {
        self.rewards = self.rewards.safe_add(reward)?;
        Ok(())
    }

    /// Penalize the validator with the `penalty`.
    pub fn penalize(&mut self, penalty: u64) -> Result<(), Error> {
        self.penalties = self.penalties.safe_add(penalty)?;
        Ok(())
    }

    /// Combine two deltas.
    fn combine(&mut self, other: Delta) -> Result<(), Error> {
        self.reward(other.rewards)?;
        self.penalize(other.penalties)
    }
}

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
        get_flag_index_deltas(&mut deltas, state, *index, *numerator, total_active_balance, spec)?;
    }

    get_inactivity_penalty_deltas(&mut deltas, state, total_active_balance, spec)?;

    // Apply the deltas, erroring on overflow above but not on overflow below (saturating at 0
    // instead).
    for (i, delta) in deltas.into_iter().enumerate() {
        state.balances_mut()[i] = state.balances()[i].safe_add(delta.rewards)?;
        state.balances_mut()[i] = state.balances()[i].saturating_sub(delta.penalties);
    }

    Ok(())
}

/// Return the deltas for a given flag index by scanning through the participation flags.
///
/// Spec v1.1.0
fn get_flag_index_deltas<T: EthSpec>(
    deltas: &mut Vec<Delta>,
    state: &mut BeaconState<T>,
    flag_index: u64,
    weight: u64,
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let unslashed_participating_indices =
        state.get_unslashed_participating_indices(flag_index, state.previous_epoch(), spec)?;
    let increment = spec.effective_balance_increment; //Factored out from balances to avoid uint64 overflow
    let unslashed_participating_increments = state
        .get_total_balance(unslashed_participating_indices.as_slice(), spec)?
        .safe_div(increment)?;
    let active_increments = total_active_balance.safe_div(increment)?;

    for index in state.get_eligible_validator_indices()? {
        let base_reward = get_base_reward(state, index, total_active_balance, spec)?;
        let mut delta = Delta::default();

        if unslashed_participating_indices.contains(&(index as usize)) {
            if state.is_in_inactivity_leak(spec) {
                // This flag reward cancels the inactivity penalty corresponding to the flag index
                delta.reward(base_reward.safe_mul(weight)?.safe_div(WEIGHT_DENOMINATOR)?);
            } else {
                let reward_numerator = base_reward
                    .safe_mul(weight)?
                    .safe_mul(unslashed_participating_increments)?;
                delta.reward(
                    reward_numerator.safe_div(active_increments.safe_mul(WEIGHT_DENOMINATOR)?)?,
                );
            }
        } else {
            delta.penalize(base_reward.safe_mul(weight)?.safe_div(WEIGHT_DENOMINATOR)?);
        }
        deltas[index as usize].combine(delta);
    }
    Ok(())
}

fn get_inactivity_penalty_deltas<T: EthSpec>(
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
                );
            }
            if !matching_target_indices.contains(&index) {
                let penalty_numerator = state.validators()[index]
                    .effective_balance
                    .safe_mul(state.as_altair()?.inactivity_scores[index])?;
                let penalty_denominator =
                    INACTIVITY_SCORE_BIAS.safe_mul(INACTIVITY_PENALTY_QUOTIENT_ALTAIR)?;
                delta.penalize(penalty_numerator.safe_div(penalty_denominator)?)?;
            }
            deltas[index].combine(delta);
        }
    }
    Ok(())
}

/// Return the combined effective balance of an array of validators.
///
/// Spec v1.1.0
pub fn get_total_active_balance<T: EthSpec>(
    state: &BeaconState<T>,
    spec: &ChainSpec,
) -> Result<u64, Error> {
    let total_balance = state.get_total_balance(
        state
            .get_active_validator_indices(state.current_epoch(), spec)?
            .as_slice(),
        spec,
    )?;
    //TODO: this comparator should be in `get_total_balance`
    Ok(std::cmp::max(
        spec.effective_balance_increment,
        total_balance,
    ))
}

/// Returns the base reward for some validator.
///
/// Spec v1.1.0
pub fn get_base_reward<T: EthSpec>(
    state: &BeaconState<T>,
    index: usize,
    // Should be == get_total_active_balance(state, spec)
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, Error> {
    if total_active_balance == 0 {
        Ok(0)
    } else {
        Ok(state
            .get_effective_balance(index, spec)?
            .safe_div(spec.effective_balance_increment)?
            .safe_mul(get_base_reward_per_increment(total_active_balance, spec)?)?)
    }
}

/// Returns the base reward for some validator.
///
/// Spec v1.1.0
pub fn get_base_reward_per_increment(
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, ArithError> {
    return Ok(spec
        .effective_balance_increment
        .safe_mul(spec.base_reward_factor)?
        .safe_div(total_active_balance.integer_sqrt())?);
}
