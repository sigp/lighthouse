use crate::per_epoch_processing::validator_statuses::{
    TotalBalances, ValidatorStatus, ValidatorStatuses,
};
use crate::per_epoch_processing::Error;
use safe_arith::SafeArith;
use types::{BeaconState, ChainSpec, EthSpec, Epoch};
use criterion::SamplingMode::Flat;
use integer_sqrt::IntegerSquareRoot;

//TODO: move to chainspec
const TIMELY_HEAD_FLAG_INDEX: u64 = 0;
const TIMELY_SOURCE_FLAG_INDEX: u64 = 1;
const TIMELY_TARGET_FLAG_INDEX: u64 = 2;
const TIMELY_HEAD_WEIGHT: u64 = 12;
const TIMELY_SOURCE_WEIGHT: u64 = 12;
const TIMELY_TARGET_WEIGHT: u64 = 24;
const SYNC_REWARD_WEIGHT: u64 = 8;
const WEIGHT_DENOMINATOR: u64 = 64;

const FLAG_INDICES_AND_WEIGHTS: [(u64, u64);3]= [(TIMELY_HEAD_FLAG_INDEX, TIMELY_HEAD_WEIGHT), (TIMELY_SOURCE_FLAG_INDEX, TIMELY_SOURCE_WEIGHT), (TIMELY_TARGET_FLAG_INDEX, TIMELY_TARGET_WEIGHT),];

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

    let deltas = FLAG_INDICES_AND_WEIGHTS.iter().map(|(index, numerator)| {
        get_flag_index_deltas(state, *index, *numerator, spec);
    }).collect();

    flag_indices_and_numerators = get_flag_indices_and_weights()
    flag_deltas = [get_flag_index_deltas(state, index, numerator) for (index, numerator) in flag_indices_and_numerators]
    deltas = flag_deltas + [get_inactivity_penalty_deltas(state)]
    for (rewards, penalties) in deltas:
    for index in range(len(state.validators)):
        increase_balance(state, ValidatorIndex(index), rewards[index])
    decrease_balance(state, ValidatorIndex(index), penalties[index])





    // def get_flag_index_deltas(state: BeaconState, flag_index: int, weight: uint64) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    // """
    // Return the deltas for a given flag index by scanning through the participation flags.
    // """
    // rewards = [Gwei(0)] * len(state.validators)
    // penalties = [Gwei(0)] * len(state.validators)
    // unslashed_participating_indices = get_unslashed_participating_indices(state, flag_index, get_previous_epoch(state))
    // increment = EFFECTIVE_BALANCE_INCREMENT  # Factored out from balances to avoid uint64 overflow
    // unslashed_participating_increments = get_total_balance(state, unslashed_participating_indices) // increment
    // active_increments = get_total_active_balance(state) // increment
    // for index in get_eligible_validator_indices(state):
    //     base_reward = get_base_reward(state, index)
    // if index in unslashed_participating_indices:
    // if is_in_inactivity_leak(state):
    // # This flag reward cancels the inactivity penalty corresponding to the flag index
    // rewards[index] += Gwei(base_reward * weight // WEIGHT_DENOMINATOR)
    // else:
    // reward_numerator = base_reward * weight * unslashed_participating_increments
    // rewards[index] += Gwei(reward_numerator // (active_increments * WEIGHT_DENOMINATOR))
    // else:
    // penalties[index] += Gwei(base_reward * weight // WEIGHT_DENOMINATOR)
    // return rewards, penalties


    // Guard against an out-of-bounds during the validator balance update.
    if validator_statuses.statuses.len() != state.balances().len()
        || validator_statuses.statuses.len() != state.validators().len()
    {
        return Err(Error::ValidatorStatusesInconsistent);
    }

    let deltas = get_attestation_deltas(state, &validator_statuses, spec)?;

    // Apply the deltas, erroring on overflow above but not on overflow below (saturating at 0
    // instead).
    for (i, delta) in deltas.iter().enumerate() {
        state.balances_mut()[i] = state.balances()[i].safe_add(delta.rewards)?;
        state.balances_mut()[i] = state.balances()[i].saturating_sub(delta.penalties);
    }

    Ok(())
}

fn get_eligible_validator_indices<T: EthSpec>(state: &mut BeaconState<T>) -> Vec<u64>{
    let previous_epoch = state.previous_epoch();
    state.validators().iter().enumerate().filter(|(i, val)|{
        val.is_active_at(previous_epoch) || (val.is_slashed() && previous_epoch + Epoch::new(1) < val.withdrawable_epoch)
    }).collect()
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
pub fn get_base_reward_per_increment<T: EthSpec>(
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, Error> {
    return Ok(spec.effective_balance_increment.safe_mul(spec.base_reward_factor)
        .safe_div(total_active_balance.integer_sqrt())?)
}


/// Return the deltas for a given flag index by scanning through the participation flags.
///
/// Spec v1.1.0
fn get_flag_index_deltas<T: EthSpec>(
    state: &mut BeaconState<T>,
    flag_index: u64,
    weight: u64,
    spec: &ChainSpec,
) -> Result<Vec<Delta>, Error> {

    let mut deltas = vec![Delta::default(); state.validators().len()];

let  unslashed_participating_indices = state.get_unslashed_participating_indices( flag_index, state.previous_epoch(), spec)?;
let increment = spec.effective_balance_increment;  //Factored out from balances to avoid uint64 overflow
let  unslashed_participating_increments = state.get_total_balance(unslashed_participating_indices.as_slice(), spec)?; // increment
let  active_increments =    state.get_total_balance(state.get_active_validator_indices(current_epoch, spec)?.as_slice(), spec)?; // increment
    Ok(get_eligible_validator_indices(state).into_iter().map(|index| {
        let base_reward = get_base_reward()?;
        if unslashed_participating_increments.contains(&index) {
            if is_in_inactivity_leak(state, spec) {

            }

        }
    }).collect())
// for index in get_eligible_validator_indices(state):
//     base_reward = get_base_reward(state, index)
// if index in unslashed_participating_indices:
// if is_in_inactivity_leak(state):
// # This flag reward cancels the inactivity penalty corresponding to the flag index
// rewards[index] += Gwei(base_reward * weight // WEIGHT_DENOMINATOR)
// else:
// reward_numerator = base_reward * weight * unslashed_participating_increments
// rewards[index] += Gwei(reward_numerator // (active_increments * WEIGHT_DENOMINATOR))
// else:
// penalties[index] += Gwei(base_reward * weight // WEIGHT_DENOMINATOR)
// return rewards, penalties


}

fn is_in_inactivity_leak(state: &BeaconState<T>,spec: &ChainSpec) -> bool {
    (state.previous_epoch() - state.finalized_checkpoint().epoch()) > spec.min_epochs_to_inactivity_penalty
}

/// Apply rewards for participation in attestations during the previous epoch.
///
/// Spec v0.12.1
fn get_attestation_deltas<T: EthSpec>(
    state: &BeaconState<T>,
    validator_statuses: &ValidatorStatuses,
    spec: &ChainSpec,
) -> Result<Vec<Delta>, Error> {
    let finality_delay = state
        .previous_epoch()
        .safe_sub(state.finalized_checkpoint().epoch)?
        .as_u64();

    let mut deltas = vec![Delta::default(); state.validators().len()];

    let total_balances = &validator_statuses.total_balances;

    // Filter out ineligible validators. All sub-functions of the spec do this except for
    // `get_inclusion_delay_deltas`. It's safe to do so here because any validator that is in the
    // unslashed indices of the matching source attestations is active, and therefore eligible.
    for (index, validator) in validator_statuses
        .statuses
        .iter()
        .enumerate()
        .filter(|(_, validator)| is_eligible_validator(validator))
    {
        let base_reward = get_base_reward(state, index, total_balances.current_epoch(), spec)?;

        let source_delta =
            get_source_delta(validator, base_reward, total_balances, finality_delay, spec)?;
        let target_delta =
            get_target_delta(validator, base_reward, total_balances, finality_delay, spec)?;
        let head_delta =
            get_head_delta(validator, base_reward, total_balances, finality_delay, spec)?;
        let (inclusion_delay_delta, proposer_delta) =
            get_inclusion_delay_delta(validator, base_reward, spec)?;
        let inactivity_penalty_delta =
            get_inactivity_penalty_delta(validator, base_reward, finality_delay, spec)?;

        deltas[index].combine(source_delta)?;
        deltas[index].combine(target_delta)?;
        deltas[index].combine(head_delta)?;
        deltas[index].combine(inclusion_delay_delta)?;
        deltas[index].combine(inactivity_penalty_delta)?;

        if let Some((proposer_index, proposer_delta)) = proposer_delta {
            if proposer_index >= deltas.len() {
                return Err(Error::ValidatorStatusesInconsistent);
            }

            deltas[proposer_index].combine(proposer_delta)?;
        }
    }

    Ok(deltas)
}

fn get_attestation_component_delta(
    index_in_unslashed_attesting_indices: bool,
    attesting_balance: u64,
    total_balances: &TotalBalances,
    base_reward: u64,
    finality_delay: u64,
    spec: &ChainSpec,
) -> Result<Delta, Error> {
    let mut delta = Delta::default();

    let total_balance = total_balances.current_epoch();

    if index_in_unslashed_attesting_indices {
        if finality_delay > spec.min_epochs_to_inactivity_penalty {
            // Since full base reward will be canceled out by inactivity penalty deltas,
            // optimal participation receives full base reward compensation here.
            delta.reward(base_reward)?;
        } else {
            let reward_numerator = base_reward
                .safe_mul(attesting_balance.safe_div(spec.effective_balance_increment)?)?;
            delta.reward(
                reward_numerator
                    .safe_div(total_balance.safe_div(spec.effective_balance_increment)?)?,
            )?;
        }
    } else {
        delta.penalize(base_reward)?;
    }

    Ok(delta)
}

fn get_source_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    total_balances: &TotalBalances,
    finality_delay: u64,
    spec: &ChainSpec,
) -> Result<Delta, Error> {
    get_attestation_component_delta(
        validator.is_previous_epoch_attester && !validator.is_slashed,
        total_balances.previous_epoch_attesters(),
        total_balances,
        base_reward,
        finality_delay,
        spec,
    )
}

fn get_target_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    total_balances: &TotalBalances,
    finality_delay: u64,
    spec: &ChainSpec,
) -> Result<Delta, Error> {
    get_attestation_component_delta(
        validator.is_previous_epoch_target_attester && !validator.is_slashed,
        total_balances.previous_epoch_target_attesters(),
        total_balances,
        base_reward,
        finality_delay,
        spec,
    )
}

fn get_head_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    total_balances: &TotalBalances,
    finality_delay: u64,
    spec: &ChainSpec,
) -> Result<Delta, Error> {
    get_attestation_component_delta(
        validator.is_previous_epoch_head_attester && !validator.is_slashed,
        total_balances.previous_epoch_head_attesters(),
        total_balances,
        base_reward,
        finality_delay,
        spec,
    )
}

fn get_inclusion_delay_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    spec: &ChainSpec,
) -> Result<(Delta, Option<(usize, Delta)>), Error> {
    // Spec: `index in get_unslashed_attesting_indices(state, matching_source_attestations)`
    if validator.is_previous_epoch_attester && !validator.is_slashed {
        let mut delta = Delta::default();
        let mut proposer_delta = Delta::default();

        let inclusion_info = validator
            .inclusion_info
            .ok_or(Error::ValidatorStatusesInconsistent)?;

        let proposer_reward = get_proposer_reward(base_reward, spec)?;
        proposer_delta.reward(proposer_reward)?;

        let max_attester_reward = base_reward.safe_sub(proposer_reward)?;
        delta.reward(max_attester_reward.safe_div(inclusion_info.delay)?)?;

        let proposer_index = inclusion_info.proposer_index as usize;
        Ok((delta, Some((proposer_index, proposer_delta))))
    } else {
        Ok((Delta::default(), None))
    }
}


// def get_inactivity_penalty_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
// """
// Return the inactivity penalty deltas by considering timely target participation flags and inactivity scores.
// """
// rewards = [Gwei(0) for _ in range(len(state.validators))]
// penalties = [Gwei(0) for _ in range(len(state.validators))]
// if is_in_inactivity_leak(state):
//     previous_epoch = get_previous_epoch(state)
// matching_target_indices = get_unslashed_participating_indices(state, TIMELY_TARGET_FLAG_INDEX, previous_epoch)
// for index in get_eligible_validator_indices(state):
// for (_, weight) in get_flag_indices_and_weights():
// # This inactivity penalty cancels the flag reward corresponding to the flag index
// penalties[index] += Gwei(get_base_reward(state, index) * weight // WEIGHT_DENOMINATOR)
// if index not in matching_target_indices:
//     penalty_numerator = state.validators[index].effective_balance * state.inactivity_scores[index]
// penalty_denominator = INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_ALTAIR
// penalties[index] += Gwei(penalty_numerator // penalty_denominator)
// return rewards, penalties


fn get_inactivity_penalty_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    finality_delay: u64,
    spec: &ChainSpec,
) -> Result<Delta, Error> {
    let mut delta = Delta::default();

    // Inactivity penalty
    if finality_delay > spec.min_epochs_to_inactivity_penalty {
        // If validator is performing optimally this cancels all rewards for a neutral balance
        delta.penalize(
            spec.base_rewards_per_epoch
                .safe_mul(base_reward)?
                .safe_sub(get_proposer_reward(base_reward, spec)?)?,
        )?;

        // Additionally, all validators whose FFG target didn't match are penalized extra
        // This condition is equivalent to this condition from the spec:
        // `index not in get_unslashed_attesting_indices(state, matching_target_attestations)`
        if validator.is_slashed || !validator.is_previous_epoch_target_attester {
            delta.penalize(
                validator
                    .current_epoch_effective_balance
                    .safe_mul(finality_delay)?
                    .safe_div(spec.inactivity_penalty_quotient)?,
            )?;
        }
    }

    Ok(delta)
}

/// Compute the reward awarded to a proposer for including an attestation from a validator.
///
/// The `base_reward` param should be the `base_reward` of the attesting validator.
fn get_proposer_reward(base_reward: u64, spec: &ChainSpec) -> Result<u64, Error> {
    Ok(base_reward.safe_div(spec.proposer_reward_quotient)?)
}

/// Is the validator eligible for penalties and rewards at the current epoch?
///
/// Spec: v0.12.1
fn is_eligible_validator(validator: &ValidatorStatus) -> bool {
    validator.is_active_in_previous_epoch
        || (validator.is_slashed && !validator.is_withdrawable_in_current_epoch)
}
