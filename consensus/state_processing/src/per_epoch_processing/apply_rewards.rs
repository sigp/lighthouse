use super::super::common::get_base_reward;
use super::validator_statuses::{TotalBalances, ValidatorStatus, ValidatorStatuses};
use super::Error;
use safe_arith::SafeArith;

use types::*;

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
/// Spec v0.11.1
pub fn process_rewards_and_penalties<T: EthSpec>(
    state: &mut BeaconState<T>,
    validator_statuses: &mut ValidatorStatuses,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if state.current_epoch() == T::genesis_epoch() {
        return Ok(());
    }

    // Guard against an out-of-bounds during the validator balance update.
    if validator_statuses.statuses.len() != state.balances.len()
        || validator_statuses.statuses.len() != state.validators.len()
    {
        return Err(Error::ValidatorStatusesInconsistent);
    }

    let deltas = get_attestation_deltas(state, &validator_statuses, spec)?;

    // Apply the deltas, erroring on overflow above but not on overflow below (saturating at 0
    // instead).
    for (i, delta) in deltas.iter().enumerate() {
        state.balances[i] = state.balances[i].safe_add(delta.rewards)?;
        state.balances[i] = state.balances[i].saturating_sub(delta.penalties);
    }

    Ok(())
}

/// Apply rewards for participation in attestations during the previous epoch.
///
/// Spec v0.11.1
fn get_attestation_deltas<T: EthSpec>(
    state: &BeaconState<T>,
    validator_statuses: &ValidatorStatuses,
    spec: &ChainSpec,
) -> Result<Vec<Delta>, Error> {
    let finality_delay = (state.previous_epoch() - state.finalized_checkpoint.epoch).as_u64();

    let mut deltas = vec![Delta::default(); state.validators.len()];

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
/// Spec: v0.12.0
fn is_eligible_validator(validator: &ValidatorStatus) -> bool {
    validator.is_active_in_previous_epoch
        || (validator.is_slashed && !validator.is_withdrawable_in_current_epoch)
}
