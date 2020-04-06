use super::super::common::get_base_reward;
use super::validator_statuses::{TotalBalances, ValidatorStatus, ValidatorStatuses};
use super::Error;

use types::*;

/// Use to track the changes to a validators balance.
#[derive(Default, Clone)]
pub struct Delta {
    rewards: u64,
    penalties: u64,
}

impl Delta {
    /// Reward the validator with the `reward`.
    pub fn reward(&mut self, reward: u64) {
        self.rewards += reward;
    }

    /// Penalize the validator with the `penalty`.
    pub fn penalize(&mut self, penalty: u64) {
        self.penalties += penalty;
    }
}

impl std::ops::AddAssign for Delta {
    /// Use wrapping addition as that is how it's defined in the spec.
    fn add_assign(&mut self, other: Delta) {
        self.rewards += other.rewards;
        self.penalties += other.penalties;
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

    let mut deltas = vec![Delta::default(); state.balances.len()];

    get_attestation_deltas(&mut deltas, state, &validator_statuses, spec)?;

    get_proposer_deltas(&mut deltas, state, validator_statuses, spec)?;

    // Apply the deltas, over-flowing but not under-flowing (saturating at 0 instead).
    for (i, delta) in deltas.iter().enumerate() {
        state.balances[i] += delta.rewards;
        state.balances[i] = state.balances[i].saturating_sub(delta.penalties);
    }

    Ok(())
}

/// For each attesting validator, reward the proposer who was first to include their attestation.
///
/// Spec v0.11.1
fn get_proposer_deltas<T: EthSpec>(
    deltas: &mut Vec<Delta>,
    state: &BeaconState<T>,
    validator_statuses: &mut ValidatorStatuses,
    spec: &ChainSpec,
) -> Result<(), Error> {
    for (index, validator) in validator_statuses.statuses.iter().enumerate() {
        if validator.is_previous_epoch_attester && !validator.is_slashed {
            let inclusion = validator
                .inclusion_info
                .expect("It is a logic error for an attester not to have an inclusion delay.");

            let base_reward = get_base_reward(
                state,
                index,
                validator_statuses.total_balances.current_epoch(),
                spec,
            )?;

            if inclusion.proposer_index >= deltas.len() {
                return Err(Error::ValidatorStatusesInconsistent);
            }

            deltas[inclusion.proposer_index].reward(base_reward / spec.proposer_reward_quotient);
        }
    }

    Ok(())
}

/// Apply rewards for participation in attestations during the previous epoch.
///
/// Spec v0.11.1
fn get_attestation_deltas<T: EthSpec>(
    deltas: &mut Vec<Delta>,
    state: &BeaconState<T>,
    validator_statuses: &ValidatorStatuses,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let finality_delay = (state.previous_epoch() - state.finalized_checkpoint.epoch).as_u64();

    for (index, validator) in validator_statuses.statuses.iter().enumerate() {
        let base_reward = get_base_reward(
            state,
            index,
            validator_statuses.total_balances.current_epoch(),
            spec,
        )?;

        let delta = get_attestation_delta::<T>(
            &validator,
            &validator_statuses.total_balances,
            base_reward,
            finality_delay,
            spec,
        );

        deltas[index] += delta;
    }

    Ok(())
}

/// Determine the delta for a single validator, sans proposer rewards.
///
/// Spec v0.11.1
fn get_attestation_delta<T: EthSpec>(
    validator: &ValidatorStatus,
    total_balances: &TotalBalances,
    base_reward: u64,
    finality_delay: u64,
    spec: &ChainSpec,
) -> Delta {
    let mut delta = Delta::default();

    // Is this validator eligible to be rewarded or penalized?
    // Spec: validator index in `eligible_validator_indices`
    let is_eligible = validator.is_active_in_previous_epoch
        || (validator.is_slashed && !validator.is_withdrawable_in_current_epoch);

    if !is_eligible {
        return delta;
    }

    // Handle integer overflow by dividing these quantities by EFFECTIVE_BALANCE_INCREMENT
    // Spec:
    // - increment = EFFECTIVE_BALANCE_INCREMENT
    // - reward_numerator = get_base_reward(state, index) * (attesting_balance // increment)
    // - rewards[index] = reward_numerator // (total_balance // increment)
    let total_balance_ebi = total_balances.current_epoch() / spec.effective_balance_increment;
    let total_attesting_balance_ebi =
        total_balances.previous_epoch_attesters() / spec.effective_balance_increment;
    let matching_target_balance_ebi =
        total_balances.previous_epoch_target_attesters() / spec.effective_balance_increment;
    let matching_head_balance_ebi =
        total_balances.previous_epoch_head_attesters() / spec.effective_balance_increment;

    // Expected FFG source.
    // Spec:
    // - validator index in `get_unslashed_attesting_indices(state, matching_source_attestations)`
    if validator.is_previous_epoch_attester && !validator.is_slashed {
        delta.reward(base_reward * total_attesting_balance_ebi / total_balance_ebi);
        // Inclusion speed bonus
        let proposer_reward = base_reward / spec.proposer_reward_quotient;
        let max_attester_reward = base_reward - proposer_reward;
        let inclusion = validator
            .inclusion_info
            .expect("It is a logic error for an attester not to have an inclusion delay.");
        delta.reward(max_attester_reward / inclusion.delay);
    } else {
        delta.penalize(base_reward);
    }

    // Expected FFG target.
    // Spec:
    // - validator index in `get_unslashed_attesting_indices(state, matching_target_attestations)`
    if validator.is_previous_epoch_target_attester && !validator.is_slashed {
        delta.reward(base_reward * matching_target_balance_ebi / total_balance_ebi);
    } else {
        delta.penalize(base_reward);
    }

    // Expected head.
    // Spec:
    // - validator index in `get_unslashed_attesting_indices(state, matching_head_attestations)`
    if validator.is_previous_epoch_head_attester && !validator.is_slashed {
        delta.reward(base_reward * matching_head_balance_ebi / total_balance_ebi);
    } else {
        delta.penalize(base_reward);
    }

    // Inactivity penalty
    if finality_delay > spec.min_epochs_to_inactivity_penalty {
        // All eligible validators are penalized
        delta.penalize(spec.base_rewards_per_epoch * base_reward);

        // Additionally, all validators whose FFG target didn't match are penalized extra
        if !validator.is_previous_epoch_target_attester {
            delta.penalize(
                validator.current_epoch_effective_balance * finality_delay
                    / spec.inactivity_penalty_quotient,
            );
        }
    }

    // Proposer bonus is handled in `get_proposer_deltas`.
    //
    // This function only computes the delta for a single validator, so it cannot also return a
    // delta for a validator.

    delta
}
