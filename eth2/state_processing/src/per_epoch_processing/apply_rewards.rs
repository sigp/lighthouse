use super::validator_statuses::{TotalBalances, ValidatorStatus, ValidatorStatuses};
use super::Error;
use integer_sqrt::IntegerSquareRoot;
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
/// Spec v0.8.0
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

    // Update statuses with the information from winning roots.
    validator_statuses.process_winning_roots(state, spec)?;

    get_crosslink_deltas(&mut deltas, state, &validator_statuses, spec)?;

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
/// Spec v0.8.0
fn get_proposer_deltas<T: EthSpec>(
    deltas: &mut Vec<Delta>,
    state: &BeaconState<T>,
    validator_statuses: &mut ValidatorStatuses,
    spec: &ChainSpec,
) -> Result<(), Error> {
    for (index, validator) in validator_statuses.statuses.iter().enumerate() {
        if validator.is_previous_epoch_attester {
            let inclusion = validator
                .inclusion_info
                .expect("It is a logic error for an attester not to have an inclusion distance.");

            let base_reward = get_base_reward(
                state,
                index,
                validator_statuses.total_balances.current_epoch,
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
/// Spec v0.8.0
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
            validator_statuses.total_balances.current_epoch,
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
/// Spec v0.8.0
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

    let total_balance = total_balances.current_epoch;
    let total_attesting_balance = total_balances.previous_epoch_attesters;
    let matching_target_balance = total_balances.previous_epoch_target_attesters;
    let matching_head_balance = total_balances.previous_epoch_head_attesters;

    // Expected FFG source.
    // Spec:
    // - validator index in `get_unslashed_attesting_indices(state, matching_source_attestations)`
    if validator.is_previous_epoch_attester && !validator.is_slashed {
        delta.reward(base_reward * total_attesting_balance / total_balance);
        // Inclusion speed bonus
        let proposer_reward = base_reward / spec.proposer_reward_quotient;
        let max_attester_reward = base_reward - proposer_reward;
        let inclusion = validator
            .inclusion_info
            .expect("It is a logic error for an attester not to have an inclusion distance.");
        delta.reward(
            max_attester_reward
                * (T::SlotsPerEpoch::to_u64() + spec.min_attestation_inclusion_delay
                    - inclusion.distance)
                / T::SlotsPerEpoch::to_u64(),
        );
    } else {
        delta.penalize(base_reward);
    }

    // Expected FFG target.
    // Spec:
    // - validator index in `get_unslashed_attesting_indices(state, matching_target_attestations)`
    if validator.is_previous_epoch_target_attester && !validator.is_slashed {
        delta.reward(base_reward * matching_target_balance / total_balance);
    } else {
        delta.penalize(base_reward);
    }

    // Expected head.
    // Spec:
    // - validator index in `get_unslashed_attesting_indices(state, matching_head_attestations)`
    if validator.is_previous_epoch_head_attester && !validator.is_slashed {
        delta.reward(base_reward * matching_head_balance / total_balance);
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

/// Calculate the deltas based upon the winning roots for attestations during the previous epoch.
///
/// Spec v0.8.0
fn get_crosslink_deltas<T: EthSpec>(
    deltas: &mut Vec<Delta>,
    state: &BeaconState<T>,
    validator_statuses: &ValidatorStatuses,
    spec: &ChainSpec,
) -> Result<(), Error> {
    for (index, validator) in validator_statuses.statuses.iter().enumerate() {
        let mut delta = Delta::default();

        let base_reward = get_base_reward(
            state,
            index,
            validator_statuses.total_balances.current_epoch,
            spec,
        )?;

        if let Some(ref winning_root) = validator.winning_root_info {
            delta.reward(
                base_reward * winning_root.total_attesting_balance
                    / winning_root.total_committee_balance,
            );
        } else {
            delta.penalize(base_reward);
        }

        deltas[index] += delta;
    }

    Ok(())
}

/// Returns the base reward for some validator.
///
/// Spec v0.8.0
fn get_base_reward<T: EthSpec>(
    state: &BeaconState<T>,
    index: usize,
    // Should be == get_total_active_balance(state, spec)
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, BeaconStateError> {
    if total_active_balance == 0 {
        Ok(0)
    } else {
        Ok(
            state.get_effective_balance(index, spec)? * spec.base_reward_factor
                / total_active_balance.integer_sqrt()
                / spec.base_rewards_per_epoch,
        )
    }
}
