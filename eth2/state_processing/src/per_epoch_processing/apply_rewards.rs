use super::validator_statuses::{TotalBalances, ValidatorStatus, ValidatorStatuses};
use super::{Error, WinningRootHashSet};
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
/// Spec v0.5.1
pub fn apply_rewards(
    state: &mut BeaconState,
    validator_statuses: &mut ValidatorStatuses,
    winning_root_for_shards: &WinningRootHashSet,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Guard against an out-of-bounds during the validator balance update.
    if validator_statuses.statuses.len() != state.validator_balances.len() {
        return Err(Error::ValidatorStatusesInconsistent);
    }
    // Guard against an out-of-bounds during the attester inclusion balance update.
    if validator_statuses.statuses.len() != state.validator_registry.len() {
        return Err(Error::ValidatorStatusesInconsistent);
    }

    let mut deltas = vec![Delta::default(); state.validator_balances.len()];

    get_justification_and_finalization_deltas(&mut deltas, state, &validator_statuses, spec)?;
    get_crosslink_deltas(&mut deltas, state, &validator_statuses, spec)?;

    // Apply the proposer deltas if we are finalizing normally.
    //
    // This is executed slightly differently to the spec because of the way our functions are
    // structured. It should be functionally equivalent.
    if epochs_since_finality(state, spec) <= 4 {
        get_proposer_deltas(
            &mut deltas,
            state,
            validator_statuses,
            winning_root_for_shards,
            spec,
        )?;
    }

    // Apply the deltas, over-flowing but not under-flowing (saturating at 0 instead).
    for (i, delta) in deltas.iter().enumerate() {
        state.validator_balances[i] += delta.rewards;
        state.validator_balances[i] = state.validator_balances[i].saturating_sub(delta.penalties);
    }

    Ok(())
}

/// Applies the attestation inclusion reward to each proposer for every validator who included an
/// attestation in the previous epoch.
///
/// Spec v0.5.1
fn get_proposer_deltas(
    deltas: &mut Vec<Delta>,
    state: &mut BeaconState,
    validator_statuses: &mut ValidatorStatuses,
    winning_root_for_shards: &WinningRootHashSet,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Update statuses with the information from winning roots.
    validator_statuses.process_winning_roots(state, winning_root_for_shards, spec)?;

    for (index, validator) in validator_statuses.statuses.iter().enumerate() {
        let mut delta = Delta::default();

        if validator.is_previous_epoch_attester {
            let inclusion = validator
                .inclusion_info
                .expect("It is a logic error for an attester not to have an inclusion distance.");

            let base_reward = get_base_reward(
                state,
                inclusion.proposer_index,
                validator_statuses.total_balances.previous_epoch,
                spec,
            )?;

            if inclusion.proposer_index >= deltas.len() {
                return Err(Error::ValidatorStatusesInconsistent);
            }

            delta.reward(base_reward / spec.attestation_inclusion_reward_quotient);
        }

        deltas[index] += delta;
    }

    Ok(())
}

/// Apply rewards for participation in attestations during the previous epoch.
///
/// Spec v0.5.1
fn get_justification_and_finalization_deltas(
    deltas: &mut Vec<Delta>,
    state: &BeaconState,
    validator_statuses: &ValidatorStatuses,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let epochs_since_finality = epochs_since_finality(state, spec);

    for (index, validator) in validator_statuses.statuses.iter().enumerate() {
        let base_reward = get_base_reward(
            state,
            index,
            validator_statuses.total_balances.previous_epoch,
            spec,
        )?;
        let inactivity_penalty = get_inactivity_penalty(
            state,
            index,
            epochs_since_finality.as_u64(),
            validator_statuses.total_balances.previous_epoch,
            spec,
        )?;

        let delta = if epochs_since_finality <= 4 {
            compute_normal_justification_and_finalization_delta(
                &validator,
                &validator_statuses.total_balances,
                base_reward,
                spec,
            )
        } else {
            compute_inactivity_leak_delta(&validator, base_reward, inactivity_penalty, spec)
        };

        deltas[index] += delta;
    }

    Ok(())
}

/// Determine the delta for a single validator, if the chain is finalizing normally.
///
/// Spec v0.5.1
fn compute_normal_justification_and_finalization_delta(
    validator: &ValidatorStatus,
    total_balances: &TotalBalances,
    base_reward: u64,
    spec: &ChainSpec,
) -> Delta {
    let mut delta = Delta::default();

    let boundary_attesting_balance = total_balances.previous_epoch_boundary_attesters;
    let total_balance = total_balances.previous_epoch;
    let total_attesting_balance = total_balances.previous_epoch_attesters;
    let matching_head_balance = total_balances.previous_epoch_boundary_attesters;

    // Expected FFG source.
    if validator.is_previous_epoch_attester {
        delta.reward(base_reward * total_attesting_balance / total_balance);
        // Inclusion speed bonus
        let inclusion = validator
            .inclusion_info
            .expect("It is a logic error for an attester not to have an inclusion distance.");
        delta.reward(
            base_reward * spec.min_attestation_inclusion_delay / inclusion.distance.as_u64(),
        );
    } else if validator.is_active_in_previous_epoch {
        delta.penalize(base_reward);
    }

    // Expected FFG target.
    if validator.is_previous_epoch_boundary_attester {
        delta.reward(base_reward / boundary_attesting_balance / total_balance);
    } else if validator.is_active_in_previous_epoch {
        delta.penalize(base_reward);
    }

    // Expected head.
    if validator.is_previous_epoch_head_attester {
        delta.reward(base_reward * matching_head_balance / total_balance);
    } else if validator.is_active_in_previous_epoch {
        delta.penalize(base_reward);
    };

    // Proposer bonus is handled in `apply_proposer_deltas`.
    //
    // This function only computes the delta for a single validator, so it cannot also return a
    // delta for a validator.

    delta
}

/// Determine the delta for a single delta, assuming the chain is _not_ finalizing normally.
///
/// Spec v0.5.1
fn compute_inactivity_leak_delta(
    validator: &ValidatorStatus,
    base_reward: u64,
    inactivity_penalty: u64,
    spec: &ChainSpec,
) -> Delta {
    let mut delta = Delta::default();

    if validator.is_active_in_previous_epoch {
        if !validator.is_previous_epoch_attester {
            delta.penalize(inactivity_penalty);
        } else {
            // If a validator did attest, apply a small penalty for getting attestations included
            // late.
            let inclusion = validator
                .inclusion_info
                .expect("It is a logic error for an attester not to have an inclusion distance.");
            delta.reward(
                base_reward * spec.min_attestation_inclusion_delay / inclusion.distance.as_u64(),
            );
            delta.penalize(base_reward);
        }

        if !validator.is_previous_epoch_boundary_attester {
            delta.reward(inactivity_penalty);
        }

        if !validator.is_previous_epoch_head_attester {
            delta.penalize(inactivity_penalty);
        }
    }

    // Penalize slashed-but-inactive validators as though they were active but offline.
    if !validator.is_active_in_previous_epoch
        & validator.is_slashed
        & !validator.is_withdrawable_in_current_epoch
    {
        delta.penalize(2 * inactivity_penalty + base_reward);
    }

    delta
}

/// Calculate the deltas based upon the winning roots for attestations during the previous epoch.
///
/// Spec v0.5.1
fn get_crosslink_deltas(
    deltas: &mut Vec<Delta>,
    state: &BeaconState,
    validator_statuses: &ValidatorStatuses,
    spec: &ChainSpec,
) -> Result<(), Error> {
    for (index, validator) in validator_statuses.statuses.iter().enumerate() {
        let mut delta = Delta::default();

        let base_reward = get_base_reward(
            state,
            index,
            validator_statuses.total_balances.previous_epoch,
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
/// Spec v0.5.1
fn get_base_reward(
    state: &BeaconState,
    index: usize,
    previous_total_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, BeaconStateError> {
    if previous_total_balance == 0 {
        Ok(0)
    } else {
        let adjusted_quotient = previous_total_balance.integer_sqrt() / spec.base_reward_quotient;
        Ok(state.get_effective_balance(index, spec)? / adjusted_quotient / 5)
    }
}

/// Returns the inactivity penalty for some validator.
///
/// Spec v0.5.1
fn get_inactivity_penalty(
    state: &BeaconState,
    index: usize,
    epochs_since_finality: u64,
    previous_total_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, BeaconStateError> {
    Ok(get_base_reward(state, index, previous_total_balance, spec)?
        + state.get_effective_balance(index, spec)? * epochs_since_finality
            / spec.inactivity_penalty_quotient
            / 2)
}

/// Returns the epochs since the last finalized epoch.
///
/// Spec v0.5.1
fn epochs_since_finality(state: &BeaconState, spec: &ChainSpec) -> Epoch {
    state.current_epoch(spec) + 1 - state.finalized_epoch
}
