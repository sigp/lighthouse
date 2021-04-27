use crate::{common::initiate_validator_exit, per_epoch_processing::Error};
use itertools::Itertools;
use safe_arith::SafeArith;
use types::{BeaconState, ChainSpec, EthSpec, Validator};

/// Performs a validator registry update, if required.
///
/// NOTE: unchanged in Altair
pub fn process_registry_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Process activation eligibility and ejections.
    // Collect eligible and exiting validators (we need to avoid mutating the state while iterating).
    // We assume it's safe to re-order the change in eligibility and `initiate_validator_exit`.
    // Rest assured exiting validators will still be exited in the same order as in the spec.
    let current_epoch = state.current_epoch();
    let is_ejectable = |validator: &Validator| {
        validator.is_active_at(current_epoch)
            && validator.effective_balance <= spec.ejection_balance
    };
    let indices_to_update: Vec<_> = state
        .validators()
        .iter()
        .enumerate()
        .filter(|(_, validator)| {
            validator.is_eligible_for_activation_queue(spec) || is_ejectable(validator)
        })
        .map(|(idx, _)| idx)
        .collect();

    for index in indices_to_update {
        let validator = state.get_validator_mut(index)?;
        if validator.is_eligible_for_activation_queue(spec) {
            validator.activation_eligibility_epoch = current_epoch.safe_add(1)?;
        }
        if is_ejectable(validator) {
            initiate_validator_exit(state, index, spec)?;
        }
    }

    // Queue validators eligible for activation and not dequeued for activation prior to finalized epoch
    let activation_queue = state
        .validators()
        .iter()
        .enumerate()
        .filter(|(_, validator)| validator.is_eligible_for_activation(state, spec))
        .sorted_by_key(|(index, validator)| (validator.activation_eligibility_epoch, *index))
        .map(|(index, _)| index)
        .collect_vec();

    // Dequeue validators for activation up to churn limit
    let churn_limit = state.get_churn_limit(spec)? as usize;
    let delayed_activation_epoch = state.compute_activation_exit_epoch(current_epoch, spec)?;
    for index in activation_queue.into_iter().take(churn_limit) {
        state.get_validator_mut(index)?.activation_epoch = delayed_activation_epoch;
    }

    Ok(())
}
