use crate::common::exit_validator;
use types::{BeaconStateError as Error, *};

/// Update validator registry, activating/exiting validators if possible.
///
/// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
///
/// Spec v0.4.0
pub fn update_validator_registry(state: &mut BeaconState, spec: &ChainSpec) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);
    let active_validator_indices = state.get_active_validator_indices(current_epoch, spec)?;
    let total_balance = state.get_total_balance(&active_validator_indices[..], spec)?;

    let max_balance_churn = std::cmp::max(
        spec.max_deposit_amount,
        total_balance / (2 * spec.max_balance_churn_quotient),
    );

    let mut balance_churn = 0;
    for index in 0..state.validator_registry.len() {
        let validator = &state.validator_registry[index];

        if (validator.activation_epoch == spec.far_future_epoch)
            & (state.validator_balances[index] == spec.max_deposit_amount)
        {
            balance_churn += state.get_effective_balance(index, spec)?;
            if balance_churn > max_balance_churn {
                break;
            }
            state.activate_validator(index, false, spec);
        }
    }

    let mut balance_churn = 0;
    for index in 0..state.validator_registry.len() {
        let validator = &state.validator_registry[index];

        if (validator.exit_epoch == spec.far_future_epoch) & (validator.initiated_exit) {
            balance_churn += state.get_effective_balance(index, spec)?;
            if balance_churn > max_balance_churn {
                break;
            }

            exit_validator(state, index, spec)?;
        }
    }

    state.validator_registry_update_epoch = current_epoch;

    Ok(())
}
