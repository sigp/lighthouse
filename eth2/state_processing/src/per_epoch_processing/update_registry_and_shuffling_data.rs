use super::super::common::exit_validator;
use super::Error;
use types::*;

/// Peforms a validator registry update, if required.
///
/// Spec v0.5.1
pub fn update_registry_and_shuffling_data(
    state: &mut BeaconState,
    current_total_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // First set previous shuffling data to current shuffling data.
    state.previous_shuffling_epoch = state.current_shuffling_epoch;
    state.previous_shuffling_start_shard = state.previous_shuffling_start_shard;
    state.previous_shuffling_seed = state.previous_shuffling_seed;

    let current_epoch = state.current_epoch(spec);
    let next_epoch = current_epoch + 1;

    // Check we should update, and if so, update.
    if should_update_validator_registry(state, spec)? {
        update_validator_registry(state, current_total_balance, spec)?;

        // If we update the registry, update the shuffling data and shards as well.
        state.current_shuffling_epoch = next_epoch;
        state.current_shuffling_start_shard = {
            let active_validators =
                state.get_cached_active_validator_indices(RelativeEpoch::Current, spec)?;
            let epoch_committee_count = spec.get_epoch_committee_count(active_validators.len());

            (state.current_shuffling_start_shard + epoch_committee_count) % spec.shard_count
        };
        state.current_shuffling_seed = state.generate_seed(state.current_shuffling_epoch, spec)?;
    } else {
        // If processing at least on crosslink keeps failing, the reshuffle every power of two, but
        // don't update the current_shuffling_start_shard.
        let epochs_since_last_update = current_epoch - state.validator_registry_update_epoch;

        if epochs_since_last_update > 1 && epochs_since_last_update.is_power_of_two() {
            state.current_shuffling_epoch = next_epoch;
            state.current_shuffling_seed =
                state.generate_seed(state.current_shuffling_epoch, spec)?;
        }
    }

    Ok(())
}

/// Returns `true` if the validator registry should be updated during an epoch processing.
///
/// Spec v0.5.1
pub fn should_update_validator_registry(
    state: &BeaconState,
    spec: &ChainSpec,
) -> Result<bool, BeaconStateError> {
    if state.finalized_epoch <= state.validator_registry_update_epoch {
        return Ok(false);
    }

    let num_active_validators = state
        .get_cached_active_validator_indices(RelativeEpoch::Current, spec)?
        .len();
    let current_epoch_committee_count = spec.get_epoch_committee_count(num_active_validators);

    for shard in (0..current_epoch_committee_count)
        .map(|i| (state.current_shuffling_start_shard + i as u64) % spec.shard_count)
    {
        if state.latest_crosslinks[shard as usize].epoch <= state.validator_registry_update_epoch {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Update validator registry, activating/exiting validators if possible.
///
/// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
///
/// Spec v0.5.1
pub fn update_validator_registry(
    state: &mut BeaconState,
    current_total_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);

    let max_balance_churn = std::cmp::max(
        spec.max_deposit_amount,
        current_total_balance / (2 * spec.max_balance_churn_quotient),
    );

    // Activate validators within the allowable balance churn.
    let mut balance_churn = 0;
    for index in 0..state.validator_registry.len() {
        let not_activated =
            state.validator_registry[index].activation_epoch == spec.far_future_epoch;
        let has_enough_balance = state.validator_balances[index] >= spec.max_deposit_amount;

        if not_activated && has_enough_balance {
            // Check the balance churn would be within the allowance.
            balance_churn += state.get_effective_balance(index, spec)?;
            if balance_churn > max_balance_churn {
                break;
            }

            activate_validator(state, index, false, spec);
        }
    }

    // Exit validators within the allowable balance churn.
    let mut balance_churn = 0;
    for index in 0..state.validator_registry.len() {
        let not_exited = state.validator_registry[index].exit_epoch == spec.far_future_epoch;
        let has_initiated_exit = state.validator_registry[index].initiated_exit;

        if not_exited && has_initiated_exit {
            // Check the balance churn would be within the allowance.
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

/// Activate the validator of the given ``index``.
///
/// Spec v0.5.1
pub fn activate_validator(
    state: &mut BeaconState,
    validator_index: usize,
    is_genesis: bool,
    spec: &ChainSpec,
) {
    let current_epoch = state.current_epoch(spec);

    state.validator_registry[validator_index].activation_epoch = if is_genesis {
        spec.genesis_epoch
    } else {
        state.get_delayed_activation_exit_epoch(current_epoch, spec)
    }
}
