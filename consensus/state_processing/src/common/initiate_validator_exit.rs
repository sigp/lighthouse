use safe_arith::SafeArith;
use std::cmp::max;
use types::{BeaconStateError as Error, *};

/// Initiate the exit of the validator of the given `index`.
pub fn initiate_validator_exit<T: EthSpec>(
    state: &mut BeaconState<T>,
    index: usize,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // TODO: try to minimize lookups of the validator while satisfying the borrow checker
    // Return if the validator already initiated exit
    let validator = state.get_validator(index)?;
    if validator.exit_epoch != spec.far_future_epoch {
        return Ok(());
    }

    match &state {
        &BeaconState::Base(_)
        | &BeaconState::Altair(_)
        | &BeaconState::Merge(_)
        | &BeaconState::Capella(_)
        | &BeaconState::Deneb(_) => {
            // Ensure the exit cache is built.
            state.build_exit_cache(spec)?;

            // Compute exit queue epoch
            let delayed_epoch = state.compute_activation_exit_epoch(state.current_epoch(), spec)?;
            let mut exit_queue_epoch = state
                .exit_cache()
                .max_epoch()?
                .map_or(delayed_epoch, |epoch| max(epoch, delayed_epoch));
            let exit_queue_churn = state.exit_cache().get_churn_at(exit_queue_epoch)?;

            if exit_queue_churn >= state.get_churn_limit(spec)? {
                exit_queue_epoch.safe_add_assign(1)?;
            }
            state
                .exit_cache_mut()
                .record_validator_exit(exit_queue_epoch)?;

            let validator = state.get_validator_mut(index)?;
            validator.exit_epoch = exit_queue_epoch;
            validator.withdrawable_epoch =
                exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;
        }
        &BeaconState::Electra(_) => {
            // Compute exit queue epoch [Modified in Electra:EIP7251]
            let exit_queue_epoch =
                compute_exit_epoch_and_update_churn(state, validator.effective_balance, spec)?;
            let validator = state.get_validator_mut(index)?;
            // Set validator exit epoch and withdrawable epoch
            validator.exit_epoch = exit_queue_epoch;
            validator.withdrawable_epoch = validator
                .exit_epoch
                .safe_add(spec.min_validator_withdrawability_delay)?;
            // TODO: consider impact on exit cache
        }
    }

    Ok(())
}

// TODO: should this function be moved to its own file?
pub fn compute_exit_epoch_and_update_churn<E: EthSpec>(
    state: &mut BeaconState<E>,
    exit_balance: u64,
    spec: &ChainSpec,
) -> Result<Epoch, Error> {
    let earliest_exit_epoch = state.compute_activation_exit_epoch(state.current_epoch(), spec)?;
    let per_epoch_churn = state.get_activation_exit_churn_limit(spec)?;

    if state.earliest_exit_epoch()? < earliest_exit_epoch {
        *state.earliest_exit_epoch_mut()? = earliest_exit_epoch;
        *state.exit_balance_to_consume_mut()? = per_epoch_churn;
    }
    if exit_balance <= state.exit_balance_to_consume()? {
        // Exit fits in the current earliest epoch
        state
            .exit_balance_to_consume_mut()?
            .safe_sub_assign(exit_balance)?;
    } else {
        // Exit does not fit in the current earliest epoch
        let balance_to_process = exit_balance.safe_sub(state.exit_balance_to_consume()?)?;
        let additional_epochs = balance_to_process.safe_div(per_epoch_churn)?;
        let remainder = balance_to_process.safe_rem(per_epoch_churn)?;
        *state.earliest_exit_epoch_mut()? = Epoch::new(additional_epochs.safe_add(1)?);
        *state.exit_balance_to_consume_mut()? = per_epoch_churn.safe_sub(remainder)?;
    }

    state.earliest_exit_epoch()
}
