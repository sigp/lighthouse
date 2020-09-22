use safe_arith::SafeArith;
use std::cmp::max;
use types::{BeaconStateError as Error, *};

/// Initiate the exit of the validator of the given `index`.
///
/// Spec v0.12.1
pub fn initiate_validator_exit<T: EthSpec>(
    state: &mut BeaconState<T>,
    index: usize,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if index >= state.validators.len() {
        return Err(Error::UnknownValidator(index as u64));
    }

    // Return if the validator already initiated exit
    if state.validators[index].exit_epoch != spec.far_future_epoch {
        return Ok(());
    }

    // Ensure the exit cache is built.
    state.exit_cache.build(&state.validators, spec)?;

    // Compute exit queue epoch
    let delayed_epoch = state.compute_activation_exit_epoch(state.current_epoch(), spec)?;
    let mut exit_queue_epoch = state
        .exit_cache
        .max_epoch()?
        .map_or(delayed_epoch, |epoch| max(epoch, delayed_epoch));
    let exit_queue_churn = state.exit_cache.get_churn_at(exit_queue_epoch)?;

    if exit_queue_churn >= state.get_churn_limit(spec)? {
        exit_queue_epoch.safe_add_assign(1)?;
    }

    state.exit_cache.record_validator_exit(exit_queue_epoch)?;
    state.validators[index].exit_epoch = exit_queue_epoch;
    state.validators[index].withdrawable_epoch =
        exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;

    Ok(())
}
