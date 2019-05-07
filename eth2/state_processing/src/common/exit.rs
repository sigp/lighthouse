use std::cmp::max;
use types::{BeaconStateError as Error, *};

/// Initiate the exit of the validator of the given `index`.
///
/// Spec v0.6.1
pub fn initiate_validator_exit(
    state: &mut BeaconState,
    index: usize,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if index >= state.validator_registry.len() {
        return Err(Error::UnknownValidator);
    }

    // Return if the validator already initiated exit
    if state.validator_registry[index].exit_epoch != spec.far_future_epoch {
        return Ok(());
    }

    // Compute exit queue epoch
    let delayed_epoch = state.get_delayed_activation_exit_epoch(state.current_epoch(spec), spec);
    let mut exit_queue_epoch = state
        .exit_cache
        .max_epoch()
        .map_or(delayed_epoch, |epoch| max(epoch, delayed_epoch));
    let exit_queue_churn = state.exit_cache.get_churn_at(exit_queue_epoch);

    if exit_queue_churn >= state.get_churn_limit(spec)? {
        exit_queue_epoch += 1;
    }

    state.exit_cache.record_validator_exit(exit_queue_epoch);
    state.validator_registry[index].exit_epoch = exit_queue_epoch;
    state.validator_registry[index].withdrawable_epoch =
        exit_queue_epoch + spec.min_validator_withdrawability_delay;

    Ok(())
}
