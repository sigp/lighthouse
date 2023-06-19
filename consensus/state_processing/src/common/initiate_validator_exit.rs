use safe_arith::SafeArith;
use std::cmp::max;
use types::{BeaconStateError as Error, *};

/// Initiate the exit of the validator of the given `index`.
pub fn initiate_validator_exit<T: EthSpec>(
    state: &mut BeaconState<T>,
    index: usize,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // We do things in a slightly different order to the spec here. Instead of immediately checking
    // whether the validator has already exited, we instead prepare the exit cache and compute the
    // cheap-to-calculate values from that. *Then* we look up the validator a single time in the
    // validator tree (expensive), make the check and mutate as appropriate.

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

    let validator = state.get_validator_cow(index)?;

    // Return if the validator already initiated exit
    if validator.exit_epoch() != spec.far_future_epoch {
        return Ok(());
    }

    let validator = validator.to_mut();
    validator.mutable.exit_epoch = exit_queue_epoch;
    validator.mutable.withdrawable_epoch =
        exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;

    state
        .exit_cache_mut()
        .record_validator_exit(exit_queue_epoch)?;

    Ok(())
}
