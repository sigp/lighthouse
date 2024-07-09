use safe_arith::SafeArith;
use std::cmp::max;
use types::{BeaconStateError as Error, *};

/// Initiate the exit of the validator of the given `index`.
pub fn initiate_validator_exit<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let validator = state.get_validator_cow(index)?;

    // Return if the validator already initiated exit
    if validator.exit_epoch != spec.far_future_epoch {
        return Ok(());
    }

    // Ensure the exit cache is built.
    state.build_exit_cache(spec)?;

    // Compute exit queue epoch
    let exit_queue_epoch = if state.fork_name_unchecked() >= ForkName::Electra {
        let effective_balance = state.get_validator(index)?.effective_balance;
        state.compute_exit_epoch_and_update_churn(effective_balance, spec)?
    } else {
        let delayed_epoch = state.compute_activation_exit_epoch(state.current_epoch(), spec)?;
        let mut exit_queue_epoch = state
            .exit_cache()
            .max_epoch()?
            .map_or(delayed_epoch, |epoch| max(epoch, delayed_epoch));
        let exit_queue_churn = state.exit_cache().get_churn_at(exit_queue_epoch)?;

        if exit_queue_churn >= state.get_validator_churn_limit(spec)? {
            exit_queue_epoch.safe_add_assign(1)?;
        }
        exit_queue_epoch
    };

    let validator = state.get_validator_mut(index)?;
    validator.exit_epoch = exit_queue_epoch;
    validator.withdrawable_epoch =
        exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;

    state
        .exit_cache_mut()
        .record_validator_exit(exit_queue_epoch)?;

    Ok(())
}
