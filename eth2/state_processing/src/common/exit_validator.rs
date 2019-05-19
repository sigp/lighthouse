use types::{BeaconStateError as Error, *};

/// Exit the validator of the given `index`.
///
/// Spec v0.5.1
pub fn exit_validator<T: EthSpec>(
    state: &mut BeaconState<T>,
    validator_index: usize,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if validator_index >= state.validator_registry.len() {
        return Err(Error::UnknownValidator);
    }

    let delayed_epoch = state.get_delayed_activation_exit_epoch(state.current_epoch(), spec);

    if state.validator_registry[validator_index].exit_epoch > delayed_epoch {
        state.validator_registry[validator_index].exit_epoch = delayed_epoch;
    }

    Ok(())
}
