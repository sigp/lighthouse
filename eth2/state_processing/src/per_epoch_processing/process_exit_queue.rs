use types::*;

/// Process the exit queue.
///
/// Spec v0.5.0
pub fn process_exit_queue(state: &mut BeaconState, spec: &ChainSpec) {
    let current_epoch = state.current_epoch(spec);

    let eligible = |index: usize| {
        let validator = &state.validator_registry[index];

        if validator.withdrawable_epoch != spec.far_future_epoch {
            false
        } else {
            current_epoch >= validator.exit_epoch + spec.min_validator_withdrawability_delay
        }
    };

    let mut eligable_indices: Vec<usize> = (0..state.validator_registry.len())
        .filter(|i| eligible(*i))
        .collect();
    eligable_indices.sort_by_key(|i| state.validator_registry[*i].exit_epoch);

    for (dequeues, index) in eligable_indices.iter().enumerate() {
        if dequeues as u64 >= spec.max_exit_dequeues_per_epoch {
            break;
        }
        prepare_validator_for_withdrawal(state, *index, spec);
    }
}

/// Initiate an exit for the validator of the given `index`.
///
/// Spec v0.5.0
fn prepare_validator_for_withdrawal(
    state: &mut BeaconState,
    validator_index: usize,
    spec: &ChainSpec,
) {
    state.validator_registry[validator_index].withdrawable_epoch =
        state.current_epoch(spec) + spec.min_validator_withdrawability_delay;
}
