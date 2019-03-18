use super::update_validator_registry::update_validator_registry;
use super::Error;
use types::*;

/// Peforms a validator registry update, if required.
///
/// Spec v0.4.0
pub fn process_validator_registry(state: &mut BeaconState, spec: &ChainSpec) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);
    let next_epoch = state.next_epoch(spec);

    state.previous_shuffling_epoch = state.current_shuffling_epoch;
    state.previous_shuffling_start_shard = state.current_shuffling_start_shard;

    state.previous_shuffling_seed = state.current_shuffling_seed;

    if should_update_validator_registry(state, spec)? {
        update_validator_registry(state, spec)?;

        state.current_shuffling_epoch = next_epoch;
        state.current_shuffling_start_shard = (state.current_shuffling_start_shard
            + spec.get_epoch_committee_count(
                state
                    .get_cached_active_validator_indices(RelativeEpoch::Current, spec)?
                    .len(),
            ) as u64)
            % spec.shard_count;
        state.current_shuffling_seed = state.generate_seed(state.current_shuffling_epoch, spec)?
    } else {
        let epochs_since_last_registry_update =
            current_epoch - state.validator_registry_update_epoch;
        if (epochs_since_last_registry_update > 1)
            & epochs_since_last_registry_update.is_power_of_two()
        {
            state.current_shuffling_epoch = next_epoch;
            state.current_shuffling_seed =
                state.generate_seed(state.current_shuffling_epoch, spec)?
        }
    }

    Ok(())
}

/// Returns `true` if the validator registry should be updated during an epoch processing.
///
/// Spec v0.5.0
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
        .into_iter()
        .map(|i| (state.current_shuffling_start_shard + i as u64) % spec.shard_count)
    {
        if state.latest_crosslinks[shard as usize].epoch <= state.validator_registry_update_epoch {
            return Ok(false);
        }
    }

    Ok(true)
}
