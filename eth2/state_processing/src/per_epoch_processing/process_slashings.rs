use types::{BeaconStateError as Error, *};

/// Process slashings.
///
/// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
///
/// Spec v0.4.0
pub fn process_slashings(state: &mut BeaconState, spec: &ChainSpec) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);
    let active_validator_indices =
        state.get_cached_active_validator_indices(RelativeEpoch::Current, spec)?;
    let total_balance = state.get_total_balance(&active_validator_indices[..], spec)?;

    for (index, validator) in state.validator_registry.iter().enumerate() {
        if validator.slashed
            && (current_epoch
                == validator.withdrawable_epoch - Epoch::from(spec.latest_slashed_exit_length / 2))
        {
            // TODO: check the following two lines are correct.
            let total_at_start = state.get_slashed_balance(current_epoch + 1, spec)?;
            let total_at_end = state.get_slashed_balance(current_epoch, spec)?;

            let total_penalities = total_at_end.saturating_sub(total_at_start);

            let effective_balance = state.get_effective_balance(index, spec)?;
            let penalty = std::cmp::max(
                effective_balance * std::cmp::min(total_penalities * 3, total_balance)
                    / total_balance,
                effective_balance / spec.min_penalty_quotient,
            );

            safe_sub_assign!(state.validator_balances[index], penalty);
        }
    }

    Ok(())
}
