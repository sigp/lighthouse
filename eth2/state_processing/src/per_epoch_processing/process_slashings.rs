use types::{BeaconStateError as Error, *};

/// Process slashings.
///
/// Spec v0.5.1
pub fn process_slashings(
    state: &mut BeaconState,
    current_total_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);

    let total_at_start = state.get_slashed_balance(current_epoch + 1, spec)?;
    let total_at_end = state.get_slashed_balance(current_epoch, spec)?;
    let total_penalities = total_at_end - total_at_start;

    for (index, validator) in state.validator_registry.iter().enumerate() {
        let should_penalize = current_epoch.as_usize()
            == validator.withdrawable_epoch.as_usize() - spec.latest_slashed_exit_length / 2;

        if validator.slashed && should_penalize {
            let effective_balance = state.get_effective_balance(index, spec)?;

            let penalty = std::cmp::max(
                effective_balance * std::cmp::min(total_penalities * 3, current_total_balance)
                    / current_total_balance,
                effective_balance / spec.min_penalty_quotient,
            );

            state.validator_balances[index] -= penalty;
        }
    }

    Ok(())
}
