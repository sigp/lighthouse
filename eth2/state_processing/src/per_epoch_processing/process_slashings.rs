use types::{BeaconStateError as Error, *};

/// Process slashings.
///
/// Spec v0.6.3
pub fn process_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    current_total_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state.current_epoch();

    let total_at_start = state.get_slashed_balance(current_epoch + 1)?;
    let total_at_end = state.get_slashed_balance(current_epoch)?;
    let total_penalties = total_at_end - total_at_start;

    for (index, validator) in state.validator_registry.iter().enumerate() {
        let should_penalize = current_epoch.as_usize() + T::LatestSlashedExitLength::to_usize() / 2
            == validator.withdrawable_epoch.as_usize();

        if validator.slashed && should_penalize {
            let effective_balance = state.get_effective_balance(index, spec)?;

            let penalty = std::cmp::max(
                effective_balance * std::cmp::min(total_penalties * 3, current_total_balance)
                    / current_total_balance,
                effective_balance / spec.min_slashing_penalty_quotient,
            );

            safe_sub_assign!(state.balances[index], penalty);
        }
    }

    Ok(())
}
