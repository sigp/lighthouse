use types::{BeaconStateError as Error, *};

/// Process slashings.
///
/// Spec v0.8.0
pub fn process_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    total_balance: u64,
) -> Result<(), Error> {
    let epoch = state.current_epoch();
    let sum_slashings = state.get_all_slashings().iter().sum::<u64>();

    for (index, validator) in state.validators.iter().enumerate() {
        if validator.slashed
            && epoch + T::EpochsPerSlashingsVector::to_u64() / 2 == validator.withdrawable_epoch
        {
            let penalty = validator.effective_balance
                * std::cmp::min(sum_slashings * 3, total_balance)
                / total_balance;

            safe_sub_assign!(state.balances[index], penalty);
        }
    }

    Ok(())
}
