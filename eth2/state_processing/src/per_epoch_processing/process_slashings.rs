use safe_arith::SafeArith;
use types::{BeaconStateError as Error, *};

/// Process slashings.
///
/// Spec v0.11.1
pub fn process_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    total_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let epoch = state.current_epoch();
    let sum_slashings = state.get_all_slashings().iter().sum::<u64>();

    for (index, validator) in state.validators.iter().enumerate() {
        if validator.slashed
            && epoch + T::EpochsPerSlashingsVector::to_u64().safe_div(2)?
                == validator.withdrawable_epoch
        {
            let increment = spec.effective_balance_increment;
            let penalty_numerator = validator
                .effective_balance
                .safe_div(increment)?
                .safe_mul(std::cmp::min(sum_slashings.safe_mul(3)?, total_balance))?;
            let penalty = penalty_numerator
                .safe_div(total_balance)?
                .safe_mul(increment)?;

            safe_sub_assign!(state.balances[index], penalty);
        }
    }

    Ok(())
}
