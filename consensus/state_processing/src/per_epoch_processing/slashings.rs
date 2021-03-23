use crate::per_epoch_processing::Error;
use safe_arith::{SafeArith, SafeArithIter};
use types::{BeaconState, ChainSpec, EthSpec, Unsigned};

/// Process slashings.
pub fn process_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    total_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let epoch = state.current_epoch();
    let sum_slashings = state.get_all_slashings().iter().copied().safe_sum()?;
    // FIXME(altair): abstract over slashing multiplier
    let adjusted_total_slashing_balance = std::cmp::min(
        sum_slashings.safe_mul(spec.proportional_slashing_multiplier)?,
        total_balance,
    );

    let (validators, balances) = state.validators_and_balances_mut();
    for (index, validator) in validators.iter().enumerate() {
        if validator.slashed
            && epoch.safe_add(T::EpochsPerSlashingsVector::to_u64().safe_div(2)?)?
                == validator.withdrawable_epoch
        {
            let increment = spec.effective_balance_increment;
            let penalty_numerator = validator
                .effective_balance
                .safe_div(increment)?
                .safe_mul(adjusted_total_slashing_balance)?;
            let penalty = penalty_numerator
                .safe_div(total_balance)?
                .safe_mul(increment)?;

            // Equivalent to `decrease_balance(state, index, penalty)`, but avoids borrowing `state`.
            balances[index] = balances[index].saturating_sub(penalty);
        }
    }

    Ok(())
}
