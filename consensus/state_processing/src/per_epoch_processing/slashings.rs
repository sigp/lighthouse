use crate::common::decrease_balance;
use crate::per_epoch_processing::Error;
use safe_arith::{SafeArith, SafeArithIter};
use types::{BeaconState, ChainSpec, EthSpec, Unsigned};

/// Process slashings.
pub fn process_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    indices: Option<Vec<(usize, u64)>>,
    total_balance: u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let epoch = state.current_epoch();
    let sum_slashings = state.get_all_slashings().iter().copied().safe_sum()?;

    let adjusted_total_slashing_balance = std::cmp::min(
        sum_slashings.safe_mul(spec.proportional_slashing_multiplier_for_state(state))?,
        total_balance,
    );

    let target_withdrawable_epoch =
        epoch.safe_add(T::EpochsPerSlashingsVector::to_u64().safe_div(2)?)?;
    let indices = indices.unwrap_or_else(|| {
        state
            .validators()
            .iter()
            .enumerate()
            .filter(|(_, validator)| {
                validator.slashed() && target_withdrawable_epoch == validator.withdrawable_epoch()
            })
            .map(|(index, validator)| (index, validator.effective_balance()))
            .collect()
    });

    for (index, validator_effective_balance) in indices {
        let increment = spec.effective_balance_increment;
        let penalty_numerator = validator_effective_balance
            .safe_div(increment)?
            .safe_mul(adjusted_total_slashing_balance)?;
        let penalty = penalty_numerator
            .safe_div(total_balance)?
            .safe_mul(increment)?;

        decrease_balance(state, index, penalty)?;
    }

    Ok(())
}
