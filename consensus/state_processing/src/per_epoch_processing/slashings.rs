use crate::common::decrease_balance;
use crate::per_epoch_processing::{
    single_pass::{process_epoch_single_pass, SinglePassConfig},
    Error,
};
use safe_arith::{SafeArith, SafeArithIter};
use types::{BeaconState, ChainSpec, EthSpec, Unsigned};

/// Process slashings.
pub fn process_slashings<E: EthSpec>(
    state: &mut BeaconState<E>,
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
        epoch.safe_add(E::EpochsPerSlashingsVector::to_u64().safe_div(2)?)?;
    let indices = state
        .validators()
        .iter()
        .enumerate()
        .filter(|(_, validator)| {
            validator.slashed && target_withdrawable_epoch == validator.withdrawable_epoch
        })
        .map(|(index, validator)| (index, validator.effective_balance))
        .collect::<Vec<(usize, u64)>>();

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

pub fn process_slashings_slow<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    process_epoch_single_pass(
        state,
        spec,
        SinglePassConfig {
            slashings: true,
            ..SinglePassConfig::disable_all()
        },
    )?;
    Ok(())
}
