use super::errors::EpochProcessingError;
use safe_arith::SafeArith;
use types::beacon_state::BeaconState;
use types::chain_spec::ChainSpec;
use types::{BeaconStateError, EthSpec};

pub fn process_effective_balance_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    // Compute new total active balance for the next epoch as a side-effect of iterating the
    // effective balances.
    let next_epoch = state.next_epoch()?;
    let mut new_total_active_balance = 0;

    let hysteresis_increment = spec
        .effective_balance_increment
        .safe_div(spec.hysteresis_quotient)?;
    let downward_threshold = hysteresis_increment.safe_mul(spec.hysteresis_downward_multiplier)?;
    let upward_threshold = hysteresis_increment.safe_mul(spec.hysteresis_upward_multiplier)?;
    let (validators, balances) = state.validators_and_balances_mut();
    let mut validators_iter = validators.iter_cow();

    while let Some((index, validator)) = validators_iter.next_cow() {
        let balance = balances
            .get(index)
            .copied()
            .ok_or(BeaconStateError::BalancesOutOfBounds(index))?;

        let new_effective_balance = if balance.safe_add(downward_threshold)?
            < validator.effective_balance()
            || validator.effective_balance().safe_add(upward_threshold)? < balance
        {
            std::cmp::min(
                balance.safe_sub(balance.safe_rem(spec.effective_balance_increment)?)?,
                spec.max_effective_balance,
            )
        } else {
            validator.effective_balance()
        };

        if validator.is_active_at(next_epoch) {
            new_total_active_balance.safe_add_assign(new_effective_balance)?;
        }

        if new_effective_balance != validator.effective_balance() {
            validator.to_mut().mutable.effective_balance = new_effective_balance;
        }
    }

    state.set_total_active_balance(next_epoch, new_total_active_balance);

    Ok(())
}
