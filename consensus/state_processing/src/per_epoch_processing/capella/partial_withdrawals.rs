use crate::common::withdraw_balance;
use crate::EpochProcessingError;
use safe_arith::SafeArith;
use types::{beacon_state::BeaconState, eth_spec::EthSpec, ChainSpec};

pub fn process_partial_withdrawals<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let mut partial_withdrawals_count = 0;
    let mut validator_index = *state.next_partial_withdrawal_validator_index()? as usize;

    let n_validators = state.validators().len();
    // FIXME: is this the most efficient way to do this?
    for _ in 0..n_validators {
        // TODO: is this the correct way to handle validators not existing?
        if let (Some(validator), Some(balance)) = (
            state.validators().get(validator_index),
            state.balances().get(validator_index),
        ) {
            if validator.is_partially_withdrawable_validator(*balance, spec) {
                withdraw_balance(
                    state,
                    validator_index,
                    *balance - spec.max_effective_balance,
                )?;
                partial_withdrawals_count.safe_add_assign(1)?;

                validator_index = validator_index.safe_add(1)? % n_validators;
                if partial_withdrawals_count == T::max_partial_withdrawals_per_epoch() {
                    break;
                }
            }
        }
    }
    *state.next_partial_withdrawal_validator_index_mut()? = validator_index as u64;

    Ok(())
}
