#[cfg(all(feature = "withdrawals", feature = "withdrawals-processing"))]
use crate::common::withdraw_balance;
use crate::EpochProcessingError;
use types::{beacon_state::BeaconState, eth_spec::EthSpec, ChainSpec};

#[cfg(all(feature = "withdrawals", feature = "withdrawals-processing"))]
pub fn process_full_withdrawals<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let current_epoch = state.current_epoch();
    // FIXME: is this the most efficient way to do this?
    for validator_index in 0..state.validators().len() {
        // TODO: is this the correct way to handle validators not existing?
        if let (Some(validator), Some(balance)) = (
            state.validators().get(validator_index),
            state.balances().get(validator_index),
        ) {
            if validator.is_fully_withdrawable_at(*balance, current_epoch, spec) {
                withdraw_balance(state, validator_index, *balance)?;
            }
        }
    }
    Ok(())
}
