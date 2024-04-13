mod deposit_data_tree;
mod get_attestation_participation;
mod get_indexed_attestation;
mod initiate_validator_exit;
mod slash_validator;

pub mod altair;
pub mod base;
pub mod update_progressive_balances_cache;

pub use get_indexed_attestation::indexed_attestation_base;
pub use get_indexed_attestation::indexed_attestation_electra;

pub use deposit_data_tree::DepositDataTree;
pub use get_attestation_participation::get_attestation_participation_flag_indices;

pub use initiate_validator_exit::initiate_validator_exit;
pub use slash_validator::slash_validator;

use safe_arith::SafeArith;
use types::{BeaconState, BeaconStateError, EthSpec};

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    delta: u64,
) -> Result<(), BeaconStateError> {
    increase_balance_directly(state.get_balance_mut(index)?, delta)
}

/// Decrease the balance of a validator, saturating upon overflow, as per the spec.
pub fn decrease_balance<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    delta: u64,
) -> Result<(), BeaconStateError> {
    decrease_balance_directly(state.get_balance_mut(index)?, delta)
}

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance_directly(balance: &mut u64, delta: u64) -> Result<(), BeaconStateError> {
    balance.safe_add_assign(delta)?;
    Ok(())
}

/// Decrease the balance of a validator, saturating upon overflow, as per the spec.
pub fn decrease_balance_directly(balance: &mut u64, delta: u64) -> Result<(), BeaconStateError> {
    *balance = balance.saturating_sub(delta);
    Ok(())
}
