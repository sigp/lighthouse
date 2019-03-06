use crate::errors::{DepositInvalid as Invalid, DepositValidationError as Error};
use types::*;

/// Indicates if a `Deposit` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `Deposit` is valid, otherwise indicates the reason for invalidity.
///
/// Note: this function is incomplete.
///
/// Spec v0.4.0
pub fn verify_deposit(
    state: &BeaconState,
    deposit: &Deposit,
    _spec: &ChainSpec,
) -> Result<(), Error> {
    // TODO: verify serialized deposit data.

    // TODO: verify deposit index.
    verify!(
        deposit.index == state.deposit_index,
        Invalid::BadIndex(state.deposit_index, deposit.index)
    );

    // TODO: verify merkle branch.

    Ok(())
}
