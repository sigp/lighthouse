use crate::errors::{TransferInvalid as Invalid, TransferValidationError as Error};
use types::*;

/// Indicates if a `Transfer` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `Transfer` is valid, otherwise indicates the reason for invalidity.
///
/// Note: this function is incomplete.
///
/// Spec v0.4.0
pub fn verify_transfer(
    _state: &BeaconState,
    _transfer: &Transfer,
    _spec: &ChainSpec,
) -> Result<(), Error> {
    // TODO: verify transfer.

    Ok(())
}
