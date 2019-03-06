use crate::errors::{TransferInvalid as Invalid, TransferValidationError as Error};
use ssz::TreeHash;
use types::beacon_state::helpers::verify_bitfield_length;
use types::*;

/// Verify validity of ``slashable_attestation`` fields.
///
/// Returns `Ok(())` if all fields are valid.
///
/// Spec v0.4.0
pub fn verify_transfer(
    state: &BeaconState,
    transfer: &Transfer,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // TODO: verify transfer.

    Ok(())
}
