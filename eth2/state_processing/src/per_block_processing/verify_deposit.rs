use crate::errors::{DepositInvalid as Invalid, DepositValidationError as Error};
use ssz::TreeHash;
use types::beacon_state::helpers::verify_bitfield_length;
use types::*;

/// Verify validity of ``slashable_attestation`` fields.
///
/// Returns `Ok(())` if all fields are valid.
///
/// Spec v0.4.0
pub fn verify_deposit(
    state: &BeaconState,
    deposit: &Deposit,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // TODO: verify serialized deposit data.

    // TODO: verify deposit index.
    verify!(deposit.index == state.deposit_index, Invalid::BadIndex);

    // TODO: verify merkle branch.

    Ok(())
}
