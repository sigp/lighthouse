use super::errors::{BlockOperationError, BlsExecutionChangeInvalid as Invalid};
use crate::per_block_processing::signature_sets::bls_execution_change_signature_set;
use crate::VerifySignatures;
use eth2_hashing::hash;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Indicates if a `BlsToExecutionChange` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `SignedBlsToExecutionChange` is valid, otherwise indicates the reason for invalidity.
pub fn verify_bls_to_execution_change<T: EthSpec>(
    state: &BeaconState<T>,
    signed_address_change: &SignedBlsToExecutionChange,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let address_change = &signed_address_change.message;

    let validator = state
        .validators()
        .get(address_change.validator_index as usize)
        .ok_or_else(|| error(Invalid::ValidatorUnknown(address_change.validator_index)))?;

    verify!(
        validator
            .withdrawal_credentials
            .as_bytes()
            .first()
            .map(|byte| *byte == spec.bls_withdrawal_prefix_byte)
            .unwrap_or(false),
        Invalid::NonBlsWithdrawalCredentials
    );

    // Re-hashing the pubkey isn't necessary during block replay, so we may want to skip that in
    // future.
    let pubkey_hash = hash(address_change.from_bls_pubkey.as_serialized());
    verify!(
        validator.withdrawal_credentials.as_bytes().get(1..) == pubkey_hash.get(1..),
        Invalid::WithdrawalCredentialsMismatch
    );

    if verify_signatures.is_true() {
        verify!(
            bls_execution_change_signature_set(state, signed_address_change, spec)?.verify(),
            Invalid::BadSignature
        );
    }

    Ok(())
}
