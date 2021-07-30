use super::errors::{BlockOperationError, IndexedAttestationInvalid as Invalid};
use super::signature_sets::{get_pubkey_from_state, indexed_attestation_signature_set};
use crate::VerifySignatures;
use itertools::Itertools;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Verify an `IndexedAttestation`.
pub fn is_valid_indexed_attestation<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation<T>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let indices = &indexed_attestation.attesting_indices;

    // Verify that indices aren't empty
    verify!(!indices.is_empty(), Invalid::IndicesEmpty);

    // Check that indices are sorted and unique
    let check_sorted = |list: &[u64]| -> Result<()> {
        list.iter()
            .tuple_windows()
            .enumerate()
            .try_for_each(|(i, (x, y))| {
                if x < y {
                    Ok(())
                } else {
                    Err(error(Invalid::BadValidatorIndicesOrdering(i)))
                }
            })?;
        Ok(())
    };
    check_sorted(indices)?;

    if verify_signatures.is_true() {
        verify!(
            indexed_attestation_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                &indexed_attestation.signature,
                indexed_attestation,
                spec
            )?
            .verify(),
            Invalid::BadSignature
        );
    }

    Ok(())
}
