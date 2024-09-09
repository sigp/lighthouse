use super::errors::{BlockOperationError, IndexedPayloadAttestationInvalid as Invalid};
use super::signature_sets::{get_pubkey_from_state, indexed_payload_attestation_signature_set};
use crate::VerifySignatures;
use itertools::Itertools;
use types::*;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

pub fn is_valid_indexed_payload_attestation<E: EthSpec>(
    state: &BeaconState<E>,
    indexed_payload_attestation: &IndexedPayloadAttestation<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockOperationError<Invalid>> {
    // Verify the data is valid
    if indexed_payload_attestation.data.payload_status >= PayloadStatus::PayloadInvalidStatus {
        return Err(error(Invalid::PayloadStatusInvalid));
    }

    // Verify indices are sorted and unique
    let indices = &indexed_payload_attestation.attesting_indices;
    verify!(!indices.is_empty(), Invalid::IndicesEmpty);
    let check_sorted = |list: &[u64]| -> Result<(), BlockOperationError<Invalid>> {
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
    check_sorted(&indices)?;

    if verify_signatures.is_true() {
        verify!(
            indexed_payload_attestation_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                &indexed_payload_attestation.signature,
                &indexed_payload_attestation,
                spec
            )?
            .verify(),
            Invalid::BadSignature
        );
    }

    Ok(())
}
