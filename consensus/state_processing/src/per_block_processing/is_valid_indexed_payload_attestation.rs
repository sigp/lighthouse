use super::errors::{BlockOperationError, IndexedPayloadAttestationInvalid as Invalid};
use super::signature_sets::{get_pubkey_from_state, indexed_payload_attestation_signature_set};
use crate::VerifySignatures;
use types::*;

pub fn is_valid_indexed_payload_attestation<E: EthSpec>(
    state: &BeaconState<E>,
    indexed_payload_attestation: &IndexedPayloadAttestation<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockOperationError<Invalid>> {
    // Verify indices are non-empty and sorted (duplicates allowed)
    let indices = &indexed_payload_attestation.attesting_indices;
    verify!(!indices.is_empty(), Invalid::IndicesEmpty);
    verify!(indices.is_sorted(), Invalid::BadValidatorIndicesOrdering);

    if verify_signatures.is_true() {
        verify!(
            indexed_payload_attestation_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                &indexed_payload_attestation.signature,
                indexed_payload_attestation,
                spec
            )?
            .verify(),
            Invalid::BadSignature
        );
    }

    Ok(())
}
