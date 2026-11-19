use super::errors::{BlockOperationError, IndexedAttestationInvalid as Invalid};
use super::signature_sets::{get_bls_pubkey_from_state, indexed_attestation_signature_set};
use crate::VerifySignatures;
use itertools::Itertools;
use typenum::Unsigned;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Verify an `IndexedAttestation`.
pub fn is_valid_indexed_attestation<E: EthSpec>(
    state: &BeaconState<E>,
    indexed_attestation: IndexedAttestationRef<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let indices = indexed_attestation.attesting_indices_to_vec();

    // Verify that indices aren't empty
    verify!(!indices.is_empty(), Invalid::IndicesEmpty);

    // [New in Gloas:EIP7688] Gloas attesting indices have no type-level bound, so check the
    // spec's maximum here. Pre-Gloas attestation types already enforce an equal or tighter bound
    // in SSZ.
    let max_indices = if matches!(indexed_attestation, IndexedAttestationRef::Pq(_)) {
        E::MaxValidatorsPerCommittee::to_usize().saturating_mul(E::max_committees_per_slot_pq())
    } else {
        E::MaxValidatorsPerSlot::to_usize()
    };
    verify!(
        indices.len() <= max_indices,
        Invalid::IndicesExceedMaxLength {
            length: indices.len(),
            max: max_indices,
        }
    );

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
    check_sorted(&indices)?;

    if let IndexedAttestationRef::Pq(indexed) = indexed_attestation {
        if verify_signatures.is_true() {
            let statement = crate::pq::attestation_statement(state, &indexed.data, &indices, spec)?;
            verify!(
                crate::pq::verify_attestation_proof::<E>(&[statement], &indexed.proof),
                Invalid::BadSignature
            );
        }
    } else if verify_signatures.is_true() {
        verify!(
            indexed_attestation_signature_set(
                state,
                |i| get_bls_pubkey_from_state(state, i),
                indexed_attestation.signature().map_err(|_| {
                    super::signature_sets::Error::PqUnsupported("IndexedAttestation")
                })?,
                indexed_attestation,
                spec
            )?
            .verify(),
            Invalid::BadSignature
        );
    }

    Ok(())
}
