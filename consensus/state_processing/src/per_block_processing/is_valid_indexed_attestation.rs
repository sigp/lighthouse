use super::errors::{BlockOperationError, IndexedAttestationInvalid as Invalid};
use super::signature_sets::{get_pubkey_from_state, indexed_attestation_signature_set};
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
    verify!(
        indices.len() <= E::MaxValidatorsPerSlot::to_usize(),
        Invalid::IndicesExceedMaxLength {
            length: indices.len(),
            max: E::MaxValidatorsPerSlot::to_usize(),
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

    if verify_signatures.is_true() {
        verify!(
            indexed_attestation_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                indexed_attestation.signature(),
                indexed_attestation,
                spec
            )?
            .verify(),
            Invalid::BadSignature
        );
    }

    Ok(())
}
