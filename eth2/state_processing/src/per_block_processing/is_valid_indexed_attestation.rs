use super::errors::{BlockOperationError, IndexedAttestationInvalid as Invalid};
use super::signature_sets::indexed_attestation_signature_set;
use crate::VerifySignatures;
use std::collections::HashSet;
use std::iter::FromIterator;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Verify an `IndexedAttestation`.
///
/// Spec v0.8.0
pub fn is_valid_indexed_attestation<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation<T>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let bit_0_indices = &indexed_attestation.custody_bit_0_indices;
    let bit_1_indices = &indexed_attestation.custody_bit_1_indices;

    // Verify no index has custody bit equal to 1 [to be removed in phase 1]
    verify!(bit_1_indices.is_empty(), Invalid::CustodyBitfieldHasSetBits);

    // Verify max number of indices
    let total_indices = bit_0_indices.len() + bit_1_indices.len();
    verify!(
        total_indices <= T::MaxValidatorsPerCommittee::to_usize(),
        Invalid::MaxIndicesExceed(T::MaxValidatorsPerCommittee::to_usize(), total_indices)
    );

    // Verify index sets are disjoint
    let custody_bit_intersection: HashSet<&u64> =
        &HashSet::from_iter(bit_0_indices.iter()) & &HashSet::from_iter(bit_1_indices.iter());
    verify!(
        custody_bit_intersection.is_empty(),
        Invalid::CustodyBitValidatorsIntersect
    );

    // Check that both vectors of indices are sorted
    let check_sorted = |list: &[u64]| -> Result<()> {
        list.windows(2).enumerate().try_for_each(|(i, pair)| {
            if pair[0] >= pair[1] {
                Err(error(Invalid::BadValidatorIndicesOrdering(i)))
            } else {
                Ok(())
            }
        })?;
        Ok(())
    };
    check_sorted(&bit_0_indices)?;
    check_sorted(&bit_1_indices)?;

    if verify_signatures.is_true() {
        verify!(
            indexed_attestation_signature_set(
                state,
                &indexed_attestation.signature,
                &indexed_attestation,
                spec
            )?
            .is_valid(),
            Invalid::BadSignature
        );
    }

    Ok(())
}
