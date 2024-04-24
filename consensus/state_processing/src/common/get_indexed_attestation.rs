use super::get_attesting_indices;
use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
use types::{indexed_attestation::IndexedAttestationBase, *};

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

/// Convert `attestation` to (almost) indexed-verifiable form.
///
/// Spec v0.12.1
pub fn get_indexed_attestation<E: EthSpec>(
    committee: &[usize],
    attestation: &Attestation<E>,
) -> Result<IndexedAttestation<E>> {
    let attesting_indices = match attestation {
        Attestation::Base(att) => get_attesting_indices::<E>(committee, &att.aggregation_bits)?,
        // TODO(eip7549) implement get_attesting_indices for electra
        Attestation::Electra(_) => todo!(),
    };

    Ok(IndexedAttestation::Base(IndexedAttestationBase {
        attesting_indices: VariableList::new(attesting_indices)?,
        data: attestation.data().clone(),
        signature: attestation.signature().clone(),
    }))
}
