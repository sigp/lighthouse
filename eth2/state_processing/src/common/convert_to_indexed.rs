use super::get_attesting_indices;
use itertools::{Either, Itertools};
use types::*;

/// Convert `attestation` to (almost) indexed-verifiable form.
///
/// Spec v0.6.1
pub fn convert_to_indexed<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation,
) -> Result<IndexedAttestation, BeaconStateError> {
    let attesting_indices =
        get_attesting_indices(state, &attestation.data, &attestation.aggregation_bitfield)?;

    let (custody_bit_0_indices, custody_bit_1_indices) =
        attesting_indices.into_iter().enumerate().partition_map(
            |(committee_idx, validator_idx)| match attestation.custody_bitfield.get(committee_idx) {
                Ok(true) => Either::Right(validator_idx as u64),
                _ => Either::Left(validator_idx as u64),
            },
        );

    Ok(IndexedAttestation {
        custody_bit_0_indices,
        custody_bit_1_indices,
        data: attestation.data.clone(),
        signature: attestation.signature.clone(),
    })
}
