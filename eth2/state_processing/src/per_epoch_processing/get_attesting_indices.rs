use crate::common::verify_bitfield_length;
use types::*;

/// Returns validator indices which participated in the attestation.
///
/// Spec v0.6.1
pub fn get_attesting_indices_unsorted(
    state: &BeaconState,
    attestation_data: &AttestationData,
    bitfield: &Bitfield,
    spec: &ChainSpec,
) -> Result<Vec<usize>, BeaconStateError> {
    let committee = state.get_crosslink_committee(
        attestation_data.target_epoch,
        attestation_data.shard,
        spec,
    )?;

    if !verify_bitfield_length(&bitfield, committee.committee.len()) {
        return Err(BeaconStateError::InvalidBitfield);
    }

    Ok(committee
        .committee
        .iter()
        .enumerate()
        .filter_map(|(i, validator_index)| match bitfield.get(i) {
            Ok(true) => Some(*validator_index),
            _ => None,
        })
        .collect())
}
