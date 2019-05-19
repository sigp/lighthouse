use crate::common::verify_bitfield_length;
use types::*;

/// Returns validator indices which participated in the attestation.
///
/// Spec v0.6.1
pub fn get_attesting_indices_unsorted<T: EthSpec>(
    state: &BeaconState<T>,
    attestation_data: &AttestationData,
    bitfield: &Bitfield,
) -> Result<Vec<usize>, BeaconStateError> {
    let target_relative_epoch =
        RelativeEpoch::from_epoch(state.current_epoch(), attestation_data.target_epoch)?;

    let committee =
        state.get_crosslink_committee_for_shard(attestation_data.shard, target_relative_epoch)?;

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
