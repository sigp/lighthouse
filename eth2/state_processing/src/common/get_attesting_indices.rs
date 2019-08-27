use std::collections::BTreeSet;
use types::*;

/// Returns validator indices which participated in the attestation, sorted by increasing index.
///
/// Spec v0.8.1
pub fn get_attesting_indices<T: EthSpec>(
    state: &BeaconState<T>,
    attestation_data: &AttestationData,
    bitlist: &BitList<T::MaxValidatorsPerCommittee>,
) -> Result<BTreeSet<usize>, BeaconStateError> {
    let target_relative_epoch =
        RelativeEpoch::from_epoch(state.current_epoch(), attestation_data.target.epoch)?;

    let committee = state.get_crosslink_committee_for_shard(
        attestation_data.crosslink.shard,
        target_relative_epoch,
    )?;

    if bitlist.len() != committee.committee.len() {
        return Err(BeaconStateError::InvalidBitfield);
    }

    Ok(committee
        .committee
        .iter()
        .enumerate()
        .filter_map(|(i, validator_index)| match bitlist.get(i) {
            Ok(true) => Some(*validator_index),
            _ => None,
        })
        .collect())
}
