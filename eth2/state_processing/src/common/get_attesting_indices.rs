use std::collections::BTreeSet;
use types::*;

/// Returns validator indices which participated in the attestation, sorted by increasing index.
///
/// Spec v0.11.1
pub fn get_attesting_indices<T: EthSpec>(
    committee: &[usize],
    bitlist: &BitList<T::MaxValidatorsPerCommittee>,
) -> Result<BTreeSet<usize>, BeaconStateError> {
    if bitlist.len() != committee.len() {
        return Err(BeaconStateError::InvalidBitfield);
    }

    Ok(committee
        .iter()
        .enumerate()
        .filter_map(|(i, validator_index)| match bitlist.get(i) {
            Ok(true) => Some(*validator_index),
            _ => None,
        })
        .collect())
}
