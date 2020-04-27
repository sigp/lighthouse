use types::*;

/// Returns validator indices which participated in the attestation, sorted by increasing index.
///
/// Spec v0.11.1
pub fn get_attesting_indices<T: EthSpec>(
    committee: &[usize],
    bitlist: &BitList<T::MaxValidatorsPerCommittee>,
) -> Result<Vec<usize>, BeaconStateError> {
    if bitlist.len() != committee.len() {
        return Err(BeaconStateError::InvalidBitfield);
    }

    let mut indices = Vec::with_capacity(bitlist.num_set_bits());

    for (i, validator_index) in committee.iter().enumerate() {
        if let Ok(true) = bitlist.get(i) {
            indices.push(*validator_index)
        }
    }

    indices.sort_unstable();

    Ok(indices)
}
