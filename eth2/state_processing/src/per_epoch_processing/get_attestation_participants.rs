use crate::common::verify_bitfield_length;
use types::*;

/// Returns validator indices which participated in the attestation.
///
/// Spec v0.5.1
pub fn get_attestation_participants<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    attestation_data: &AttestationData,
    bitfield: &Bitfield,
    spec: &ChainSpec,
) -> Result<Vec<usize>, BeaconStateError> {
    let epoch = attestation_data.slot.epoch(spec.slots_per_epoch);

    let crosslink_committee =
        state.get_crosslink_committee_for_shard(epoch, attestation_data.shard, spec)?;

    if crosslink_committee.slot != attestation_data.slot {
        return Err(BeaconStateError::NoCommitteeForShard);
    }

    let committee = &crosslink_committee.committee;

    if !verify_bitfield_length(&bitfield, committee.len()) {
        return Err(BeaconStateError::InvalidBitfield);
    }

    let mut participants = Vec::with_capacity(committee.len());
    for (i, validator_index) in committee.iter().enumerate() {
        match bitfield.get(i) {
            Ok(bit) if bit => participants.push(*validator_index),
            _ => {}
        }
    }
    participants.shrink_to_fit();

    Ok(participants)
}
