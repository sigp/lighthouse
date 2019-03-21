use super::errors::InclusionError;
use super::get_attestation_participants::get_attestation_participants;
use types::*;

/// Returns the distance between the first included attestation for some validator and this
/// slot.
///
/// Spec v0.5.0
pub fn inclusion_distance(
    state: &BeaconState,
    attestations: &[&PendingAttestation],
    validator_index: usize,
    spec: &ChainSpec,
) -> Result<u64, InclusionError> {
    let attestation = earliest_included_attestation(state, attestations, validator_index, spec)?;
    Ok((attestation.inclusion_slot - attestation.data.slot).as_u64())
}

/// Returns the slot of the earliest included attestation for some validator.
///
/// Spec v0.5.0
pub fn inclusion_slot(
    state: &BeaconState,
    attestations: &[&PendingAttestation],
    validator_index: usize,
    spec: &ChainSpec,
) -> Result<Slot, InclusionError> {
    let attestation = earliest_included_attestation(state, attestations, validator_index, spec)?;
    Ok(attestation.inclusion_slot)
}

/// Finds the earliest included attestation for some validator.
///
/// Spec v0.5.0
fn earliest_included_attestation(
    state: &BeaconState,
    attestations: &[&PendingAttestation],
    validator_index: usize,
    spec: &ChainSpec,
) -> Result<PendingAttestation, InclusionError> {
    let mut included_attestations = vec![];

    for (i, a) in attestations.iter().enumerate() {
        let participants =
            get_attestation_participants(state, &a.data, &a.aggregation_bitfield, spec)?;
        if participants.iter().any(|i| *i == validator_index) {
            included_attestations.push(i);
        }
    }

    let earliest_attestation_index = included_attestations
        .iter()
        .min_by_key(|i| attestations[**i].inclusion_slot)
        .ok_or_else(|| InclusionError::NoAttestationsForValidator)?;
    Ok(attestations[*earliest_attestation_index].clone())
}
