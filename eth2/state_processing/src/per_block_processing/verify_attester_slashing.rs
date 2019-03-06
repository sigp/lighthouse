use super::verify_slashable_attestation::verify_slashable_attestation;
use crate::errors::{AttesterSlashingInvalid as Invalid, AttesterSlashingValidationError as Error};
use types::*;

/// Indicates if an `AttesterSlashing` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `AttesterSlashing` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.4.0
pub fn verify_attester_slashing(
    state: &BeaconState,
    attester_slashing: &AttesterSlashing,
    spec: &ChainSpec,
) -> Result<Vec<u64>, Error> {
    let slashable_attestation_1 = &attester_slashing.slashable_attestation_1;
    let slashable_attestation_2 = &attester_slashing.slashable_attestation_2;

    verify!(
        slashable_attestation_1.data != slashable_attestation_2.data,
        Invalid::AttestationDataIdentical
    );
    verify!(
        slashable_attestation_1.is_double_vote(slashable_attestation_2, spec)
            | slashable_attestation_1.is_surround_vote(slashable_attestation_2, spec),
        Invalid::NotSlashable
    );

    verify_slashable_attestation(state, &slashable_attestation_1, spec)
        .map_err(|e| Error::Invalid(Invalid::SlashableAttestation1Invalid(e.into())))?;
    verify_slashable_attestation(state, &slashable_attestation_2, spec)
        .map_err(|e| Error::Invalid(Invalid::SlashableAttestation2Invalid(e.into())))?;

    let mut slashable_indices = vec![];
    for i in &slashable_attestation_1.validator_indices {
        let validator = state
            .validator_registry
            .get(*i as usize)
            .ok_or_else(|| Error::Invalid(Invalid::UnknownValidator(*i)))?;

        if slashable_attestation_1.validator_indices.contains(&i) & !validator.slashed {
            slashable_indices.push(*i);
        }
    }

    verify!(!slashable_indices.is_empty(), Invalid::NoSlashableIndices);

    Ok(slashable_indices)
}
