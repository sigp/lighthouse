use super::errors::{AttesterSlashingInvalid as Invalid, AttesterSlashingValidationError as Error};
use super::verify_slashable_attestation::verify_slashable_attestation;
use types::*;

/// Indicates if an `AttesterSlashing` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `AttesterSlashing` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.5.0
pub fn verify_attester_slashing(
    state: &BeaconState,
    attester_slashing: &AttesterSlashing,
    should_verify_slashable_attestations: bool,
    spec: &ChainSpec,
) -> Result<(), Error> {
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

    if should_verify_slashable_attestations {
        verify_slashable_attestation(state, &slashable_attestation_1, spec)
            .map_err(|e| Error::Invalid(Invalid::SlashableAttestation1Invalid(e.into())))?;
        verify_slashable_attestation(state, &slashable_attestation_2, spec)
            .map_err(|e| Error::Invalid(Invalid::SlashableAttestation2Invalid(e.into())))?;
    }

    Ok(())
}

/// For a given attester slashing, return the indices able to be slashed.
///
/// Returns Ok(indices) if `indices.len() > 0`.
///
/// Spec v0.5.0
pub fn gather_attester_slashing_indices(
    state: &BeaconState,
    attester_slashing: &AttesterSlashing,
    spec: &ChainSpec,
) -> Result<Vec<u64>, Error> {
    gather_attester_slashing_indices_modular(
        state,
        attester_slashing,
        |_, validator| validator.slashed,
        spec,
    )
}

/// Same as `gather_attester_slashing_indices` but allows the caller to specify the criteria
/// for determining whether a given validator should be considered slashed.
pub fn gather_attester_slashing_indices_modular<F>(
    state: &BeaconState,
    attester_slashing: &AttesterSlashing,
    is_slashed: F,
    spec: &ChainSpec,
) -> Result<Vec<u64>, Error>
where
    F: Fn(u64, &Validator) -> bool,
{
    let slashable_attestation_1 = &attester_slashing.slashable_attestation_1;
    let slashable_attestation_2 = &attester_slashing.slashable_attestation_2;

    let mut slashable_indices = Vec::with_capacity(spec.max_indices_per_slashable_vote);
    for i in &slashable_attestation_1.validator_indices {
        let validator = state
            .validator_registry
            .get(*i as usize)
            .ok_or_else(|| Error::Invalid(Invalid::UnknownValidator(*i)))?;

        if slashable_attestation_2.validator_indices.contains(&i) & !is_slashed(*i, validator) {
            // TODO: verify that we should reject any slashable attestation which includes a
            // withdrawn validator. PH has asked the question on gitter, awaiting response.
            verify!(
                validator.withdrawable_epoch > state.slot.epoch(spec.slots_per_epoch),
                Invalid::ValidatorAlreadyWithdrawn(*i)
            );

            slashable_indices.push(*i);
        }
    }

    verify!(!slashable_indices.is_empty(), Invalid::NoSlashableIndices);

    slashable_indices.shrink_to_fit();

    Ok(slashable_indices)
}
