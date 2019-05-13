use super::errors::{AttesterSlashingInvalid as Invalid, AttesterSlashingValidationError as Error};
use super::verify_indexed_attestation::verify_indexed_attestation;
use types::*;

/// Indicates if an `AttesterSlashing` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `AttesterSlashing` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.5.1
pub fn verify_attester_slashing(
    state: &BeaconState,
    attester_slashing: &AttesterSlashing,
    should_verify_indexed_attestations: bool,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let indexed_attestation_1 = &attester_slashing.indexed_attestation_1;
    let indexed_attestation_2 = &attester_slashing.indexed_attestation_2;

    verify!(
        indexed_attestation_1.data != indexed_attestation_2.data,
        Invalid::AttestationDataIdentical
    );
    verify!(
        indexed_attestation_1.is_double_vote(indexed_attestation_2, spec)
            | indexed_attestation_1.is_surround_vote(indexed_attestation_2, spec),
        Invalid::NotSlashable
    );

    if should_verify_indexed_attestations {
        verify_indexed_attestation(state, &indexed_attestation_1, spec)
            .map_err(|e| Error::Invalid(Invalid::IndexedAttestation1Invalid(e.into())))?;
        verify_indexed_attestation(state, &indexed_attestation_2, spec)
            .map_err(|e| Error::Invalid(Invalid::IndexedAttestation2Invalid(e.into())))?;
    }

    Ok(())
}

/// For a given attester slashing, return the indices able to be slashed.
///
/// Returns Ok(indices) if `indices.len() > 0`.
///
/// Spec v0.5.1
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
    let indexed_attestation_1 = &attester_slashing.indexed_attestation_1;
    let indexed_attestation_2 = &attester_slashing.indexed_attestation_2;

    let mut indexed_indices = Vec::with_capacity(spec.max_indices_per_indexed_vote);
    for i in &indexed_attestation_1.validator_indices {
        let validator = state
            .validator_registry
            .get(*i as usize)
            .ok_or_else(|| Error::Invalid(Invalid::UnknownValidator(*i)))?;

        if indexed_attestation_2.validator_indices.contains(&i) & !is_slashed(*i, validator) {
            // TODO: verify that we should reject any indexed attestation which includes a
            // withdrawn validator. PH has asked the question on gitter, awaiting response.
            verify!(
                validator.withdrawable_epoch > state.slot.epoch(spec.slots_per_epoch),
                Invalid::ValidatorAlreadyWithdrawn(*i)
            );

            indexed_indices.push(*i);
        }
    }

    verify!(!indexed_indices.is_empty(), Invalid::NoSlashableIndices);

    indexed_indices.shrink_to_fit();

    Ok(indexed_indices)
}
