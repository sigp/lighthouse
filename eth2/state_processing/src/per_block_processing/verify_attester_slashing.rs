use super::errors::{AttesterSlashingInvalid as Invalid, AttesterSlashingValidationError as Error};
use super::verify_indexed_attestation::verify_indexed_attestation;
use std::collections::BTreeSet;
use types::*;

/// Indicates if an `AttesterSlashing` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `AttesterSlashing` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.6.1
pub fn verify_attester_slashing<T: EthSpec>(
    state: &BeaconState<T>,
    attester_slashing: &AttesterSlashing,
    should_verify_indexed_attestations: bool,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;

    // Spec: is_slashable_attestation_data
    verify!(
        attestation_1.is_double_vote(attestation_2)
            || attestation_1.is_surround_vote(attestation_2),
        Invalid::NotSlashable
    );

    if should_verify_indexed_attestations {
        verify_indexed_attestation(state, &attestation_1, spec)
            .map_err(|e| Error::Invalid(Invalid::IndexedAttestation1Invalid(e.into())))?;
        verify_indexed_attestation(state, &attestation_2, spec)
            .map_err(|e| Error::Invalid(Invalid::IndexedAttestation2Invalid(e.into())))?;
    }

    Ok(())
}

/// For a given attester slashing, return the indices able to be slashed in ascending order.
///
/// Returns Ok(indices) if `indices.len() > 0`.
///
/// Spec v0.6.1
pub fn get_slashable_indices<T: EthSpec>(
    state: &BeaconState<T>,
    attester_slashing: &AttesterSlashing,
) -> Result<Vec<u64>, Error> {
    get_slashable_indices_modular(state, attester_slashing, |_, validator| {
        validator.is_slashable_at(state.current_epoch())
    })
}

/// Same as `gather_attester_slashing_indices` but allows the caller to specify the criteria
/// for determining whether a given validator should be considered slashable.
pub fn get_slashable_indices_modular<F, T: EthSpec>(
    state: &BeaconState<T>,
    attester_slashing: &AttesterSlashing,
    is_slashable: F,
) -> Result<Vec<u64>, Error>
where
    F: Fn(u64, &Validator) -> bool,
{
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;

    let attesting_indices_1 = attestation_1
        .custody_bit_0_indices
        .iter()
        .chain(&attestation_1.custody_bit_1_indices)
        .cloned()
        .collect::<BTreeSet<_>>();
    let attesting_indices_2 = attestation_2
        .custody_bit_0_indices
        .iter()
        .chain(&attestation_2.custody_bit_1_indices)
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut slashable_indices = vec![];

    for index in &attesting_indices_1 & &attesting_indices_2 {
        let validator = state
            .validator_registry
            .get(index as usize)
            .ok_or_else(|| Error::Invalid(Invalid::UnknownValidator(index)))?;

        if is_slashable(index, validator) {
            slashable_indices.push(index);
        }
    }

    verify!(!slashable_indices.is_empty(), Invalid::NoSlashableIndices);

    Ok(slashable_indices)
}
