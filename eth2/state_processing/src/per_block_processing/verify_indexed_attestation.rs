use super::errors::{
    IndexedAttestationInvalid as Invalid, IndexedAttestationValidationError as Error,
};
use std::collections::HashSet;
use std::iter::FromIterator;
use tree_hash::TreeHash;
use types::*;

/// Verify an `IndexedAttestation`.
///
/// Spec v0.6.3
pub fn verify_indexed_attestation<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify_indexed_attestation_parametric(state, indexed_attestation, spec, true)
}

/// Verify but don't check the signature.
///
/// Spec v0.6.3
pub fn verify_indexed_attestation_without_signature<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify_indexed_attestation_parametric(state, indexed_attestation, spec, false)
}

/// Optionally check the signature.
///
/// Spec v0.6.3
fn verify_indexed_attestation_parametric<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation,
    spec: &ChainSpec,
    verify_signature: bool,
) -> Result<(), Error> {
    let custody_bit_0_indices = &indexed_attestation.custody_bit_0_indices;
    let custody_bit_1_indices = &indexed_attestation.custody_bit_1_indices;

    // Ensure no duplicate indices across custody bits
    let custody_bit_intersection: HashSet<&u64> =
        &HashSet::from_iter(custody_bit_0_indices) & &HashSet::from_iter(custody_bit_1_indices);
    verify!(
        custody_bit_intersection.is_empty(),
        Invalid::CustodyBitValidatorsIntersect
    );

    // Check that nobody signed with custody bit 1 (to be removed in phase 1)
    if !custody_bit_1_indices.is_empty() {
        invalid!(Invalid::CustodyBitfieldHasSetBits);
    }

    let total_indices = custody_bit_0_indices.len() + custody_bit_1_indices.len();
    verify!(1 <= total_indices, Invalid::NoValidatorIndices);
    verify!(
        total_indices as u64 <= spec.max_indices_per_attestation,
        Invalid::MaxIndicesExceed(spec.max_indices_per_attestation, total_indices)
    );

    // Check that both vectors of indices are sorted
    let check_sorted = |list: &Vec<u64>| {
        list.windows(2).enumerate().try_for_each(|(i, pair)| {
            if pair[0] >= pair[1] {
                invalid!(Invalid::BadValidatorIndicesOrdering(i));
            } else {
                Ok(())
            }
        })?;
        Ok(())
    };
    check_sorted(custody_bit_0_indices)?;
    check_sorted(custody_bit_1_indices)?;

    if verify_signature {
        verify_indexed_attestation_signature(state, indexed_attestation, spec)?;
    }

    Ok(())
}

/// Create an aggregate public key for a list of validators, failing if any key can't be found.
fn create_aggregate_pubkey<'a, T, I>(
    state: &BeaconState<T>,
    validator_indices: I,
) -> Result<AggregatePublicKey, Error>
where
    I: IntoIterator<Item = &'a u64>,
    T: EthSpec,
{
    validator_indices.into_iter().try_fold(
        AggregatePublicKey::new(),
        |mut aggregate_pubkey, &validator_idx| {
            state
                .validator_registry
                .get(validator_idx as usize)
                .ok_or_else(|| Error::Invalid(Invalid::UnknownValidator(validator_idx)))
                .map(|validator| {
                    aggregate_pubkey.add(&validator.pubkey);
                    aggregate_pubkey
                })
        },
    )
}

/// Verify the signature of an IndexedAttestation.
///
/// Spec v0.6.3
fn verify_indexed_attestation_signature<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let bit_0_pubkey = create_aggregate_pubkey(state, &indexed_attestation.custody_bit_0_indices)?;
    let bit_1_pubkey = create_aggregate_pubkey(state, &indexed_attestation.custody_bit_1_indices)?;

    let message_0 = AttestationDataAndCustodyBit {
        data: indexed_attestation.data.clone(),
        custody_bit: false,
    }
    .tree_hash_root();
    let message_1 = AttestationDataAndCustodyBit {
        data: indexed_attestation.data.clone(),
        custody_bit: true,
    }
    .tree_hash_root();

    let mut messages = vec![];
    let mut keys = vec![];

    if !indexed_attestation.custody_bit_0_indices.is_empty() {
        messages.push(&message_0[..]);
        keys.push(&bit_0_pubkey);
    }
    if !indexed_attestation.custody_bit_1_indices.is_empty() {
        messages.push(&message_1[..]);
        keys.push(&bit_1_pubkey);
    }

    let domain = spec.get_domain(
        indexed_attestation.data.target_epoch,
        Domain::Attestation,
        &state.fork,
    );

    verify!(
        indexed_attestation
            .signature
            .verify_multiple(&messages[..], domain, &keys[..]),
        Invalid::BadSignature
    );

    Ok(())
}
