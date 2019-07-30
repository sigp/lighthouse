use super::errors::{
    IndexedAttestationInvalid as Invalid, IndexedAttestationValidationError as Error,
};
use std::collections::HashSet;
use std::iter::FromIterator;
use tree_hash::TreeHash;
use types::*;

/// Verify an `IndexedAttestation`.
///
/// Spec v0.8.0
pub fn is_valid_indexed_attestation<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    is_valid_indexed_attestation_parametric(state, indexed_attestation, spec, true)
}

/// Verify but don't check the signature.
///
/// Spec v0.8.0
pub fn is_valid_indexed_attestation_without_signature<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    is_valid_indexed_attestation_parametric(state, indexed_attestation, spec, false)
}

/// Optionally check the signature.
///
/// Spec v0.8.0
fn is_valid_indexed_attestation_parametric<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation<T>,
    spec: &ChainSpec,
    verify_signature: bool,
) -> Result<(), Error> {
    let bit_0_indices = &indexed_attestation.custody_bit_0_indices;
    let bit_1_indices = &indexed_attestation.custody_bit_1_indices;

    // Verify no index has custody bit equal to 1 [to be removed in phase 1]
    verify!(bit_1_indices.is_empty(), Invalid::CustodyBitfieldHasSetBits);

    // Verify max number of indices
    let total_indices = bit_0_indices.len() + bit_1_indices.len();
    verify!(
        total_indices <= T::MaxValidatorsPerCommittee::to_usize(),
        Invalid::MaxIndicesExceed(T::MaxValidatorsPerCommittee::to_usize(), total_indices)
    );

    // Verify index sets are disjoint
    let custody_bit_intersection: HashSet<&u64> =
        &HashSet::from_iter(bit_0_indices.iter()) & &HashSet::from_iter(bit_1_indices.iter());
    verify!(
        custody_bit_intersection.is_empty(),
        Invalid::CustodyBitValidatorsIntersect
    );

    // Check that both vectors of indices are sorted
    let check_sorted = |list: &[u64]| -> Result<(), Error> {
        list.windows(2).enumerate().try_for_each(|(i, pair)| {
            if pair[0] >= pair[1] {
                invalid!(Invalid::BadValidatorIndicesOrdering(i));
            } else {
                Ok(())
            }
        })?;
        Ok(())
    };
    check_sorted(&bit_0_indices)?;
    check_sorted(&bit_1_indices)?;

    if verify_signature {
        is_valid_indexed_attestation_signature(state, indexed_attestation, spec)?;
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
                .validators
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
/// Spec v0.8.0
fn is_valid_indexed_attestation_signature<T: EthSpec>(
    state: &BeaconState<T>,
    indexed_attestation: &IndexedAttestation<T>,
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

    let messages = vec![&message_0[..], &message_1[..]];
    let keys = vec![&bit_0_pubkey, &bit_1_pubkey];

    let domain = spec.get_domain(
        indexed_attestation.data.target.epoch,
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
