use super::errors::{
    SlashableAttestationInvalid as Invalid, SlashableAttestationValidationError as Error,
};
use ssz::TreeHash;
use types::beacon_state::helpers::verify_bitfield_length;
use types::*;

/// Indicates if a `SlashableAttestation` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `SlashableAttestation` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.4.0
pub fn verify_slashable_attestation(
    state: &BeaconState,
    slashable_attestation: &SlashableAttestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if slashable_attestation.custody_bitfield.num_set_bits() > 0 {
        invalid!(Invalid::CustodyBitfieldHasSetBits);
    }

    if slashable_attestation.validator_indices.is_empty() {
        invalid!(Invalid::NoValidatorIndices);
    }

    for i in 0..(slashable_attestation.validator_indices.len() - 1) {
        if slashable_attestation.validator_indices[i]
            >= slashable_attestation.validator_indices[i + 1]
        {
            invalid!(Invalid::BadValidatorIndicesOrdering(i));
        }
    }

    if !verify_bitfield_length(
        &slashable_attestation.custody_bitfield,
        slashable_attestation.validator_indices.len(),
    ) {
        invalid!(Invalid::BadCustodyBitfieldLength(
            slashable_attestation.validator_indices.len(),
            slashable_attestation.custody_bitfield.len()
        ));
    }

    if slashable_attestation.validator_indices.len() > spec.max_indices_per_slashable_vote as usize
    {
        invalid!(Invalid::MaxIndicesExceed(
            spec.max_indices_per_slashable_vote as usize,
            slashable_attestation.validator_indices.len()
        ));
    }

    // TODO: this signature verification could likely be replaced with:
    //
    // super::validate_attestation::validate_attestation_signature(..)

    let mut aggregate_pubs = vec![AggregatePublicKey::new(); 2];
    let mut message_exists = vec![false; 2];

    for (i, v) in slashable_attestation.validator_indices.iter().enumerate() {
        let custody_bit = match slashable_attestation.custody_bitfield.get(i) {
            Ok(bit) => bit,
            Err(_) => unreachable!(),
        };

        message_exists[custody_bit as usize] = true;

        match state.validator_registry.get(*v as usize) {
            Some(validator) => {
                aggregate_pubs[custody_bit as usize].add(&validator.pubkey);
            }
            None => invalid!(Invalid::UnknownValidator(*v)),
        };
    }

    let message_0 = AttestationDataAndCustodyBit {
        data: slashable_attestation.data.clone(),
        custody_bit: false,
    }
    .hash_tree_root();
    let message_1 = AttestationDataAndCustodyBit {
        data: slashable_attestation.data.clone(),
        custody_bit: true,
    }
    .hash_tree_root();

    let mut messages = vec![];
    let mut keys = vec![];

    if message_exists[0] {
        messages.push(&message_0[..]);
        keys.push(&aggregate_pubs[0]);
    }
    if message_exists[1] {
        messages.push(&message_1[..]);
        keys.push(&aggregate_pubs[1]);
    }

    let domain = {
        let epoch = slashable_attestation.data.slot.epoch(spec.slots_per_epoch);
        spec.get_domain(epoch, Domain::Attestation, &state.fork)
    };

    verify!(
        slashable_attestation
            .aggregate_signature
            .verify_multiple(&messages[..], domain, &keys[..]),
        Invalid::BadSignature
    );

    Ok(())
}
