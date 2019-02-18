use bls::AggregatePublicKey;
use ssz::TreeHash;
use types::{AttestationDataAndCustodyBit, BeaconState, Bitfield, ChainSpec, SlashableAttestation};

/// Verify `bitfield` against the `committee_size`.
pub fn verify_bitfield(bitfield: &Bitfield, committee_size: u64) -> bool {
    // Bitfield does not have padding
    if bitfield.len() as u64 != committee_size {
        return false
    }
    true
}

/// Verify validity of `slashable_attestation` fields.
pub fn verify_slashable_attestation(
    state: &BeaconState,
    slashable_attestation: &SlashableAttestation,
    spec: &ChainSpec,
) -> bool {

    if slashable_attestation.custody_bitfield.num_set_bits() > 0 {
        // To be removed in stage 1
        return false;
    }

    if slashable_attestation.validator_indices.is_empty() {
        return false
    }

    for i in 0..(slashable_attestation.validator_indices.len() - 1) {
        if slashable_attestation.validator_indices[i] >= slashable_attestation.validator_indices[i + 1] {
            return false
        }
    }

    if !verify_bitfield(&slashable_attestation.custody_bitfield, slashable_attestation.validator_indices.len() as u64) {
        return false
    }


    if slashable_attestation.validator_indices.len() as u64 > spec.max_indices_per_slashable_vote {
        return false;
    }

    // Generate aggregate public keys
    let mut pubkeys_custody_bit_0: AggregatePublicKey = AggregatePublicKey::new();
    let mut pubkeys_custody_bit_1: AggregatePublicKey = AggregatePublicKey::new();
    for (i, validator_index) in slashable_attestation.validator_indices.iter().enumerate() {

        match slashable_attestation.custody_bitfield.get(i) {
            Ok(true) => pubkeys_custody_bit_1.add(&state.validator_registry[*validator_index as usize].pubkey.as_raw()),
            Ok(false) => pubkeys_custody_bit_0.add(&state.validator_registry[*validator_index as usize].pubkey.as_raw()),
            Err(_) => return false, // TODO: check this isn't reached
        }
    }

    // Convert messages to hashes
    let mut messages: Vec<u8> = vec![];
    messages.append(&mut (AttestationDataAndCustodyBit {data: slashable_attestation.data.clone(), custody_bit: false}).hash_tree_root());
    messages.append(&mut (AttestationDataAndCustodyBit {data: slashable_attestation.data.clone(), custody_bit: true}).hash_tree_root());

    slashable_attestation.aggregate_signature.verify_multiple (
        &messages,
        state.fork.get_domain(
            slashable_attestation.data.slot.epoch(spec.epoch_length),
            spec.domain_attestation,
        ),
        &[pubkeys_custody_bit_0, pubkeys_custody_bit_1],
    )
}


#[cfg(tests)]
mod test {
    pub fn test_TODO() {
        assert!(1 == 2);
    }
}
