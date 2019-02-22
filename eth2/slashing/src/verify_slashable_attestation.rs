use bls::AggregatePublicKey;
use ssz::TreeHash;
use types::{AttestationDataAndCustodyBit, BeaconState, Bitfield, ChainSpec, SlashableAttestation};

/// Verify `bitfield` against the `committee_size`.
pub fn verify_bitfield(bitfield: &Bitfield, committee_size: u64) -> bool {
    // Bitfield does not have padding
    if bitfield.len() as u64 != committee_size {
        return false;
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
        return false;
    }

    for i in 0..(slashable_attestation.validator_indices.len() - 1) {
        if slashable_attestation.validator_indices[i]
            >= slashable_attestation.validator_indices[i + 1]
        {
            return false;
        }
    }

    if !verify_bitfield(
        &slashable_attestation.custody_bitfield,
        slashable_attestation.validator_indices.len() as u64,
    ) {
        return false;
    }

    if slashable_attestation.validator_indices.len() as u64 > spec.max_indices_per_slashable_vote {
        return false;
    }

    // Generate aggregate public keys
    let mut pubkeys_custody_bit_0: AggregatePublicKey = AggregatePublicKey::new();
    let mut pubkeys_custody_bit_1: AggregatePublicKey = AggregatePublicKey::new();
    for (i, validator_index) in slashable_attestation.validator_indices.iter().enumerate() {
        match slashable_attestation.custody_bitfield.get(i) {
            Ok(true) => pubkeys_custody_bit_1.add(
                &state.validator_registry[*validator_index as usize]
                    .pubkey
                    .as_raw(),
            ),
            Ok(false) => pubkeys_custody_bit_0.add(
                &state.validator_registry[*validator_index as usize]
                    .pubkey
                    .as_raw(),
            ),
            Err(_) => return false,
        }
    }

    // Convert messages to hashes
    let mut messages: Vec<u8> = vec![];
    messages.append(
        &mut (AttestationDataAndCustodyBit {
            data: slashable_attestation.data.clone(),
            custody_bit: false,
        })
        .hash_tree_root(),
    );
    messages.append(
        &mut (AttestationDataAndCustodyBit {
            data: slashable_attestation.data.clone(),
            custody_bit: true,
        })
        .hash_tree_root(),
    );

    // Verify signatures and votes
    slashable_attestation.aggregate_signature.verify_multiple(
        &messages,
        //state.fork.get_domain(
        //    slashable_attestation.data.slot.epoch(spec.epoch_length),
        spec.domain_attestation,
        //),
        &[pubkeys_custody_bit_0, pubkeys_custody_bit_1],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::SecretKey;
    use types::{AttestationData, AggregateSignature, test_utils::BeaconStateTestBuilder, Crosslink, Signature};

    #[test]
    pub fn test_verify_slashable_attestation() {
        let builder = BeaconStateTestBuilder::with_random_validators(3);
        let validator_keys = builder.keypairs.clone();
        let spec = builder.spec.clone();
        let state = builder.build().unwrap();

        // SlashableAttestation fields
        let validator_indices: Vec<u64> = vec![0, 1, 2];
        let data = AttestationData {
            slot: state.slot,
            shard: 1,
            beacon_block_root: spec.zero_hash,
            epoch_boundary_root: spec.zero_hash,
            shard_block_root: spec.zero_hash,
            latest_crosslink: Crosslink{
                epoch: spec.genesis_epoch,
                shard_block_root: spec.zero_hash,
            },
            justified_epoch: state.justified_epoch,
            justified_block_root: spec.zero_hash,
        };
        let attestation_data_and_false = AttestationDataAndCustodyBit {
            data: data.clone(),
            custody_bit: false
        };
        let custody_bitfield = Bitfield::with_capacity(validator_indices.len());
        let mut aggregate_signature = AggregateSignature::new();
        // Signature for custody bitfield 0 indices
        for validator_index in validator_indices.iter() {
            let sig = Signature::new(
                &attestation_data_and_false.hash_tree_root(),
                spec.domain_attestation,
                &validator_keys[*validator_index as usize].sk
            );
            aggregate_signature.add(&sig);
        }

        // Signature for custody bit 1 indices
        let attestation_data_and_true = AttestationDataAndCustodyBit {
            data: data.clone(),
            custody_bit: true
        };
        let mut sk: Vec<u8> = vec![0;48];
        sk[47] += 1;
        let sk = SecretKey::from_bytes(&sk).unwrap();
        let sig = Signature::new(
            &attestation_data_and_true.hash_tree_root(),
            spec.domain_attestation,
            &sk,
        );
        aggregate_signature.add(&sig);

        // Verify Slashable attestation
        let slashable_attestation = SlashableAttestation {
            validator_indices,
            data,
            custody_bitfield,
            aggregate_signature,
        };

        // Note should pass but fails due to bug in spec
        assert!(verify_slashable_attestation(&state, &slashable_attestation, &spec));
    }
}
