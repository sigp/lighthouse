use bls::AggregatePublicKey;
use types::{Fork, SlashableVoteData};

pu fn get_fork_version(fork: Fork, slot: u64) -> u64 {
    if slot < fork.slot {
        fork.previous_version
    } else {
        fork.current_version
    }
}

pub fn get_domain(fork: Fork, slot: u64, domain_type: u64) -> u64 {
    get_fork_version(fork, slot) * u64::pow(2, 32) + domain_type
}

pub fn verify_slashable_vote_data(
    state: BeaconState,
    vote_data: SlashableVoteData,
    spec: &ChainSpec,
) -> bool {
    if (vote_data.custody_bit_0_indicies.len() + vote_data.custody_bit_1_indicies.len() > spec.max_casper_votes) {
        return false;
    }

    // Generate aggregate public key for custody bit 0 indicies
    let mut pubkeys_custody_bit_0: AggregatePublicKey = AggregatePublicKey::new();
    for i in vote_data.custody_bit_0_indicies.iter() {
         pubkeys_custody_bit_0.add(&state.validator_registry[i].pubkey);
    }

    // Generate aggregate public key for custody bit 1 indicies
    let mut pubkeys_custody_bit_1: AggregatePublicKey = AggregatePublicKey::new();
    for i in vote_data.custody_bit_1_indicies.iter() {
         pubkeys_custody_bit_1.add(&state.validator_registry[i].pubkey);
    }

    // Convert messages to hashes
    let mut messages: Vec<u8>;
    messages.append((AttestationDataAndCustodyBit {vote_data.data, false}).hash_tree_root());
    messages.append((AttestationDataAndCustodyBit {vote_data.data, true}).hash_tree_root());


    vote_data.aggregate_signature.verify_multiple (
        &messages,
        &vec![publickeys_custody_bit_0, publickeys_custody_bit_1],
        get_domain(
            state.fork,
            vote_data.data.slot,
            1, // DOMAIN_ATTESTATION
        ),
    )
}


#[cft(tests)]
mod test {
    pub fn test_TODO() {
        assert!(1 == 2);
    }
}
