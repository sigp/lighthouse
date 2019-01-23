use bls::AggregatePublicKey;
use types::SlashableVoteData;

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
   
    vote_data.aggregate_signature.verify_multiple (
        // parse messages, https://github.com/sigp/lighthouse/issues/70
        &vec![publickeys_custody_bit_0, publickeys_custody_bit_1], 
        // parse domain, https://github.com/sigp/lighthouse/issues/91
        // For domain likely just add 8 bytes to message
    )
}


#[cft(tests)]
mod test {
    pub fn test_TODO() {
        assert!(1 == 2);
    }
}
