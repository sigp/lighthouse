use std::collections::HashMap;

use super::crystallized_state::CrystallizedState;
use super::partial_crosslink_record::PartialCrosslinkRecord;
use super::aggregate_vote::AggregateVote;
use super::config::Config;
use super::utils::types::Bitfield;
use super::utils::bls::PublicKey;
use super::crosslinks::{ 
    get_crosslink_shards, 
    get_crosslink_aggvote_msg,
    get_crosslink_notaries };

pub fn update_ffg_and_crosslink_progress(
    cry_state: &CrystallizedState,
    partial_crosslinks: &Vec<PartialCrosslinkRecord>,
    ffg_voter_bitfield: &Bitfield,
    aggregate_votes: &Vec<AggregateVote>,
    config: &Config)
    -> (Vec<PartialCrosslinkRecord>, Bitfield, usize)
{
    let mut vote_key_bitfield_map: HashMap<Vec<u8>, Bitfield> =
        HashMap::new();
    for pc in partial_crosslinks {
       vote_key_bitfield_map.insert(pc.vote_key(), pc.voter_bitfield.clone());
    }
    let mut global_bitfield = ffg_voter_bitfield.clone();
    let mut total_voters: usize = 0;
    let crosslink_shards: Vec<u16> = get_crosslink_shards(
        &cry_state, &config);

    for av in aggregate_votes {
        let attestation = get_crosslink_aggvote_msg(
            &av,
            &cry_state);
        let validator_indicies = get_crosslink_notaries(
            &cry_state,
            &av.shard_id,
            &crosslink_shards);
        let mut crosslink_bitfield = match vote_key_bitfield_map.get(&av.vote_key()) {
            None => Bitfield::new(),
            Some(existing_bitfield) => existing_bitfield.clone()
        };
        let mut public_keys: Vec<&PublicKey> = vec![];
        for (i, vi) in validator_indicies.iter().enumerate() {
            if av.notary_bitfield.get_bit(&i) {
                public_keys.push(&cry_state.active_validators[i].pubkey);
                if global_bitfield.get_bit(&vi) == false {
                    global_bitfield.set_bit(&vi, &true);
                    crosslink_bitfield.set_bit(&i, &true);
                    total_voters += 1;
                }
            }
        }
        // TODO: add bls verfification here, it is completely bypassed
        assert_eq!(attestation, attestation);   // fixes warning

        vote_key_bitfield_map.insert(av.vote_key(), crosslink_bitfield);
    }
    
    let mut new_partial_crosslinks: Vec<PartialCrosslinkRecord> = vec![];
    for (vote_key, bitfield) in vote_key_bitfield_map {
        new_partial_crosslinks.push(PartialCrosslinkRecord::new_from_vote_key(
                &vote_key,
                bitfield));
    }

    (new_partial_crosslinks, global_bitfield, total_voters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::shuffling::get_shuffling;
    use super::super::super::validator_record::ValidatorRecord;
    use super::super::super::super::utils::types::{ Sha256Digest, Bitfield };
    use super::super::super::super::utils::bls::AggregateSignature;
    
    #[test]
    fn test_update_ffg_and_crosslink_progress_scenario_1() {
        let mut cry_state = CrystallizedState::zero();
        let mut config = Config::standard();

        // Create some shard_ids and associated hashes
        let shard_ids: Vec<u16> = (0..10).collect();
        let shard_hashes: Vec<Sha256Digest> = shard_ids.iter()  
            .map(|_| Sha256Digest::random()).collect();
       
        // Define which shards with have partial crosslinks and which will
        // have aggregate votes. Note: there should be some overlap here.
        let shards_with_partial_crosslinks: Vec<u16> = shard_ids[0..5].to_vec();
        let shards_with_aggregate_votes: Vec<u16> = shard_ids[4..10].to_vec();

        // Update the config to neatly fit the shards we created. 
        config.shard_count = shard_ids.len() as u16;
        config.notaries_per_crosslink = 10;
       
        // Create just enough validators to notarise each shard
        let validator_count: usize = 
            (config.shard_count * config.notaries_per_crosslink) as usize;
       
        // Load active validators into the cry_state
        (0..validator_count).for_each(
            |_| cry_state.active_validators.push(
                ValidatorRecord::zero_with_thread_rand_pub_key()));
        
        // Set a shuffling for the validators 
        let s = get_shuffling(
            &Sha256Digest::zero(),
            &cry_state.num_active_validators(),
            &config);
        cry_state.current_shuffling = s.clone();

        // Create the required partial crosslink records 
        let partial_crosslinks: Vec<PartialCrosslinkRecord> = 
            shards_with_partial_crosslinks
            .iter()  
            .map(|i| {
                let mut bitfield = Bitfield::new();
                // Only the first 7 validators should sign the partial xlinks
                for i in 0..7 {
                    bitfield.set_bit(&i, &true);
                }
                PartialCrosslinkRecord {
                    shard_id: *i,
                    shard_block_hash: shard_hashes[*i as usize],
                    voter_bitfield: bitfield
                }
            }).collect();
        
        let mut total_aggregate_sig_votes = 0;
        let mut aggregate_sig_bitfield = Bitfield::new();

        // Create the required aggregate votes
        let aggregate_votes: Vec<AggregateVote> = shards_with_aggregate_votes
            .iter()  
            .map(|i| {
                let validator_indicies = get_crosslink_notaries(
                    &cry_state,
                    i,
                    &shard_ids);
                let mut bitfield = Bitfield::new();
                // Only the last 2 validators should sign the aggregate votes
                for i in 8..10 {
                    bitfield.set_bit(&i, &true);
                    total_aggregate_sig_votes += 1;
                    aggregate_sig_bitfield.set_bit(&validator_indicies[i], &true)
                }
                AggregateVote {
                    shard_id: *i,
                    shard_block_hash: shard_hashes[*i as usize],
                    notary_bitfield: bitfield,
                    aggregate_sig: AggregateSignature::new()
                }
            }).collect();
        assert_eq!(aggregate_votes.len(), shards_with_aggregate_votes.len(), 
                   "test setup failed.");

        let (new_partial_crosslinks, global_bitfield, vote_count) = 
            update_ffg_and_crosslink_progress(
            &cry_state,
            &partial_crosslinks,
            &Bitfield::new(),
            &aggregate_votes,
            &config);

        assert_eq!(total_aggregate_sig_votes, vote_count, 
                   "The total votes returned did not \
                   match our running tally.");
        
        assert_eq!(total_aggregate_sig_votes, 
                   global_bitfield.num_true_bits() as usize,
                   "The FFG field did not have as many true \
                   bits as expected.");

        assert!(aggregate_sig_bitfield == global_bitfield);

        for pc in new_partial_crosslinks {
            let id = pc.shard_id;
            let mut vote_count = 0;
            if shards_with_partial_crosslinks.contains(&id) {
                vote_count += 7;
            }
            if shards_with_aggregate_votes.contains(&id) {
                vote_count += 2;
            }
            assert_eq!(pc.voter_bitfield.num_true_bits(), vote_count,
                       "shard_id {} failed.", id);
            assert_eq!(pc.shard_block_hash, shard_hashes[id as usize]);
        }
    }
}
