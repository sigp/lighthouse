use super::validator_record::ValidatorRecord;
use super::utils::types::Bitfield;
use super::utils::bls::{ AggregateSignature, PublicKey };
use super::crystallized_state::CrystallizedState;
use super::active_state::ActiveState;
use super::config::Config;
use super::shuffling::get_shuffling;

pub fn process_recent_attesters(
    cry_state: &CrystallizedState,
    recent_attesters: &Vec<usize>,
    config: &Config)
    -> Vec<i64>
{
    let mut deltas: Vec<i64> = vec![0; cry_state.num_active_validators()];
    for v in recent_attesters {
        deltas[*v] += config.attester_reward;
    }
    deltas
}

// For a given state set and skip_count, return a proposer and set
// of attestors.
pub fn get_attesters_and_proposer(
    cry_state: &CrystallizedState,
    act_state: &ActiveState,
    skip_count: &u64,
    config: &Config)
    -> (Vec<usize>, usize)
{
    let active_validator_count = cry_state.num_active_validators(); 
    assert!(active_validator_count >= 2, "must be >=2 active validators");
    let shuffled_validator_indicies = get_shuffling(
        &act_state.randao,
        &active_validator_count,
        config);
    let proposer_count: usize = 1;
    let ideal_validator_count: usize = (config.attester_count as usize)
        + (*skip_count as usize) + proposer_count;
    assert!(ideal_validator_count >= 2, 
            "ideal_validator_count must be >=2");
    if ideal_validator_count > active_validator_count {
        return (
            shuffled_validator_indicies[0..active_validator_count - 1].to_vec(),
            shuffled_validator_indicies[active_validator_count - 1]);
    } else {
        return (
            shuffled_validator_indicies[0..ideal_validator_count - 1].to_vec(),
            shuffled_validator_indicies[ideal_validator_count - 1]);
    }
}

#[allow(unused_variables)]
pub fn process_attestations(
    validators: &Vec<ValidatorRecord>,
    attestation_indicies: &Vec<usize>,
    attestation_bitfield: &Bitfield,
    msg: &Vec<u8>,
    aggregate_sig: &AggregateSignature)
    -> Option<Vec<usize>>
{
    let mut key_msg_tuples: Vec<(&PublicKey, &[u8])> = vec![];
    let mut attesters: Vec<usize> = vec![];

    assert_eq!(attestation_indicies.len(), attestation_bitfield.len());
    for (bitfield_bit, validators_index) in attestation_indicies.iter().enumerate() {
        if attestation_bitfield.get_bit(&bitfield_bit) {
            key_msg_tuples.push(
                (&validators[*validators_index].pubkey,
                &msg)
                );
            attesters.push(*validators_index);
        }
    }
    // TODO: figure out why this assert exists in the Python impl.
    assert!(attesters.len() <= 128, "Max attesters is 128.");
    
    /*
    // TODO: ensure signature verification actually takes place.
    // It is completely bypassed here.
    match aggregate_sig.verify(&key_msg_tuples) {
        false => None,
        true => Some(attesters)
    }
    */
    Some(attesters)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_process_recent_attesters() {
        let mut cry_state = CrystallizedState::zero();
        let mut config = Config::standard();
        let validator_count = 20;

        config.attester_reward = 12;

        let mut recent_attesters: Vec<usize> = vec![];

        for i in 0..validator_count {
            cry_state.active_validators
                .push(ValidatorRecord::zero_with_thread_rand_pub_key());
            if i % 2 == 0 {
                recent_attesters.push(i);
            }
        }

        let d = process_recent_attesters(
            &cry_state,
            &recent_attesters,
            &config);

        for i in 0..validator_count {
            if i % 2 == 0 {
                assert_eq!(d[i], config.attester_reward);
            } else {
                assert_eq!(d[i], 0);
            }
        }
    }

    #[test]
    fn test_attester_and_proposer_selection() {
        let mut cry_state = CrystallizedState::zero();
        
        (0..10).for_each(
            |_| cry_state.active_validators.push(
                ValidatorRecord::zero_with_thread_rand_pub_key()));

        let act_state = ActiveState::zero();
        let (attestors, proposer) = get_attesters_and_proposer(
            &cry_state,
            &act_state,
            &0,
            &Config::standard());
        assert_eq!(attestors, [0, 9, 7, 6, 4, 1, 8, 5, 2]);
        assert_eq!(proposer, 3);
    }

    #[test]
    #[should_panic(expected = "must be >=2 active validators")]
    fn test_attester_and_proposer_selection_with_zero_active_validators() {
        let mut cry_state = CrystallizedState::zero();
        cry_state.active_validators = Vec::new();
        let act_state = ActiveState::zero();
        let (_attestors, _proposer) = get_attesters_and_proposer(
            &cry_state,
            &act_state,
            &0,
            &Config::standard());
    }

    #[test]
    fn test_attestation_processing() {
        let validator_count = 10;
        let mut validators: Vec<ValidatorRecord> = vec![];
        let mut attestation_indicies: Vec<usize> = vec![];
        let mut bitfield = Bitfield::new();
        let mut agg_sig = AggregateSignature::new();
        let msg = "Message that's longer than 16 chars".as_bytes();
        
        for i in 0..validator_count {
            let (v, keypair) = 
                ValidatorRecord::zero_with_thread_rand_keypair();
            validators.push(v);
            attestation_indicies.push(i);
            bitfield.set_bit(&i, &true);
            let sig = keypair.sign(&msg);
            agg_sig.aggregate(&sig);
        }

        let result = process_attestations(
            &validators,
            &attestation_indicies,
            &bitfield,
            &msg.to_vec(),
            &agg_sig);

        match result {
            None => panic!("Verification failed."),
            Some(x) => println!("{:?}", x)
        };
    }
}

