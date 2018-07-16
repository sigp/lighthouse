use super::validator_record::ValidatorRecord;
use super::utils::types::Bitfield;
use super::utils::bls::{ AggregateSignature, PublicKey };

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

