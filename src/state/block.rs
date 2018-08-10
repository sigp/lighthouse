use super::utils::types::Hash256;
use super::utils::bls::{ Signature, AggregateSignature, Keypair, PublicKey };
use super::attestation_record::AttestationRecord;
use super::ssz;

use std::hash::{ Hash, Hasher };

const SSZ_BLOCK_LENGTH: usize = 192;

pub struct Block {
    pub parent_hash: Hash256,
    pub slot_number: u64,
    pub randao_reveal: Hash256,
    pub attestations: Vec<AttestationRecord>,
    pub pow_chain_ref: Hash256,
    pub active_state_root: Hash256,
    pub crystallized_state_root: Hash256,
} 

impl Block {
    pub fn zero() -> Self {
        Self {
            parent_hash: Hash256::zero(),
            slot_number: 0,
            randao_reveal: Hash256::zero(),
            attestations: vec![],
            pow_chain_ref: Hash256::zero(),
            active_state_root: Hash256::zero(),
            crystallized_state_root: Hash256::zero(),
        }
    }

    /// Returns a Vec<u8> 
    pub fn ssz_encode_without_attestations(&self) 
        -> [u8; SSZ_BLOCK_LENGTH]
    {
        let mut s = ssz::SszStream::new();
        s.append(&self.parent_hash);
        s.append(&self.slot_number);
        s.append(&self.randao_reveal);
        s.append(&self.pow_chain_ref);
        s.append(&self.active_state_root);
        s.append(&self.crystallized_state_root);
        let vec = s.drain();
        let mut encoded = [0; SSZ_BLOCK_LENGTH];
        encoded.copy_from_slice(&vec); encoded
    }
}

impl Hash for Block {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let bytes = self.ssz_encode_without_attestations();
        bytes.hash(state);
    }
}


#[cfg(test)]
mod tests {
    use super::super::rlp;
    extern crate rand;

    use super::*;
    use self::rand::{ SeedableRng, XorShiftRng };
    
    #[test]
    fn test_signable_message_encoding() {
        let parent_hash = Sha256Digest::from([0; 32]);
        let randao_reveal = Sha256Digest::from([1; 32]);
        let main_chain_ref = Sha256Digest::from([2; 32]);
        let state_hash = StateHash::zero();
        let mut b = Block::new(parent_hash,
                           randao_reveal,
                           main_chain_ref,
                           state_hash);
        b.skip_count = 2;
        let output = b.encode_to_signable_message();
        // TODO: test this better
        assert_eq!(output[0], 160);
        assert_eq!(output[1..21], [0; 20]);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let alice_keypair = Keypair::generate(&mut rng);
        let bob_keypair = Keypair::generate(&mut rng);
        let mut b = Block::new(Sha256Digest::random(),
                           Sha256Digest::random(),
                           Sha256Digest::random(),
                           StateHash::zero());

        // Both signatures fail before signing
        assert_eq!(b.sig_verify(&alice_keypair.public), false);
        assert_eq!(b.sig_verify(&bob_keypair.public), false);

        // Sign as Alice
        b.sig_sign(&alice_keypair);

        // Alice signature passes, bobs fails
        assert_eq!(b.sig_verify(&alice_keypair.public), true);
        assert_eq!(b.sig_verify(&bob_keypair.public), false);
    }
    
    #[test]
    fn test_ssz_serialization() {
        let b = Block {
            parent_hash: Sha256Digest::zero(),
            skip_count: 100,
            randao_reveal: Sha256Digest::zero(),
            attestation_bitfield: Bitfield::new(),
            attestation_aggregate_sig: AggregateSignature::new(),
            shard_aggregate_votes: Vec::new(),
            main_chain_ref: Sha256Digest::zero(),
            state_hash: StateHash::zero(),
            sig: None
        };
        let e = rlp::encode(&b);
        assert_eq!(e.len(), 168);
        assert_eq!(e[0], 160);
        assert_eq!(e[1..33], [0; 32]);
        assert_eq!(e[33], 100);
        assert_eq!(e[34], 160);
        assert_eq!(e[35..67], [0; 32]);
        assert_eq!(e[67], 128);
        assert_eq!(e[69], 160);
        assert_eq!(e[70..102], [0; 32]);
        /*
        assert_eq!(e[102], 248);
        assert_eq!(e[103], 64);
        assert_eq!(e[104..136], [128; 32]);
        assert_eq!(e[136..168], [128; 32]);
        */
    }
}
