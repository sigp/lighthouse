use super::utils::types::{ Sha256Digest, Bitfield, Blake2sDigest };
use super::utils::bls::{ Signature, AggregateSignature, Keypair, PublicKey };
use super::aggregate_vote::AggregateVote;
use super::rlp::{ RlpStream, Encodable } ;

pub struct Block {
    pub parent_hash: Sha256Digest,
    pub skip_count: u64,
    pub randao_reveal: Sha256Digest,
    pub attestation_bitfield: Bitfield,
    pub attestation_aggregate_sig: AggregateSignature,
    pub shard_aggregate_votes: Vec<AggregateVote>,
    pub main_chain_ref: Sha256Digest,
    pub state_hash: Blake2sDigest,
    pub sig: Option<Signature>
} 
impl Block {
    pub fn new(parent_hash: Sha256Digest,
               randao_reveal: Sha256Digest,
               main_chain_ref: Sha256Digest,
               state_hash: Blake2sDigest) -> Block {
        Block {
            parent_hash: parent_hash,
            skip_count: 0,
            randao_reveal: randao_reveal,
            attestation_bitfield: Vec::new(),
            attestation_aggregate_sig: AggregateSignature::new(),
            shard_aggregate_votes: Vec::new(),
            main_chain_ref: main_chain_ref,
            state_hash: state_hash,
            sig: None
        }
    }

    /*
     * Take a Block and covert it into an array of u8 for BLS signing 
     * or verfication. The `sig` field is purposefully omitted.
     */
    pub fn encode_to_signable_message(&self) -> [u8; 9140] {
        // Using biggest avg. block size from v2 spec
        let mut message: [u8; 9140] = [0; 9140];    

        // Create the RLP vector
        let mut s = RlpStream::new();
        s.append(&self.parent_hash);
        s.append(&self.skip_count);
        s.append(&self.randao_reveal);
        s.append(&self.attestation_bitfield);
        // TODO: represent attestation_aggregate_sig
        // TODO: represent shard_aggregate_votes
        s.append(&self.main_chain_ref);
        s.append(&self.state_hash);
        let rlp_vec = s.out();

        // Parse the RLP vector into an array compatible with the BLS signer
        let len = rlp_vec.len();
        message[..len].copy_from_slice(&rlp_vec[..len]);
        message
    }
    
    /*
     * Sign the block with the given keypair.
     */
    pub fn sig_sign(&mut self, keypair: &Keypair) {
        let message = self.encode_to_signable_message();
        self.sig = Some(keypair.sign(&message));
    }
   
    /*
     * Verify a block signature given some keypair.
     */
    pub fn sig_verify(&self, pub_key: &PublicKey) -> bool {
        let message = self.encode_to_signable_message();
        match &self.sig {
            None => false,
            Some(sig) => {
                pub_key.verify(&message, &sig)
            },
        }
    }
}

impl Encodable for Block {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.parent_hash);
        s.append(&self.skip_count);
        s.append(&self.randao_reveal);
        s.append(&self.attestation_bitfield);
        // TODO: represent attestation_aggregate_sig
        // TODO: represent shard_aggregate_votes
        s.append(&self.main_chain_ref);
        s.append(&self.state_hash);
        // TODO: represent sig
    }
}


#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;
    use self::rand::{ SeedableRng, XorShiftRng };

    #[test]
    fn test_new_for_parent_hash() {
        let parent_hash = Sha256Digest::random();
        let randao_reveal = Sha256Digest::random();
        let main_chain_ref = Sha256Digest::random();
        let state_hash = Sha256Digest::random();
        let b = Block::new(parent_hash,
                           randao_reveal,
                           main_chain_ref,
                           state_hash);
        assert_eq!(b.parent_hash, parent_hash);
        assert_eq!(b.randao_reveal, randao_reveal);
        assert_eq!(b.main_chain_ref, main_chain_ref);
        assert_eq!(b.state_hash, state_hash);
    }
    
    #[test]
    fn test_signable_message_encoding() {
        let parent_hash = Sha256Digest::from([0; 32]);
        let randao_reveal = Sha256Digest::from([1; 32]);
        let main_chain_ref = Sha256Digest::from([2; 32]);
        let state_hash = Sha256Digest::from([3; 32]);
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
                           Sha256Digest::random());

        // Both signatures fail before signing
        assert_eq!(b.sig_verify(&alice_keypair.public), false);
        assert_eq!(b.sig_verify(&bob_keypair.public), false);

        // Sign as Alice
        b.sig_sign(&alice_keypair);

        // Alice signature passes, bobs fails
        assert_eq!(b.sig_verify(&alice_keypair.public), true);
        assert_eq!(b.sig_verify(&bob_keypair.public), false);
    }
}
