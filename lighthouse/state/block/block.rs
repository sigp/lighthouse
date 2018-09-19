use super::utils::types::Hash256;
use super::attestation_record::{
    AttestationRecord,
    MIN_SSZ_ATTESTION_RECORD_LENGTH,
};
use super::ssz::{ Encodable, SszStream };

pub const MIN_SSZ_BLOCK_LENGTH: usize = {
    4 + 32 +    // parent_hash
    8 +     // slot_number
    4 + 32 +    // randao_reveal
    4 + MIN_SSZ_ATTESTION_RECORD_LENGTH +  // attestations (minimum one)
    4 + 32 +    // pow_chain_ref
    4 + 32 +    // active_state_root
    4 + 32      // crystallized_state_root
};
pub const MAX_SSZ_BLOCK_LENGTH: usize = MIN_SSZ_BLOCK_LENGTH + (1 << 24);

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
}

impl Encodable for Block {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.parent_hash);
        s.append(&self.slot_number);
        s.append(&self.randao_reveal);
        s.append_vec(&self.attestations);
        s.append(&self.pow_chain_ref);
        s.append(&self.active_state_root);
        s.append(&self.crystallized_state_root);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_zero() {
        let b = Block::zero();
        assert!(b.parent_hash.is_zero());
        assert_eq!(b.slot_number, 0);
        assert!(b.randao_reveal.is_zero());
        assert_eq!(b.attestations.len(), 0);
        assert!(b.pow_chain_ref.is_zero());
        assert!(b.active_state_root.is_zero());
        assert!(b.crystallized_state_root.is_zero());
    }

    #[test]
    pub fn test_block_min_ssz_length() {
        let mut b = Block::zero();
        b.attestations = vec![AttestationRecord::zero()];

        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&b);
        let ssz = ssz_stream.drain();

        assert_eq!(ssz.len(), MIN_SSZ_BLOCK_LENGTH);
    }
}
