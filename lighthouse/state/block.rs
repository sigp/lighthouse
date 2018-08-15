use super::utils::types::Hash256;
use super::attestation_record::AttestationRecord;
use super::ssz;

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

    // Not sure if this will be useful, leaving it here for the
    // time being.
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
}
