use super::Hash256;
use super::attestation_record::AttestationRecord;
use super::special_record::SpecialRecord;
use super::ssz::{ Encodable, SszStream };

pub const MIN_SSZ_BLOCK_LENGTH: usize = {
    8 +                 // slot
    32 +                // randao_reveal
    32 +                // pow_chain_reference
    4 +                 // ancestor hashes (assuming empty)
    32 +                // active_state_root
    32 +                // crystallized_state_root
    4 +                 // attestations (assuming empty)
    4                   // specials (assuming empty)
};
pub const MAX_SSZ_BLOCK_LENGTH: usize = MIN_SSZ_BLOCK_LENGTH + (1 << 24);

#[derive(Debug, PartialEq, Clone)]
pub struct BeaconBlock {
    pub slot: u64,
    pub randao_reveal: Hash256,
    pub pow_chain_reference: Hash256,
    pub ancestor_hashes: Vec<Hash256>,
    pub active_state_root: Hash256,
    pub crystallized_state_root: Hash256,
    pub attestations: Vec<AttestationRecord>,
    pub specials: Vec<SpecialRecord>,
}

impl BeaconBlock {
    pub fn zero() -> Self {
        Self {
            slot: 0,
            randao_reveal: Hash256::zero(),
            pow_chain_reference: Hash256::zero(),
            ancestor_hashes: vec![],
            active_state_root: Hash256::zero(),
            crystallized_state_root: Hash256::zero(),
            attestations: vec![],
            specials: vec![],
        }
    }

    /// Return a reference to `ancestor_hashes[0]`.
    ///
    /// The first hash in `ancestor_hashes` is the parent of the block.
    pub fn parent_hash(&self) -> Option<&Hash256> {
        self.ancestor_hashes.get(0)
    }
}

impl Encodable for BeaconBlock {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.randao_reveal);
        s.append(&self.pow_chain_reference);
        s.append_vec(&self.ancestor_hashes.to_vec());
        s.append(&self.active_state_root);
        s.append(&self.crystallized_state_root);
        s.append_vec(&self.attestations);
        s.append_vec(&self.specials);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_zero() {
        let b = BeaconBlock::zero();
        assert_eq!(b.slot, 0);
        assert!(b.randao_reveal.is_zero());
        assert!(b.pow_chain_reference.is_zero());
        assert_eq!(b.ancestor_hashes, vec![Hash256::zero()]);
        assert!(b.active_state_root.is_zero());
        assert!(b.crystallized_state_root.is_zero());
        assert_eq!(b.attestations.len(), 0);
        assert_eq!(b.specials.len(), 0);
    }

    #[test]
    pub fn test_block_min_ssz_length() {
        let b = BeaconBlock::zero();

        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&b);
        let ssz = ssz_stream.drain();

        assert_eq!(ssz.len(), MIN_SSZ_BLOCK_LENGTH);
    }

    #[test]
    pub fn test_block_parent_hash() {
        let mut b = BeaconBlock::zero();
        b.ancestor_hashes = vec![
            Hash256::from("cats".as_bytes()),
            Hash256::from("dogs".as_bytes()),
            Hash256::from("birds".as_bytes()),
        ];

        assert_eq!(b.parent_hash().unwrap(), &Hash256::from("cats".as_bytes()));
    }
}
