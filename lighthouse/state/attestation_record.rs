use super::utils::types::{ Hash256, Bitfield };
use super::utils::bls::{ AggregateSignature };
use super::ssz::{ Encodable, SszStream };


pub struct AttestationRecord {
    pub slot: u64,
    pub shard_id: u16,
    pub oblique_parent_hashes: Vec<Hash256>,
    pub shard_block_hash: Hash256,
    pub attester_bitfield: Bitfield,
    pub aggregate_sig: Option<AggregateSignature>,
}

impl Encodable for AttestationRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.shard_id);
        s.append_vec(&self.oblique_parent_hashes);
        s.append(&self.shard_block_hash);
        s.append_vec(&self.attester_bitfield.to_be_vec());
        // TODO: encode the aggregate sig correctly
        s.append_vec(&vec![0_u8; 64])
    }
}

impl AttestationRecord {
    pub fn zero() -> Self {
        Self {
            slot: 0,
            shard_id: 0,
            oblique_parent_hashes: vec![],
            shard_block_hash: Hash256::zero(),
            attester_bitfield: Bitfield::new(),
            aggregate_sig: None,
        }
    }
}
