use super::utils::types::{ Hash256, Bitfield };
use super::utils::bls::{ AggregateSignature };


#[derive(Clone)]
pub struct AttestationRecord {
    slot: u64,
    shard_id: u16,
    oblique_parent_hashes: Vec<Hash256>,
    shard_block_hash: Hash256,
    attester_bitfield: Bitfield,
    aggregate_sig: Option<AggregateSignature>,
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
