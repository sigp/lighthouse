use super::Hash256;

#[derive(Debug, Clone, PartialEq)]
pub struct AttestationData {
    pub slot: u64,
    pub shard: u64,
    pub beacon_block_hash: Hash256,
    pub epoch_boundary_hash: Hash256,
    pub shard_block_hash: Hash256,
    pub latest_crosslink_hash: Hash256,
    pub justified_slot: u64,
    pub justified_block_hash: Hash256,
}
