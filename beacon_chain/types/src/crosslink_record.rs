use super::Hash256;

#[derive(Clone, Debug, PartialEq)]
pub struct CrosslinkRecord {
    pub slot: u64,
    pub shard_block_root: Hash256,
}

impl CrosslinkRecord {
    /// Generates a new instance where `dynasty` and `hash` are both zero.
    pub fn zero() -> Self {
        Self {
            slot: 0,
            shard_block_root: Hash256::zero(),
        }
    }
}
