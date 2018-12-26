#[derive(Debug, PartialEq, Clone)]
pub struct ShardReassignmentRecord {
    pub validator_index: u64,
    pub shard: u64,
    pub slot: u64,
}
