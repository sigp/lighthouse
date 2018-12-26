use super::crosslink_record::CrosslinkRecord;
use super::shard_committee::ShardCommittee;
use super::validator_record::ValidatorRecord;
use super::Hash256;

#[derive(Debug, PartialEq)]
pub struct CrystallizedState {
    pub validator_set_change_slot: u64,
    pub validators: Vec<ValidatorRecord>,
    pub crosslinks: Vec<CrosslinkRecord>,
    pub last_state_recalculation_slot: u64,
    pub last_finalized_slot: u64,
    pub last_justified_slot: u64,
    pub justified_streak: u64,
    pub shard_and_committee_for_slots: Vec<Vec<ShardCommittee>>,
    pub deposits_penalized_in_period: Vec<u32>,
    pub validator_set_delta_hash_chain: Hash256,
    pub pre_fork_version: u32,
    pub post_fork_version: u32,
    pub fork_slot_number: u32,
}

impl CrystallizedState {
    // TODO: implement this.
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::zero()
    }
}
