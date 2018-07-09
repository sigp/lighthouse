use super::utils::types::Sha256Digest;
use super::validator_record::ValidatorRecord;
use super::crosslink_record::CrosslinkRecord;
use super::ethereum_types::U256;

pub struct CrystallizedState {
    pub active_validators: Vec<ValidatorRecord>,
    pub queued_validators: Vec<ValidatorRecord>,
    pub exited_validators: Vec<ValidatorRecord>,
    pub current_shuffling: Vec<u32>,  // TODO: should be u24
    pub current_epoch: u64,
    pub last_justified_epoch: u64,
    pub last_finalized_epoch: u64,
    pub dynasty: u64,
    pub next_shard: u16,
    pub current_checkpoint: Sha256Digest,
    pub crosslink_records: Vec<CrosslinkRecord>,
    pub total_deposits: U256,
}

impl CrystallizedState {
    pub fn num_active_validators(&self) -> usize {
        self.active_validators.len()
    }

    pub fn num_queued_validators(&self) -> usize {
        self.queued_validators.len()
    }

    pub fn num_exited_validators(&self) -> usize {
        self.exited_validators.len()
    }

    pub fn num_crosslink_records(&self) -> usize {
        self.crosslink_records.len()

    }
}
