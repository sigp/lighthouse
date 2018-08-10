use super::validator_record::ValidatorRecord;
use super::crosslink_record::CrosslinkRecord;
use super::shard_and_committee::ShardAndCommittee;
use super::ethereum_types::U256;
use super::utils::types::{ Hash256 };


#[derive(Clone)]
pub struct CrystallizedState {
    pub validators: Vec<ValidatorRecord>,
    pub epoch_number: u64,
    pub indicies_for_heights: Vec<ShardAndCommittee>,
    pub last_justified_slot: u64,
    pub justified_streak: u16,
    pub last_finalized_slot: u64,
    pub current_dynasty: u64,
    pub crosslinking_shard_start: u16,
    pub crosslink_records: Vec<CrosslinkRecord>,
    pub total_deposits: U256,
    pub dynasty_seed: Hash256,
    pub dynasty_seed_last_reset: u64,
}

impl CrystallizedState {
    /// Returns a new instance where all fields are either zero or an
    /// empty vector.
    pub fn zero() -> Self {
        Self {
            validators: vec![],
            epoch_number: 0,
            indicies_for_heights: vec![],
            last_justified_slot: 0,
            justified_streak: 0,
            last_finalized_slot: 0,
            current_dynasty: 0,
            crosslinking_shard_start: 0,
            crosslink_records: vec![],
            total_deposits: U256::zero(),
            dynasty_seed: Hash256::zero(),
            dynasty_seed_last_reset: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cry_state_zero() {
        let c = CrystallizedState::zero();
        assert_eq!(c.validators.len(), 0);
        assert_eq!(c.epoch_number, 0);
        assert_eq!(c.indicies_for_heights.len(), 0);
        assert_eq!(c.last_justified_slot, 0);
        assert_eq!(c.justified_streak, 0);
        assert_eq!(c.last_finalized_slot, 0);
        assert_eq!(c.current_dynasty, 0);
        assert_eq!(c.crosslinking_shard_start, 0);
        assert_eq!(c.crosslink_records.len(), 0);
        assert!(c.total_deposits.is_zero());
        assert!(c.dynasty_seed.is_zero());
        assert_eq!(c.dynasty_seed_last_reset, 0);
    }

}
