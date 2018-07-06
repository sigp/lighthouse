use super::partial_crosslink_record::PartialCrosslinkRecord;
use super::recent_proposer_record::RecentPropserRecord;
use super::utils::types::*;

pub struct ActiveState {
    pub height: u64,
    pub randao: Sha256Digest,
    pub ffg_voter_bitfield: Bitfield,
    pub recent_attesters: Vec<u32>, // TODO: should be u24
    pub partial_crosslinks: Vec<PartialCrosslinkRecord>,
    pub total_skip_count: u64,
    pub recent_proposers: Vec<RecentPropserRecord>
}

impl ActiveState {
    pub fn new_for_height(height: u64) -> ActiveState {
        ActiveState {
            height: height,
            randao: Sha256Digest::random(),
            ffg_voter_bitfield: Vec::new(),
            recent_attesters: Vec::new(),
            partial_crosslinks: Vec::new(),
            total_skip_count: 0,
            recent_proposers: Vec::new()
        }
    }

    pub fn num_recent_proposers(&self) -> usize {
        self.recent_proposers.len()
    }
    
    pub fn num_recent_attesters(&self) -> usize {
        self.recent_attesters.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_for_height() {
        let h = 1;
        let a = ActiveState::new_for_height(h);
        assert_eq!(a.height, h);
    }

    #[test]
    fn test_num_recent_proposers() {
        let mut a = ActiveState::new_for_height(1);
        for _ in 1..5 {
            a.recent_proposers.push(RecentPropserRecord::new(
                    1, 
                    Sha256Digest::random(), 
                    2));
        }
        assert_eq!(a.num_recent_proposers(), 4)
    }
    
    #[test]
    fn test_num_recent_attesters() {
        let mut a = ActiveState::new_for_height(1);
        for _ in 1..5 {
            a.recent_attesters.push(1);
        }
        assert_eq!(a.num_recent_attesters(), 4)
    }
}
