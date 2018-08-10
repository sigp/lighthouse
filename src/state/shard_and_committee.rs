#[derive(Clone)]
pub struct ShardAndCommittee {
    shard_id: u16,
    committee: Vec<u32>
}

impl ShardAndCommittee {
    /// Returns a new instance where the `shard_id` is zero and the
    /// committee is an empty vector.
    pub fn zero() -> Self {
        Self {
            shard_id: 0,
            committee: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_and_committee_zero() {
        let s = CrystallizedState::zero();
        assert_eq!(s.shard_id, 0);
        assert_eq!(s.committee.len(), 0);
    }
}
