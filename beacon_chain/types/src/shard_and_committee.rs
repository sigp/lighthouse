#[derive(Clone, Debug, PartialEq)]
pub struct ShardAndCommittee {
    pub shard: u16,
    pub committee: Vec<usize>
}

impl ShardAndCommittee {
    /// Returns a new instance where the `shard_id` is zero and the
    /// committee is an empty vector.
    pub fn zero() -> Self {
        Self {
            shard: 0,
            committee: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_and_committee_zero() {
        let s = ShardAndCommittee::zero();
        assert_eq!(s.shard, 0);
        assert_eq!(s.committee.len(), 0);
    }
}
