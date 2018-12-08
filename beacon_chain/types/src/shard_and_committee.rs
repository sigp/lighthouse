use super::ssz::{merkle_hash, TreeHash};

#[derive(Clone, Debug, PartialEq)]
pub struct ShardAndCommittee {
    pub shard: u16,
    pub committee: Vec<usize>,
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

impl TreeHash for ShardAndCommittee {
    fn tree_hash(&self) -> Vec<u8> {
        let mut committee_ssz_items = Vec::new();
        for c in &self.committee {
            let mut h = (*c as u32).tree_hash();
            h.resize(3, 0);
            committee_ssz_items.push(h);
        }
        let mut result = Vec::new();
        result.append(&mut self.shard.tree_hash());
        result.append(&mut merkle_hash(&mut committee_ssz_items));

        result.tree_hash()
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

    #[test]
    fn test_shard_and_committee_tree_hash() {
        let s = ShardAndCommittee {
            shard: 1,
            committee: vec![1, 2, 3],
        };

        // should test a known hash value
        assert_eq!(s.tree_hash().len(), 32);
    }
}
