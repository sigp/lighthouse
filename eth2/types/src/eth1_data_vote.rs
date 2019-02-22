use super::Eth1Data;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, TreeHash};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;

// Note: this is refer to as DepositRootVote in specs
#[derive(Debug, PartialEq, Clone, Default, Serialize, Encode, Decode, TestRandom)]
pub struct Eth1DataVote {
    pub eth1_data: Eth1Data,
    pub vote_count: u64,
}

impl TreeHash for Eth1DataVote {
    fn hash_tree_root_internal(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.eth1_data.hash_tree_root_internal());
        result.append(&mut self.vote_count.hash_tree_root_internal());
        hash(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::{ssz_encode, Decodable};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Eth1DataVote::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Eth1DataVote::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
