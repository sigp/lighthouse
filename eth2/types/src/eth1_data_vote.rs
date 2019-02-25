use super::Eth1Data;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};

// Note: this is refer to as DepositRootVote in specs
#[derive(Debug, PartialEq, Clone, Default, Serialize, Encode, Decode, TreeHash)]
pub struct Eth1DataVote {
    pub eth1_data: Eth1Data,
    pub vote_count: u64,
}

impl<T: RngCore> TestRandom<T> for Eth1DataVote {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            eth1_data: <_>::random_for_test(rng),
            vote_count: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::{ssz_encode, Decodable, TreeHash};

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
