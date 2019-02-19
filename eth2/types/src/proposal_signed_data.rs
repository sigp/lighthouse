use crate::test_utils::TestRandom;
use crate::{Hash256, Slot};
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use ssz_derive::{Decode, Encode};

#[derive(Debug, PartialEq, Clone, Default, Serialize, Encode, Decode)]
pub struct ProposalSignedData {
    pub slot: Slot,
    pub shard: u64,
    pub block_root: Hash256,
}

impl TreeHash for ProposalSignedData {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.slot.hash_tree_root());
        result.append(&mut self.shard.hash_tree_root());
        result.append(&mut self.block_root.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for ProposalSignedData {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            shard: <_>::random_for_test(rng),
            block_root: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ProposalSignedData::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ProposalSignedData::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
