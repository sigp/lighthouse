use crate::{test_utils::TestRandom, AggregateSignature, AttestationData, Bitfield};
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, TreeHash};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TestRandom)]
pub struct SlashableAttestation {
    pub validator_indices: Vec<u64>,
    pub data: AttestationData,
    pub custody_bitfield: Bitfield,
    pub aggregate_signature: AggregateSignature,
}

impl TreeHash for SlashableAttestation {
    fn hash_tree_root_internal(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.validator_indices.hash_tree_root_internal());
        result.append(&mut self.data.hash_tree_root_internal());
        result.append(&mut self.custody_bitfield.hash_tree_root_internal());
        result.append(&mut self.aggregate_signature.hash_tree_root_internal());
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
        let original = SlashableAttestation::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = SlashableAttestation::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
