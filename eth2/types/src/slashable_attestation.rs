use crate::{test_utils::TestRandom, AggregateSignature, AttestationData, Bitfield};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash)]
pub struct SlashableAttestation {
    pub validator_indices: Vec<u64>,
    pub data: AttestationData,
    pub custody_bitfield: Bitfield,
    pub aggregate_signature: AggregateSignature,
}

impl<T: RngCore> TestRandom<T> for SlashableAttestation {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            validator_indices: <_>::random_for_test(rng),
            data: <_>::random_for_test(rng),
            custody_bitfield: <_>::random_for_test(rng),
            aggregate_signature: <_>::random_for_test(rng),
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
