use crate::{test_utils::TestRandom, Epoch};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Encode, Decode, TreeHash)]
pub struct Fork {
    pub previous_version: u64,
    pub current_version: u64,
    pub epoch: Epoch,
}

impl<T: RngCore> TestRandom<T> for Fork {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            previous_version: <_>::random_for_test(rng),
            current_version: <_>::random_for_test(rng),
            epoch: <_>::random_for_test(rng),
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
        let original = Fork::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Fork::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
