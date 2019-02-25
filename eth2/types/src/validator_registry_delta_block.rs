use crate::{test_utils::TestRandom, Hash256, Slot};
use bls::PublicKey;
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

// The information gathered from the PoW chain validator registration function.
#[derive(Debug, Clone, PartialEq, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct ValidatorRegistryDeltaBlock {
    pub latest_registry_delta_root: Hash256,
    pub validator_index: u32,
    pub pubkey: PublicKey,
    pub slot: Slot,
    pub flag: u64,
}

impl Default for ValidatorRegistryDeltaBlock {
    /// Yields a "default" `Validator`. Primarily used for testing.
    fn default() -> Self {
        Self {
            latest_registry_delta_root: Hash256::zero(),
            validator_index: std::u32::MAX,
            pubkey: PublicKey::default(),
            slot: Slot::from(std::u64::MAX),
            flag: std::u64::MAX,
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
        let original = ValidatorRegistryDeltaBlock::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ValidatorRegistryDeltaBlock::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
