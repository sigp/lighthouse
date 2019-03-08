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

    ssz_tests!(ValidatorRegistryDeltaBlock);
}
