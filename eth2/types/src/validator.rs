use crate::{test_utils::TestRandom, Epoch, Hash256, PublicKey};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

/// Information about a `BeaconChain` validator.
///
/// Spec v0.4.0
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom, TreeHash)]
pub struct Validator {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
    pub initiated_exit: bool,
    pub slashed: bool,
}

impl Validator {
    /// Returns `true` if the validator is considered active at some epoch.
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// Returns `true` if the validator is considered exited at some epoch.
    pub fn is_exited_at(&self, epoch: Epoch) -> bool {
        self.exit_epoch <= epoch
    }

    /// Returns `true` if the validator is able to withdraw at some epoch.
    pub fn is_withdrawable_at(&self, epoch: Epoch) -> bool {
        self.withdrawable_epoch <= epoch
    }
}

impl Default for Validator {
    /// Yields a "default" `Validator`. Primarily used for testing.
    fn default() -> Self {
        Self {
            pubkey: PublicKey::default(),
            withdrawal_credentials: Hash256::default(),
            activation_epoch: Epoch::from(std::u64::MAX),
            exit_epoch: Epoch::from(std::u64::MAX),
            withdrawable_epoch: Epoch::from(std::u64::MAX),
            initiated_exit: false,
            slashed: false,
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
        let original = Validator::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_validator_can_be_active() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut validator = Validator::random_for_test(&mut rng);

        let activation_epoch = u64::random_for_test(&mut rng);
        let exit_epoch = activation_epoch + 234;

        validator.activation_epoch = Epoch::from(activation_epoch);
        validator.exit_epoch = Epoch::from(exit_epoch);

        for slot in (activation_epoch - 100)..(exit_epoch + 100) {
            let slot = Epoch::from(slot);
            if slot < activation_epoch {
                assert!(!validator.is_active_at(slot));
            } else if slot >= exit_epoch {
                assert!(!validator.is_active_at(slot));
            } else {
                assert!(validator.is_active_at(slot));
            }
        }
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Validator::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
