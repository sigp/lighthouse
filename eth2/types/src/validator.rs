use crate::{test_utils::TestRandom, Epoch, Hash256, PublicKey};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Information about a `BeaconChain` validator.
///
/// Spec v0.5.1
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

    #[test]
    fn default() {
        let v = Validator::default();

        let epoch = Epoch::new(0);

        assert_eq!(v.is_active_at(epoch), false);
        assert_eq!(v.is_exited_at(epoch), false);
        assert_eq!(v.is_withdrawable_at(epoch), false);
        assert_eq!(v.initiated_exit, false);
        assert_eq!(v.slashed, false);
    }

    #[test]
    fn is_active_at() {
        let epoch = Epoch::new(10);

        let v = Validator {
            activation_epoch: epoch,
            ..Validator::default()
        };

        assert_eq!(v.is_active_at(epoch - 1), false);
        assert_eq!(v.is_active_at(epoch), true);
        assert_eq!(v.is_active_at(epoch + 1), true);
    }

    #[test]
    fn is_exited_at() {
        let epoch = Epoch::new(10);

        let v = Validator {
            exit_epoch: epoch,
            ..Validator::default()
        };

        assert_eq!(v.is_exited_at(epoch - 1), false);
        assert_eq!(v.is_exited_at(epoch), true);
        assert_eq!(v.is_exited_at(epoch + 1), true);
    }

    #[test]
    fn is_withdrawable_at() {
        let epoch = Epoch::new(10);

        let v = Validator {
            withdrawable_epoch: epoch,
            ..Validator::default()
        };

        assert_eq!(v.is_withdrawable_at(epoch - 1), false);
        assert_eq!(v.is_withdrawable_at(epoch), true);
        assert_eq!(v.is_withdrawable_at(epoch + 1), true);
    }

    ssz_tests!(Validator);
}
