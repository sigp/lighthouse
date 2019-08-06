use crate::test_utils::TestRandom;
use crate::utils::{fork_from_hex_str, fork_to_hex_str};
use crate::Epoch;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.8.1
#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct Fork {
    #[serde(
        serialize_with = "fork_to_hex_str",
        deserialize_with = "fork_from_hex_str"
    )]
    pub previous_version: [u8; 4],
    #[serde(
        serialize_with = "fork_to_hex_str",
        deserialize_with = "fork_from_hex_str"
    )]
    pub current_version: [u8; 4],
    pub epoch: Epoch,
}

impl Fork {
    /// Initialize the `Fork` from the genesis parameters in the `spec`.
    ///
    /// Spec v0.8.1
    pub fn genesis(genesis_epoch: Epoch) -> Self {
        Self {
            previous_version: [0; 4],
            current_version: [0; 4],
            epoch: genesis_epoch,
        }
    }

    /// Return the fork version of the given ``epoch``.
    ///
    /// Spec v0.8.1
    pub fn get_fork_version(&self, epoch: Epoch) -> [u8; 4] {
        if epoch < self.epoch {
            return self.previous_version;
        }
        self.current_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Fork);

    fn test_genesis(epoch: Epoch) {
        let fork = Fork::genesis(epoch);

        assert_eq!(fork.epoch, epoch, "epoch incorrect");
        assert_eq!(
            fork.previous_version, fork.current_version,
            "previous and current are not identical"
        );
    }

    #[test]
    fn genesis() {
        test_genesis(Epoch::new(0));
        test_genesis(Epoch::new(11));
        test_genesis(Epoch::new(2_u64.pow(63)));
        test_genesis(Epoch::max_value());
    }

    #[test]
    fn get_fork_version() {
        let previous_version = [1; 4];
        let current_version = [2; 4];
        let epoch = Epoch::new(10);

        let fork = Fork {
            previous_version,
            current_version,
            epoch,
        };

        assert_eq!(fork.get_fork_version(epoch - 1), previous_version);
        assert_eq!(fork.get_fork_version(epoch), current_version);
        assert_eq!(fork.get_fork_version(epoch + 1), current_version);
    }
}
