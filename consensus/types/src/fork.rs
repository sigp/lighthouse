use crate::test_utils::TestRandom;
use crate::utils::{fork_from_hex_str, fork_to_hex_str};
use crate::Epoch;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
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
    /// Return the fork version of the given ``epoch``.
    ///
    /// Spec v0.11.1
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

    ssz_and_tree_hash_tests!(Fork);

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
