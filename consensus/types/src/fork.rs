use crate::test_utils::TestRandom;
use crate::Epoch;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Default,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct Fork {
    #[serde(with = "eth2_serde_utils::bytes_4_hex")]
    pub previous_version: [u8; 4],
    #[serde(with = "eth2_serde_utils::bytes_4_hex")]
    pub current_version: [u8; 4],
    pub epoch: Epoch,
}

impl Fork {
    /// Return the fork version of the given ``epoch``.
    ///
    /// Spec v0.12.1
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
