use crate::{
    test_utils::{fork_from_hex_str, TestRandom},
    ChainSpec, Epoch,
};
use int_to_bytes::int_to_bytes4;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.5.1
#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct Fork {
    #[serde(deserialize_with = "fork_from_hex_str")]
    pub previous_version: [u8; 4],
    #[serde(deserialize_with = "fork_from_hex_str")]
    pub current_version: [u8; 4],
    pub epoch: Epoch,
}

impl Fork {
    /// Initialize the `Fork` from the genesis parameters in the `spec`.
    ///
    /// Spec v0.5.1
    pub fn genesis(spec: &ChainSpec) -> Self {
        let mut current_version: [u8; 4] = [0; 4];
        current_version.copy_from_slice(&int_to_bytes4(spec.genesis_fork_version));

        Self {
            previous_version: current_version,
            current_version,
            epoch: spec.genesis_epoch,
        }
    }

    /// Return the fork version of the given ``epoch``.
    ///
    /// Spec v0.5.1
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

    fn test_genesis(version: u32, epoch: Epoch) {
        let mut spec = ChainSpec::foundation();

        spec.genesis_fork_version = version;
        spec.genesis_epoch = epoch;

        let fork = Fork::genesis(&spec);

        assert_eq!(fork.epoch, spec.genesis_epoch, "epoch incorrect");
        assert_eq!(
            fork.previous_version, fork.current_version,
            "previous and current are not identical"
        );
        assert_eq!(
            fork.current_version,
            version.to_le_bytes(),
            "current version incorrect"
        );
    }

    #[test]
    fn genesis() {
        test_genesis(0, Epoch::new(0));
        test_genesis(9, Epoch::new(11));
        test_genesis(2_u32.pow(31), Epoch::new(2_u64.pow(63)));
        test_genesis(u32::max_value(), Epoch::max_value());
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
