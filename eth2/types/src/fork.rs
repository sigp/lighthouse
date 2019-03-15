use crate::{test_utils::TestRandom, ChainSpec, Epoch};
use int_to_bytes::int_to_bytes4;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.5.0
#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct Fork {
    pub previous_version: [u8; 4],
    pub current_version: [u8; 4],
    pub epoch: Epoch,
}

impl Fork {
    /// Initialize the `Fork` from the genesis parameters in the `spec`.
    ///
    /// Spec v0.5.0
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
    /// Spec v0.5.0
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
}
