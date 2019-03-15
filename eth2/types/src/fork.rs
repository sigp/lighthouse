use crate::{test_utils::TestRandom, Epoch};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.4.0
#[derive(Debug, Clone, PartialEq, Default, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct Fork {
    pub previous_version: u64,
    pub current_version: u64,
    pub epoch: Epoch,
}

impl Fork {
    /// Return the fork version of the given ``epoch``.
    ///
    /// Spec v0.4.0
    pub fn get_fork_version(&self, epoch: Epoch) -> u64 {
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
