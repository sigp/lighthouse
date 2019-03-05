use crate::{test_utils::TestRandom, Epoch};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct Fork {
    pub previous_version: u64,
    pub current_version: u64,
    pub epoch: Epoch,
}

impl Fork {
    /// Return the fork version of the given ``epoch``.
    pub fn get_fork_version(&self, epoch: Epoch) -> u64 {
        if epoch < self.epoch {
            return self.previous_version;
        }
        self.current_version
    }

    /// Get the domain number that represents the fork meta and signature domain.
    pub fn get_domain(&self, epoch: Epoch, domain_type: u64) -> u64 {
        let fork_version = self.get_fork_version(epoch);
        fork_version * u64::pow(2, 32) + domain_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Fork);
}
