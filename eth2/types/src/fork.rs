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
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::{ssz_encode, Decodable, TreeHash};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Fork::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Fork::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
