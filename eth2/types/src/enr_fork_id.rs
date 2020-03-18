use crate::test_utils::TestRandom;
use crate::utils::{fork_from_hex_str, fork_to_hex_str};
use crate::{Epoch, Slot, FAR_FUTURE_EPOCH};

use fork::{next_fork_epoch, next_fork_version};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies a fork which allows nodes to identify each other on the network. This fork is used in
/// a nodes local ENR.
///
/// Spec v0.11
#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct EnrForkId {
    #[serde(
        serialize_with = "fork_to_hex_str",
        deserialize_with = "fork_from_hex_str"
    )]
    pub fork_digest: [u8; 4],
    #[serde(
        serialize_with = "fork_to_hex_str",
        deserialize_with = "fork_from_hex_str"
    )]
    pub next_fork_version: [u8; 4],
    pub next_fork_epoch: Epoch,
}

impl EnrForkId {
    /// Creates an up to date current EnrForkId with current information to broadcast to peers.
    ///
    /// Requires the current slot, `genesis_validators_root` and any disabled forks.
    /// Spec v0.11
    pub fn new(
        &self,
        slot: Slot,
        genesis_validators_root: [u8; 4],
        disabled_forks: Vec<String>,
    ) -> [u8; 4] {
        //TODO: Update once v0.11 hits
        EnrForkId {
            fork_digest: [0, 0, 0, 0],
            next_fork_version: next_fork_version(slot, disabled_forks),
            next_fork_epoch: next_fork_epoch(slot, disabled_forks),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(Fork);

    #[test]
    fn get_enr_fork() {
        let enr_fork = EnrForkId::new(Slot(10), [0, 0, 0, 0], vec![]);

        assert_eq!(fork.next_fork_version, [0, 0, 0, 0]);
        assert_eq!(fork.next_fork_epoch, FAR_FUTURE_EPOCH);
    }
}
