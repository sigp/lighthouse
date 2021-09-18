use crate::test_utils::TestRandom;
use crate::Epoch;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies a fork which allows nodes to identify each other on the network. This fork is used in
/// a nodes local ENR.
///
/// Spec v0.11
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct EnrForkId {
    #[serde(with = "eth2_serde_utils::bytes_4_hex")]
    pub fork_digest: [u8; 4],
    #[serde(with = "eth2_serde_utils::bytes_4_hex")]
    pub next_fork_version: [u8; 4],
    pub next_fork_epoch: Epoch,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(EnrForkId);
}
