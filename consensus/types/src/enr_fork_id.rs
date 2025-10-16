use crate::Epoch;
use crate::test_utils::TestRandom;

use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies a fork which allows nodes to identify each other on the network. This fork is used in
/// a nodes local ENR.
///
/// Spec v0.11
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct EnrForkId {
    /// Fork digest of the current fork computed from [`ChainSpec::compute_fork_digest`].
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub fork_digest: [u8; 4],
    /// `next_fork_version` is the fork version corresponding to the next planned fork at a future
    /// epoch. The fork version will only change for regular forks, not BPO forks.
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub next_fork_version: [u8; 4],
    /// `next_fork_epoch` is the epoch at which the next fork (whether a regular fork or a BPO fork) is planned
    pub next_fork_epoch: Epoch,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(EnrForkId);
}
