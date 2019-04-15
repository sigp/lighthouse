use super::Eth1Data;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A summation of votes for some `Eth1Data`.
///
/// Spec v0.5.1
#[derive(
    Debug, PartialEq, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct Eth1DataVote {
    pub eth1_data: Eth1Data,
    pub vote_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Eth1DataVote);
}
