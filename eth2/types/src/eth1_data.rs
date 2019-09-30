use super::Hash256;
use crate::test_utils::TestRandom;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Contains data obtained from the Eth1 chain.
///
/// Spec v0.8.1
#[derive(
    Debug, PartialEq, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct Eth1Data {
    pub deposit_root: Hash256,
    pub deposit_count: u64,
    pub block_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Eth1Data);
}
