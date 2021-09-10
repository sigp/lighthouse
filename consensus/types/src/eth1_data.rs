use super::Hash256;
use crate::test_utils::TestRandom;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Contains data obtained from the Eth1 chain.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    PartialEq,
    Clone,
    Default,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct Eth1Data {
    pub deposit_root: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub deposit_count: u64,
    pub block_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(Eth1Data);
}
