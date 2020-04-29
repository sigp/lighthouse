use crate::test_utils::TestRandom;
use crate::utils::{fork_from_hex_str, fork_to_hex_str};
use crate::{Hash256, SignedRoot};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct ForkData {
    #[serde(
        serialize_with = "fork_to_hex_str",
        deserialize_with = "fork_from_hex_str"
    )]
    pub current_version: [u8; 4],
    pub genesis_validators_root: Hash256,
}

impl SignedRoot for ForkData {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ForkData);
}
