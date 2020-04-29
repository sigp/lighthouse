use crate::{test_utils::TestRandom, BeaconBlockHeader};
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedBeaconBlockHeader);
}
