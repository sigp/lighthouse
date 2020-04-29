use crate::test_utils::TestRandom;
use crate::{Epoch, Hash256};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Casper FFG checkpoint, used in attestations.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(Checkpoint);
}
