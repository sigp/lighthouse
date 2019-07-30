use crate::test_utils::TestRandom;
use crate::{Epoch, Hash256};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{CachedTreeHash, SignedRoot, TreeHash};

/// Casper FFG checkpoint, used in attestations.
///
/// Spec v0.8.0
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
    CachedTreeHash,
    TestRandom,
    SignedRoot,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Checkpoint);
    cached_tree_hash_tests!(Checkpoint);
}
