use crate::test_utils::TestRandom;
use crate::{Epoch, Hash256};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// Specifies the block hash for a shard at an epoch.
///
/// Spec v0.6.0
#[derive(
    Debug,
    Clone,
    PartialEq,
    Default,
    Serialize,
    Deserialize,
    Hash,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
    TestRandom,
)]
pub struct Crosslink {
    pub epoch: Epoch,
    pub previous_crosslink_root: Hash256,
    pub crosslink_data_root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Crosslink);
    cached_tree_hash_tests!(Crosslink);
}
