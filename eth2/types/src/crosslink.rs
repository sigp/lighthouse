use crate::test_utils::TestRandom;
use crate::{Epoch, Hash256};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies the block hash for a shard at an epoch.
///
/// Spec v0.8.0
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    Hash,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct Crosslink {
    pub shard: u64,
    pub parent_root: Hash256,
    // Crosslinking data
    pub start_epoch: Epoch,
    pub end_epoch: Epoch,
    pub data_root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Crosslink);
}
