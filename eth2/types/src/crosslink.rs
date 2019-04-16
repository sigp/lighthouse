use crate::test_utils::TestRandom;
use crate::{Epoch, Hash256};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Specifies the block hash for a shard at an epoch.
///
/// Spec v0.5.0
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
    TestRandom,
)]
pub struct Crosslink {
    pub epoch: Epoch,
    pub crosslink_data_root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Crosslink);
}
