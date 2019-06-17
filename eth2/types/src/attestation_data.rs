use crate::test_utils::TestRandom;
use crate::{Epoch, Hash256};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{CachedTreeHash, SignedRoot, TreeHash};

/// The data upon which an attestation is based.
///
/// Spec v0.6.3
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
    CachedTreeHash,
    TestRandom,
    SignedRoot,
)]
pub struct AttestationData {
    // LMD GHOST vote
    pub beacon_block_root: Hash256,

    // FFG Vote
    pub source_epoch: Epoch,
    pub source_root: Hash256,
    pub target_epoch: Epoch,
    pub target_root: Hash256,

    // Crosslink Vote
    pub shard: u64,
    pub previous_crosslink_root: Hash256,
    pub crosslink_data_root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(AttestationData);
    cached_tree_hash_tests!(AttestationData);
}
