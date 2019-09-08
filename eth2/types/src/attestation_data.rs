use crate::test_utils::TestRandom;
use crate::{Checkpoint, Crosslink, Hash256};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// The data upon which an attestation is based.
///
/// Spec v0.8.0
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Encode, Decode, TreeHash, TestRandom,
)]
pub struct AttestationData {
    // LMD GHOST vote
    pub beacon_block_root: Hash256,

    // FFG Vote
    pub source: Checkpoint,
    pub target: Checkpoint,

    // Crosslink Vote
    pub crosslink: Crosslink,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(AttestationData);
}
