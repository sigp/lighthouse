use crate::test_utils::TestRandom;
use crate::{Hash256, TreeHashVector};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Historical block and state roots.
///
/// Spec v0.5.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct HistoricalBatch {
    pub block_roots: TreeHashVector<Hash256>,
    pub state_roots: TreeHashVector<Hash256>,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(HistoricalBatch);
}
