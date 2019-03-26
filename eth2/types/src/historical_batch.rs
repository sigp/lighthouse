use crate::test_utils::TestRandom;
use crate::Hash256;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

/// Historical block and state roots.
///
/// Spec v0.5.0
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct HistoricalBatch {
    pub block_roots: Vec<Hash256>,
    pub state_roots: Vec<Hash256>,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(HistoricalBatch);
}
