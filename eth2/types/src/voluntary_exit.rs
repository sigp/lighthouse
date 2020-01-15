use crate::{test_utils::TestRandom, Epoch};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.9.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    pub epoch: Epoch,
    pub validator_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(VoluntaryExit);
}
