use crate::{test_utils::TestRandom, Epoch};
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{SignedRoot, TreeHash};

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.8.0
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    SignedRoot,
)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    pub epoch: Epoch,
    pub validator_index: u64,
    #[signed_root(skip_hashing)]
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(VoluntaryExit);
}
