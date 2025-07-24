use crate::context_deserialize;
use crate::{ForkName, VoluntaryExit, test_utils::TestRandom};
use bls::Signature;

use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[context_deserialize(ForkName)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedVoluntaryExit);
}
