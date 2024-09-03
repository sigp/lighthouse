use crate::test_utils::TestRandom;
use crate::*;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    TestRandom,
    TreeHash,
    Debug,
    Clone,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    Derivative,
)]
#[derivative(PartialEq, Hash)]
pub struct SignedExecutionBid {
    pub message: ExecutionBid,
    pub signature: Signature,
}

impl SignedExecutionBid {
    pub fn empty() -> Self {
        Self {
            message: ExecutionBid::default(),
            signature: Signature::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedExecutionBid);
}
