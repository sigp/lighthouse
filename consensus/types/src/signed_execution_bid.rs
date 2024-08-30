use crate::test_utils::TestRandom;
use crate::*;
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
    PartialEq,
    Encode,
    Decode,
    Serialize,
    Deserialize,
)]
pub struct SignedExecutionBid {
    pub message: ExecutionBid,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedExecutionBid);
}
