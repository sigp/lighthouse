use crate::test_utils::TestRandom;
use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::U33;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub const DEPOSIT_TREE_DEPTH: usize = 32;

/// A deposit to potentially become a beacon chain validator.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct Deposit {
    pub proof: FixedVector<Hash256, U33>,
    pub data: DepositData,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(Deposit);
}
