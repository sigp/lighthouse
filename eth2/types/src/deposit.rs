use crate::test_utils::TestRandom;
use crate::*;
use fixed_len_vec::typenum::U32;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// A deposit to potentially become a beacon chain validator.
///
/// Spec v0.6.0
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
    TestRandom,
)]
pub struct Deposit {
    pub proof: FixedLenVec<Hash256, U32>,
    pub index: u64,
    pub data: DepositData,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Deposit);
    cached_tree_hash_tests!(Deposit);
}
