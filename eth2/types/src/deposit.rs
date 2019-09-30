use crate::test_utils::TestRandom;
use crate::*;
use ssz_types::typenum::U33;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A deposit to potentially become a beacon chain validator.
///
/// Spec v0.8.0
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct Deposit {
    pub proof: FixedVector<Hash256, U33>,
    pub data: DepositData,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Deposit);
}
