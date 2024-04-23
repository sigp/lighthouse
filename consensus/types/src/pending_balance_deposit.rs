use crate::test_utils::TestRandom;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct PendingBalanceDeposit {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PendingBalanceDeposit);
}
