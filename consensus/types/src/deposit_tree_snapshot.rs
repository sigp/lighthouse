use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use test_utils::TestRandom;

#[derive(Encode, Decode, Deserialize, Serialize, Clone, Debug, PartialEq, TestRandom)]
pub struct DepositTreeSnapshot {
    pub finalized: Vec<Hash256>,
    pub deposits: u64,
    pub execution_block_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(DepositTreeSnapshot);
}
