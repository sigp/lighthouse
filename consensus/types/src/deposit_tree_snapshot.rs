use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use test_utils::TestRandom;

#[derive(Encode, Decode, Deserialize, Serialize, Clone, Debug, PartialEq, TestRandom)]
pub struct FinalizedExecutionBlock {
    pub deposits: u64,
    pub block_hash: Hash256,
    pub block_height: u64,
}

impl From<&DepositTreeSnapshot> for FinalizedExecutionBlock {
    fn from(snapshot: &DepositTreeSnapshot) -> Self {
        Self {
            deposits: snapshot.deposits,
            block_hash: snapshot.execution_block_hash,
            block_height: snapshot.execution_block_height,
        }
    }
}

#[derive(Encode, Decode, Deserialize, Serialize, Clone, Debug, PartialEq, TestRandom)]
pub struct DepositTreeSnapshot {
    pub finalized: Vec<Hash256>,
    pub deposits: u64,
    pub execution_block_hash: Hash256,
    pub execution_block_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    ssz_tests!(FinalizedExecutionBlock);
    ssz_tests!(DepositTreeSnapshot);
}
