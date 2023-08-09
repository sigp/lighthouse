use crate::*;
use ethereum_hashing::{hash32_concat, ZERO_HASHES};
use int_to_bytes::int_to_bytes32;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use test_utils::TestRandom;
use DEPOSIT_TREE_DEPTH;

#[derive(Encode, Decode, Deserialize, Serialize, Clone, Debug, PartialEq, TestRandom)]
pub struct FinalizedExecutionBlock {
    pub deposit_root: Hash256,
    pub deposit_count: u64,
    pub block_hash: Hash256,
    pub block_height: u64,
}

impl From<&DepositTreeSnapshot> for FinalizedExecutionBlock {
    fn from(snapshot: &DepositTreeSnapshot) -> Self {
        Self {
            deposit_root: snapshot.deposit_root,
            deposit_count: snapshot.deposit_count,
            block_hash: snapshot.execution_block_hash,
            block_height: snapshot.execution_block_height,
        }
    }
}

#[derive(Encode, Decode, Deserialize, Serialize, Clone, Debug, PartialEq, TestRandom)]
pub struct DepositTreeSnapshot {
    pub finalized: Vec<Hash256>,
    pub deposit_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_count: u64,
    pub execution_block_hash: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub execution_block_height: u64,
}

impl Default for DepositTreeSnapshot {
    fn default() -> Self {
        let mut result = Self {
            finalized: vec![],
            deposit_root: Hash256::default(),
            deposit_count: 0,
            execution_block_hash: Hash256::zero(),
            execution_block_height: 0,
        };
        // properly set the empty deposit root
        result.deposit_root = result.calculate_root().unwrap();
        result
    }
}

impl DepositTreeSnapshot {
    // Calculates the deposit tree root from the hashes in the snapshot
    pub fn calculate_root(&self) -> Option<Hash256> {
        let mut size = self.deposit_count;
        let mut index = self.finalized.len();
        let mut deposit_root = [0; 32];
        for height in 0..DEPOSIT_TREE_DEPTH {
            deposit_root = if (size & 1) == 1 {
                index = index.checked_sub(1)?;
                hash32_concat(self.finalized.get(index)?.as_bytes(), &deposit_root)
            } else {
                hash32_concat(&deposit_root, ZERO_HASHES.get(height)?)
            };
            size /= 2;
        }
        // add mix-in-length
        deposit_root = hash32_concat(&deposit_root, &int_to_bytes32(self.deposit_count));

        Some(Hash256::from_slice(&deposit_root))
    }
    pub fn is_valid(&self) -> bool {
        self.calculate_root()
            .map_or(false, |calculated| self.deposit_root == calculated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    ssz_tests!(DepositTreeSnapshot);
}
