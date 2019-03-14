use crate::{test_utils::TestRandom, Slot};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct ShardReassignmentRecord {
    pub validator_index: u64,
    pub shard: u64,
    pub slot: Slot,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(ShardReassignmentRecord);
}
