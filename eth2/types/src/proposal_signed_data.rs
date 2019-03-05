use crate::test_utils::TestRandom;
use crate::{Hash256, Slot};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

#[derive(Debug, PartialEq, Clone, Default, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct ProposalSignedData {
    pub slot: Slot,
    pub shard: u64,
    pub block_root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(ProposalSignedData);
}
