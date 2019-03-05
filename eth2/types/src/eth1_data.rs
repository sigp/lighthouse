use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

// Note: this is refer to as DepositRootVote in specs
#[derive(Debug, PartialEq, Clone, Default, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct Eth1Data {
    pub deposit_root: Hash256,
    pub block_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Eth1Data);
}
