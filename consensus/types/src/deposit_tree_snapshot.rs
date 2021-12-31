use crate::*;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use test_utils::TestRandom;

#[derive(Encode, Decode, Clone, Debug, PartialEq, TestRandom)]
pub struct DepositTreeSnapshot {
    pub branches: Vec<Hash256>,
    pub deposits: u64,
    pub eth1_block_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(DepositTreeSnapshot);
}
