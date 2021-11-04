use crate::*;
use ssz_derive::{Decode, Encode};

#[derive(Encode, Decode, Clone, Debug)]
pub struct DepositTreeSnapshot {
    pub branches: Vec<Hash256>,
    pub deposits: u64,
    pub eth1_block_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(DepositTreeSnapshot);
}
