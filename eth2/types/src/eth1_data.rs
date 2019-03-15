use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

/// Contains data obtained from the Eth1 chain.
///
/// Spec v0.4.0
#[derive(
    Debug, PartialEq, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct Eth1Data {
    pub deposit_root: Hash256,
    pub block_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Eth1Data);
}
