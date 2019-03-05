use crate::test_utils::TestRandom;
use crate::{Epoch, Hash256};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Hash, Encode, Decode, TreeHash, TestRandom,
)]
pub struct Crosslink {
    pub epoch: Epoch,
    pub shard_block_root: Hash256,
}

impl Crosslink {
    /// Generates a new instance where `dynasty` and `hash` are both zero.
    pub fn zero() -> Self {
        Self {
            epoch: Epoch::new(0),
            shard_block_root: Hash256::zero(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Crosslink);
}
