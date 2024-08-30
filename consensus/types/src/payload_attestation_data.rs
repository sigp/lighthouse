use crate::test_utils::TestRandom;
use crate::*;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    TestRandom,
    TreeHash,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    Serialize,
    Deserialize,
)]
pub struct PayloadAttestationData {
    pub beacon_block_root: Hash256,
    pub slot: Slot,
    pub payload_status: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadAttestationData);
}
