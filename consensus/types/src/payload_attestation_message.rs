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
    Encode,
    Decode,
    Serialize,
    Deserialize,
)]
pub struct PayloadAttestationMessage {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub data: PayloadAttestationData,
    pub signature: AggregateSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadAttestationMessage);
}
