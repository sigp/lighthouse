use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    Default,
    Debug,
    Clone,
    Serialize,
    Encode,
    Decode,
    Deserialize,
    TreeHash,
    Derivative,
    TestRandom,
)]
#[derivative(PartialEq, Hash)]
// This is what Potuz' spec calls an `ExecutionPayload` even though it's clearly a bid.
pub struct ExecutionBid {
    pub parent_block_hash: ExecutionBlockHash,
    pub parent_block_root: Hash256,
    pub block_hash: ExecutionBlockHash,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub value: u64,
    pub blob_kzg_commitments_root: Hash256,
}

impl SignedRoot for ExecutionBid {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ExecutionBid);
}
