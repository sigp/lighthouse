use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Encode,
    Decode,
    Deserialize,
    TreeHash,
    Derivative,
    TestRandom,
)]
// This is what Potuz' spec calls an `ExecutionPayload` even though it's clearly a bid.
pub struct ExecutionBid {
    parent_block_hash: ExecutionBlockHash,
    parent_block_root: Hash256,
    block_hash: ExecutionBlockHash,
    #[serde(with = "serde_utils::quoted_u64")]
    gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    builder_index: u64,
    slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    value: u64,
    blob_kzg_commitments_root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ExecutionBid);
}
