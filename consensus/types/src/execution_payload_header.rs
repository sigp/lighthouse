use crate::{execution_payload::BytesPerLogsBloom, test_utils::TestRandom, *};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct ExecutionPayloadHeader {
    pub block_hash: Hash256,
    pub parent_hash: Hash256,
    pub coinbase: Address,
    pub state_root: Hash256,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub receipt_root: Hash256,
    pub logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
    pub transactions_root: Hash256,
}
