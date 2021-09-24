use crate::{test_utils::TestRandom, *};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct ExecutionPayloadHeader<T: EthSpec> {
    pub parent_hash: Hash256,
    pub coinbase: Address,
    pub state_root: Hash256,
    pub receipt_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    pub random: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub block_number: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub timestamp: u64,
    pub base_fee_per_gas: Hash256,
    pub block_hash: Hash256,
    pub transactions_root: Hash256,
}

impl<T: EthSpec> ExecutionPayloadHeader<T> {
    // TODO: check this whole thing later
    pub fn empty() -> Self {
        Self::default()
    }
}
