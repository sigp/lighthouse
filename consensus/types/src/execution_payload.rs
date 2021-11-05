use crate::{test_utils::TestRandom, *};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub type Transaction<T> = VariableList<u8, T>;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[serde(bound = "T: EthSpec")]
pub struct ExecutionPayload<T: EthSpec> {
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
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    pub base_fee_per_gas: Hash256,
    pub block_hash: Hash256,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions:
        VariableList<Transaction<T::MaxBytesPerTransaction>, T::MaxTransactionsPerPayload>,
}

impl<T: EthSpec> ExecutionPayload<T> {
    // TODO: check this whole thing later
    pub fn empty() -> Self {
        Self {
            parent_hash: Hash256::zero(),
            coinbase: Address::default(),
            state_root: Hash256::zero(),
            receipt_root: Hash256::zero(),
            logs_bloom: FixedVector::default(),
            random: Hash256::zero(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: VariableList::empty(),
            base_fee_per_gas: Hash256::zero(),
            block_hash: Hash256::zero(),
            transactions: VariableList::empty(),
        }
    }
}
