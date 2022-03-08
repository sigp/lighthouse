use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::fmt::Debug;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub enum BlockType {
    Full,
    Blinded,
}

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom, Derivative,
)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec, Txns: Transactions<T>"))]
#[serde(bound = "T: EthSpec, Txns: Transactions<T>")]
pub struct ExecutionPayload<T: EthSpec, Txns: Transactions<T> = ExecTransactions<T>> {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: Address,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    pub prev_randao: Hash256,
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
    #[serde(with = "eth2_serde_utils::quoted_u256")]
    pub base_fee_per_gas: Uint256,
    pub block_hash: ExecutionBlockHash,
    pub transactions: Txns,
}

impl<T: EthSpec, Txns: Transactions<T>> ExecutionPayload<T, Txns> {
    pub fn empty() -> Self {
        Self::default()
    }

    #[allow(clippy::integer_arithmetic)]
    /// Returns the maximum size of an execution payload.
    pub fn max_execution_payload_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (T::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (T::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + T::max_bytes_per_transaction()))
    }
}
