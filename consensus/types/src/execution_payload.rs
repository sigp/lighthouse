use std::fmt::Debug;
use serde::de::DeserializeOwned;
use crate::{test_utils::TestRandom, *};
use serde::{Serialize as Ser, Deserialize as De};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;
use tree_hash::TreeHash;

pub type Transaction<T> = VariableList<u8, T>;

pub trait Txnss<T> : Default + Debug + Clone + PartialEq  +  Encode + Decode + TreeHash + TestRandom  {
    fn hash_tree_root(&self) -> Hash256;
}

impl <T: EthSpec>  Txnss<T> for  ExecTxs<T>{
    fn hash_tree_root(&self) -> Hash256{
        Hash256::zero()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
struct ExecTxs<T: EthSpec> = VariableList<Transaction<<T as EthSpec>::MaxBytesPerTransaction>, <T as EthSpec>::MaxTransactionsPerPayload>;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct ExecutionPayload< T: EthSpec, Txns : Txnss<T>> {
    pub parent_hash: Hash256,
    pub fee_recipient: Address,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
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
    #[serde(with = "eth2_serde_utils::quoted_u256")]
    pub base_fee_per_gas: Uint256,
    pub block_hash: Hash256,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Txns,
}

impl< T: EthSpec, Txns : Txnss<T>> ExecutionPayload<T, Txns> {
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
