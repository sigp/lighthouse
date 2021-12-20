use crate::{test_utils::TestRandom, *};
use serde::de::DeserializeOwned;
use serde::{Serialize as Ser, Serializer};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::fmt::Debug;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type Transaction<T> = VariableList<u8, T>;
pub type BlindedTransactions = Hash256;

// pub type ExecTransactions<T> = VariableList<Transaction<<T as EthSpec>::MaxBytesPerTransaction>, <T as EthSpec>::MaxTransactionsPerPayload>;

// impl<T: EthSpec> Ser for ExecTransactions<T> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//         where
//             S: Serializer{
//     }
// }

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecTransactions<T: EthSpec>(
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub  VariableList<
        Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
        <T as EthSpec>::MaxTransactionsPerPayload,
    >,
);

impl<T: EthSpec> TreeHash for ExecTransactions<T> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl<T: EthSpec> TestRandom for ExecTransactions<T> {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        ExecTransactions(<VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as TestRandom>::random_for_test(rng))
    }
}

impl<T: EthSpec> Decode for ExecTransactions<T> {
    fn is_ssz_fixed_len() -> bool {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as Decode>::is_ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as Decode>::from_ssz_bytes(bytes)
        .map(ExecTransactions)
    }
}

impl<T: EthSpec> Encode for ExecTransactions<T> {
    fn is_ssz_fixed_len() -> bool {
        <VariableList<
            Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
            <T as EthSpec>::MaxTransactionsPerPayload,
        > as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }
}


//FIXME(sean) Is it ok this is DeserializeOwned? Don't need a trait lifetime if it's owned
pub trait Transactions<T>: Encode + Decode + TestRandom + TreeHash + Default + PartialEq + Ser + DeserializeOwned {}

impl<T: EthSpec> Transactions<T> for ExecTransactions<T> {}
impl<T: EthSpec> Transactions<T> for BlindedTransactions {}

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[serde(bound = "Txns: Transactions<T>")]
pub struct ExecutionPayload<T: EthSpec, Txns: Transactions<T> = ExecTransactions<T>> {
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
