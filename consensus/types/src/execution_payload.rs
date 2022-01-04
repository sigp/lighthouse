use crate::{test_utils::TestRandom, *};
use eth2_serde_utils::hex;
use serde::de::DeserializeOwned;
use serde::ser::SerializeSeq;
use serde::{de, Serialize as Ser, Serializer};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::fmt::Debug;
use std::str::FromStr;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type Transaction<T> = VariableList<u8, T>;
pub type BlindedTransactions = Hash256;

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

pub enum BlockType {
    Full,
    Blinded,
}

//FIXME(sean) Is it ok this is DeserializeOwned? Don't need a trait lifetime if it's owned
pub trait Transactions<T>:
    Encode + Decode + TestRandom + TreeHash + Default + PartialEq + Ser + DeserializeOwned
{
    fn block_type() -> BlockType;
    fn serialize_execution<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;
    fn visit_seq_execution<'a, A: serde::de::SeqAccess<'a>>(seq: A) -> Result<Self, A::Error>;
    fn visit_string_execution<E>(v: String) -> Result<Self, E>
    where
        E: de::Error;
}

impl<T: EthSpec> Transactions<T> for ExecTransactions<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn visit_seq_execution<'a, A>(mut seq: A) -> Result<Self, A::Error>
    where
        A: serde::de::SeqAccess<'a>,
    {
        let mut outer: ExecTransactions<T> = ExecTransactions::default();

        while let Some(val) = seq.next_element::<String>()? {
            let inner_vec = hex::decode(&val).map_err(de::Error::custom)?;
            let transaction: Transaction<T::MaxBytesPerTransaction> = VariableList::new(inner_vec)
                .map_err(|e| serde::de::Error::custom(format!("transaction too large: {:?}", e)))?;
            outer
                .0
                .push(transaction)
                .map_err(|e| serde::de::Error::custom(format!("too many transactions: {:?}", e)))?;
        }

        Ok(outer)
    }

    fn serialize_execution<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for transaction in self.0.iter() {
            // It's important to match on the inner values of the transaction. Serializing the
            // entire `Transaction` will result in appending the SSZ union prefix byte. The
            // execution node does not want that.
            let hex = hex::encode(&transaction[..]);
            seq.serialize_element(&hex)?;
        }
        seq.end()
    }
    fn visit_string_execution<E>(v: String) -> Result<Self, E>
    where
        E: de::Error,
    {
        Err(serde::de::Error::custom(format!(
            "cannot deserialize {} as executable transactions",
            v
        )))
    }
}

impl<T: EthSpec> Transactions<T> for BlindedTransactions {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn serialize_execution<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }

    fn visit_seq_execution<'a, A>(mut seq: A) -> Result<Self, A::Error>
    where
        A: serde::de::SeqAccess<'a>,
    {
        let val = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::custom("empty transactions root field"))?;
        let inner_vec = hex::decode(&val).map_err(de::Error::custom)?;
        Ok(Hash256::from_slice(&inner_vec))
    }
    fn visit_string_execution<E>(v: String) -> Result<Self, E>
    where
        E: de::Error,
    {
        Hash256::from_str(&v).map_err(de::Error::custom)
    }
}

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[serde(bound = "Txns: Transactions<T>", deny_unknown_fields)]
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
