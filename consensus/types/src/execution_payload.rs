use crate::{test_utils::TestRandom, *};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::{ops::Index, slice::SliceIndex};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[ssz(enum_behaviour = "union")]
#[tree_hash(enum_behaviour = "union")]
pub enum Transaction<T: EthSpec> {
    OpaqueTransaction(VariableList<u8, T::MaxBytesPerOpaqueTransaction>),
}

impl<T: EthSpec, I: SliceIndex<[u8]>> Index<I> for Transaction<T> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        match self {
            Self::OpaqueTransaction(v) => Index::index(v, index),
        }
    }
}

impl<T: EthSpec> From<VariableList<u8, T::MaxBytesPerOpaqueTransaction>> for Transaction<T> {
    fn from(list: VariableList<u8, <T as EthSpec>::MaxBytesPerOpaqueTransaction>) -> Self {
        Self::OpaqueTransaction(list)
    }
}

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct ExecutionPayload<T: EthSpec> {
    pub parent_hash: Hash256,
    pub coinbase: Address,
    pub state_root: Hash256,
    pub receipt_root: Hash256,
    #[serde(with = "serde_logs_bloom")]
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
    #[serde(with = "serde_transactions")]
    #[test_random(default)]
    pub transactions: VariableList<Transaction<T>, T::MaxTransactionsPerPayload>,
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
            base_fee_per_gas: Hash256::zero(),
            block_hash: Hash256::zero(),
            transactions: VariableList::empty(),
        }
    }
}

/// Serializes the `logs_bloom` field.
pub mod serde_logs_bloom {
    use super::*;
    use eth2_serde_utils::hex::PrefixedHexVisitor;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S, U>(bytes: &FixedVector<u8, U>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        U: Unsigned,
    {
        let mut hex_string: String = "0x".to_string();
        hex_string.push_str(&hex::encode(&bytes[..]));

        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D, U>(deserializer: D) -> Result<FixedVector<u8, U>, D::Error>
    where
        D: Deserializer<'de>,
        U: Unsigned,
    {
        let vec = deserializer.deserialize_string(PrefixedHexVisitor)?;

        FixedVector::new(vec)
            .map_err(|e| serde::de::Error::custom(format!("invalid logs bloom: {:?}", e)))
    }
}

/// Serializes the `transactions` field.
pub mod serde_transactions {
    use super::*;
    use eth2_serde_utils::hex;
    use serde::ser::SerializeSeq;
    use serde::{de, Deserializer, Serializer};
    use std::marker::PhantomData;

    pub struct ListOfBytesListVisitor<T: EthSpec> {
        _t: PhantomData<T>,
    }
    impl<'a, T> serde::de::Visitor<'a> for ListOfBytesListVisitor<T>
    where
        T: EthSpec,
    {
        type Value = VariableList<Transaction<T>, T::MaxTransactionsPerPayload>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "a list of 0x-prefixed byte lists")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'a>,
        {
            let mut outer = VariableList::default();

            while let Some(val) = seq.next_element::<String>()? {
                let inner_vec = hex::decode(&val).map_err(de::Error::custom)?;
                let inner = VariableList::new(inner_vec).map_err(|e| {
                    serde::de::Error::custom(format!("invalid transaction: {:?}", e))
                })?;
                outer.push(inner.into()).map_err(|e| {
                    serde::de::Error::custom(format!("too many transactions: {:?}", e))
                })?;
            }

            Ok(outer)
        }
    }

    pub fn serialize<S, T>(
        value: &VariableList<Transaction<T>, T::MaxTransactionsPerPayload>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: EthSpec,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for val in value {
            seq.serialize_element(&hex::encode(&val[..]))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T>(
        deserializer: D,
    ) -> Result<VariableList<Transaction<T>, T::MaxTransactionsPerPayload>, D::Error>
    where
        D: Deserializer<'de>,
        T: EthSpec,
    {
        deserializer.deserialize_any(ListOfBytesListVisitor { _t: PhantomData })
    }
}
