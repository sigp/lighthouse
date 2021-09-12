use crate::{test_utils::TestRandom, *};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

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
    pub transactions: VariableList<
        VariableList<u8, T::MaxBytesPerOpaqueTransaction>,
        T::MaxTransactionsPerPayload,
    >,
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

    pub struct ListOfBytesListVisitor<U, V> {
        _u: PhantomData<U>,
        _v: PhantomData<V>,
    }

    impl<'a, U, V> serde::de::Visitor<'a> for ListOfBytesListVisitor<U, V>
    where
        U: Unsigned,
        V: Unsigned,
    {
        type Value = VariableList<VariableList<u8, U>, V>;

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
                outer.push(inner).map_err(|e| {
                    serde::de::Error::custom(format!("too many transactions: {:?}", e))
                })?;
            }

            Ok(outer)
        }
    }

    pub fn serialize<S, U, V>(
        value: &VariableList<VariableList<u8, U>, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        U: Unsigned,
        V: Unsigned,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for val in value {
            seq.serialize_element(&hex::encode(&val[..]))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, U, V>(
        deserializer: D,
    ) -> Result<VariableList<VariableList<u8, U>, V>, D::Error>
    where
        D: Deserializer<'de>,
        U: Unsigned,
        V: Unsigned,
    {
        deserializer.deserialize_any(ListOfBytesListVisitor {
            _u: PhantomData,
            _v: PhantomData,
        })
    }
}
