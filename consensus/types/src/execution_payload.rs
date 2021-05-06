use crate::{test_utils::TestRandom, *};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

// TODO: move this into `EthSpec`.
pub type BytesPerLogsBloom = ssz_types::typenum::U256;
pub type MaxExecutionTransactions = ssz_types::typenum::U16384;
pub type MaxBytesPerOpaqueTransaction = ssz_types::typenum::U1048576;
pub type Transactions =
    VariableList<VariableList<u8, MaxBytesPerOpaqueTransaction>, MaxExecutionTransactions>;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Default, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct ExecutionPayload {
    pub block_hash: Hash256,
    pub parent_hash: Hash256,
    pub coinbase: Address,
    pub state_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub timestamp: u64,
    pub receipt_root: Hash256,
    #[serde(with = "serde_logs_bloom")]
    pub logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
    #[serde(with = "serde_transactions")]
    pub transactions: Transactions,
}

/// Serializes the `logs_bloom` field.
pub mod serde_logs_bloom {
    use super::*;
    use serde::{Deserializer, Serializer};
    use serde_utils::hex::PrefixedHexVisitor;

    pub fn serialize<S>(
        bytes: &FixedVector<u8, BytesPerLogsBloom>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut hex_string: String = "0x".to_string();
        hex_string.push_str(&hex::encode(&bytes[..]));

        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<FixedVector<u8, BytesPerLogsBloom>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = deserializer.deserialize_string(PrefixedHexVisitor)?;

        FixedVector::new(vec)
            .map_err(|e| serde::de::Error::custom(format!("invalid logs bloom: {:?}", e)))
    }
}

/// Serializes the `transactions` field.
pub mod serde_transactions {
    use super::*;
    use serde::ser::SerializeSeq;
    use serde::{de, Deserializer, Serializer};
    use serde_utils::hex;

    pub struct ListOfBytesListVisitor;
    impl<'a> serde::de::Visitor<'a> for ListOfBytesListVisitor {
        type Value = Transactions;

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

    pub fn serialize<S>(value: &Transactions, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for val in value {
            seq.serialize_element(&hex::encode(&val[..]))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Transactions, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ListOfBytesListVisitor)
    }
}
