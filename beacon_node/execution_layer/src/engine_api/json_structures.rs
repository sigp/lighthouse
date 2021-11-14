//! Contains an implementation of `EngineAPI` using the JSON-RPC API via HTTP.

use super::*;
use serde::{Deserialize, Serialize};
use types::{EthSpec, FixedVector, Transaction, Unsigned, VariableList};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonRequestBody<'a> {
    pub jsonrpc: &'a str,
    pub method: &'a str,
    pub params: serde_json::Value,
    pub id: u32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonResponseBody {
    pub jsonrpc: String,
    #[serde(default)]
    pub error: Option<JsonError>,
    #[serde(default)]
    pub result: serde_json::Value,
    pub id: u32,
}

/// On the request, just provide the `payload_id`, without the object wrapper (transparent).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent, rename_all = "camelCase")]
pub struct JsonPayloadIdRequest {
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub payload_id: u64,
}

/// On the response, expect without the object wrapper (non-transparent).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPayloadIdResponse {
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub payload_id: u64,
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec", rename_all = "camelCase")]
pub struct JsonExecutionPayloadV1<T: EthSpec> {
    pub parent_hash: Hash256,
    pub coinbase: Address,
    pub state_root: Hash256,
    pub receipt_root: Hash256,
    #[serde(with = "serde_logs_bloom")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    pub random: Hash256,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub block_number: u64,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub gas_limit: u64,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub gas_used: u64,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    pub base_fee_per_gas: Uint256,
    pub block_hash: Hash256,
    #[serde(with = "serde_transactions")]
    pub transactions:
        VariableList<Transaction<T::MaxBytesPerTransaction>, T::MaxTransactionsPerPayload>,
}

impl<T: EthSpec> From<ExecutionPayload<T>> for JsonExecutionPayloadV1<T> {
    fn from(e: ExecutionPayload<T>) -> Self {
        Self {
            parent_hash: e.parent_hash,
            coinbase: e.coinbase,
            state_root: e.state_root,
            receipt_root: e.receipt_root,
            logs_bloom: e.logs_bloom,
            random: e.random,
            block_number: e.block_number,
            gas_limit: e.gas_limit,
            gas_used: e.gas_used,
            timestamp: e.timestamp,
            extra_data: e.extra_data,
            base_fee_per_gas: e.base_fee_per_gas,
            block_hash: e.block_hash,
            transactions: e.transactions,
        }
    }
}

impl<T: EthSpec> From<JsonExecutionPayloadV1<T>> for ExecutionPayload<T> {
    fn from(e: JsonExecutionPayloadV1<T>) -> Self {
        Self {
            parent_hash: e.parent_hash,
            coinbase: e.coinbase,
            state_root: e.state_root,
            receipt_root: e.receipt_root,
            logs_bloom: e.logs_bloom,
            random: e.random,
            block_number: e.block_number,
            gas_limit: e.gas_limit,
            gas_used: e.gas_used,
            timestamp: e.timestamp,
            extra_data: e.extra_data,
            base_fee_per_gas: e.base_fee_per_gas,
            block_hash: e.block_hash,
            transactions: e.transactions,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPayloadAttributesV1 {
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub timestamp: u64,
    pub random: Hash256,
    pub fee_recipient: Address,
}

impl From<PayloadAttributes> for JsonPayloadAttributesV1 {
    fn from(p: PayloadAttributes) -> Self {
        Self {
            timestamp: p.timestamp,
            random: p.random,
            fee_recipient: p.fee_recipient,
        }
    }
}

impl From<JsonPayloadAttributesV1> for PayloadAttributes {
    fn from(j: JsonPayloadAttributesV1) -> Self {
        Self {
            timestamp: j.timestamp,
            random: j.random,
            fee_recipient: j.fee_recipient,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonForkChoiceStateV1 {
    pub head_block_hash: Hash256,
    pub safe_block_hash: Hash256,
    pub finalized_block_hash: Hash256,
}

impl From<ForkChoiceState> for JsonForkChoiceStateV1 {
    fn from(f: ForkChoiceState) -> Self {
        Self {
            head_block_hash: f.head_block_hash,
            safe_block_hash: f.safe_block_hash,
            finalized_block_hash: f.finalized_block_hash,
        }
    }
}

impl From<JsonForkChoiceStateV1> for ForkChoiceState {
    fn from(j: JsonForkChoiceStateV1) -> Self {
        Self {
            head_block_hash: j.head_block_hash,
            safe_block_hash: j.safe_block_hash,
            finalized_block_hash: j.finalized_block_hash,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JsonExecutePayloadV1ResponseStatus {
    Valid,
    Invalid,
    Syncing,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonExecutePayloadV1Response {
    pub status: JsonExecutePayloadV1ResponseStatus,
    pub latest_valid_hash: Option<Hash256>,
    pub message: Option<String>,
}

impl From<ExecutePayloadResponseStatus> for JsonExecutePayloadV1ResponseStatus {
    fn from(e: ExecutePayloadResponseStatus) -> Self {
        match e {
            ExecutePayloadResponseStatus::Valid => JsonExecutePayloadV1ResponseStatus::Valid,
            ExecutePayloadResponseStatus::Invalid => JsonExecutePayloadV1ResponseStatus::Invalid,
            ExecutePayloadResponseStatus::Syncing => JsonExecutePayloadV1ResponseStatus::Syncing,
        }
    }
}
impl From<JsonExecutePayloadV1ResponseStatus> for ExecutePayloadResponseStatus {
    fn from(j: JsonExecutePayloadV1ResponseStatus) -> Self {
        match j {
            JsonExecutePayloadV1ResponseStatus::Valid => ExecutePayloadResponseStatus::Valid,
            JsonExecutePayloadV1ResponseStatus::Invalid => ExecutePayloadResponseStatus::Invalid,
            JsonExecutePayloadV1ResponseStatus::Syncing => ExecutePayloadResponseStatus::Syncing,
        }
    }
}

impl From<ExecutePayloadResponse> for JsonExecutePayloadV1Response {
    fn from(e: ExecutePayloadResponse) -> Self {
        Self {
            status: e.status.into(),
            latest_valid_hash: e.latest_valid_hash,
            message: e.message,
        }
    }
}

impl From<JsonExecutePayloadV1Response> for ExecutePayloadResponse {
    fn from(j: JsonExecutePayloadV1Response) -> Self {
        Self {
            status: j.status.into(),
            latest_valid_hash: j.latest_valid_hash,
            message: j.message,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JsonForkchoiceUpdatedV1ResponseStatus {
    Success,
    Syncing,
}
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonForkchoiceUpdatedV1Response {
    pub status: JsonForkchoiceUpdatedV1ResponseStatus,
    #[serde(with = "opt_u64_hex_be")]
    pub payload_id: Option<PayloadId>,
}

impl From<JsonForkchoiceUpdatedV1ResponseStatus> for ForkchoiceUpdatedResponseStatus {
    fn from(j: JsonForkchoiceUpdatedV1ResponseStatus) -> Self {
        match j {
            JsonForkchoiceUpdatedV1ResponseStatus::Success => {
                ForkchoiceUpdatedResponseStatus::Success
            }
            JsonForkchoiceUpdatedV1ResponseStatus::Syncing => {
                ForkchoiceUpdatedResponseStatus::Syncing
            }
        }
    }
}
impl From<ForkchoiceUpdatedResponseStatus> for JsonForkchoiceUpdatedV1ResponseStatus {
    fn from(f: ForkchoiceUpdatedResponseStatus) -> Self {
        match f {
            ForkchoiceUpdatedResponseStatus::Success => {
                JsonForkchoiceUpdatedV1ResponseStatus::Success
            }
            ForkchoiceUpdatedResponseStatus::Syncing => {
                JsonForkchoiceUpdatedV1ResponseStatus::Syncing
            }
        }
    }
}
impl From<JsonForkchoiceUpdatedV1Response> for ForkchoiceUpdatedResponse {
    fn from(j: JsonForkchoiceUpdatedV1Response) -> Self {
        Self {
            status: j.status.into(),
            payload_id: j.payload_id,
        }
    }
}
impl From<ForkchoiceUpdatedResponse> for JsonForkchoiceUpdatedV1Response {
    fn from(f: ForkchoiceUpdatedResponse) -> Self {
        Self {
            status: f.status.into(),
            payload_id: f.payload_id,
        }
    }
}

pub mod opt_u64_hex_be {
    use serde::de::{Error, Visitor};
    use serde::{Deserialize, Deserializer, Serializer};

    struct OptWrapper(Option<u64>);
    impl<'de> Deserialize<'de> for OptWrapper {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct OptVisitor;
            const BYTES_LEN: usize = 8;
            impl<'de> Visitor<'de> for OptVisitor {
                type Value = OptWrapper;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a hex string")
                }

                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where
                    E: Error,
                {
                    if value.eq("null") {
                        return Ok(OptWrapper(None));
                    }
                    if let Some(stripped) = value.strip_prefix("0x") {
                        if stripped.is_empty() {
                            // the string '0x' is often used for null..
                            // at least it is in many of the geth test vectors
                            // TODO: verify it's valid in this context
                            return Ok(OptWrapper(None));
                        }
                        let bytes_vec = hex::decode(stripped)
                            .map_err(|e| Error::custom(format!("invalid hex: {:?}", e)))?;
                        // TODO: are they allowed to send us less than 8 bytes?
                        if bytes_vec.len() > BYTES_LEN {
                            return Err(Error::custom(format!(
                                "expected max {} bytes for array, got {}",
                                BYTES_LEN,
                                bytes_vec.len()
                            )));
                        }
                        let mut bytes_array = [0; BYTES_LEN];
                        bytes_array[BYTES_LEN - bytes_vec.len()..].copy_from_slice(&bytes_vec);
                        Ok(OptWrapper(Some(u64::from_be_bytes(bytes_array))))
                    } else {
                        Err(Error::custom(format!("must start with 0x")))
                    }
                }
            }

            deserializer.deserialize_str(OptVisitor)
        }
    }

    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            None => serializer.serialize_str("null"),
            Some(num) => serializer.serialize_str(&format!("0x{}", hex::encode(num.to_be_bytes()))),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_wrapper = OptWrapper::deserialize(deserializer)?;
        Ok(opt_wrapper.0)
    }
}

/// Serializes the `logs_bloom` field of an `ExecutionPayload`.
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

/// Serializes the `transactions` field of an `ExecutionPayload`.
pub mod serde_transactions {
    use super::*;
    use eth2_serde_utils::hex;
    use serde::ser::SerializeSeq;
    use serde::{de, Deserializer, Serializer};
    use std::marker::PhantomData;

    type Value<M, N> = VariableList<Transaction<M>, N>;

    #[derive(Default)]
    pub struct ListOfBytesListVisitor<M, N> {
        _phantom_m: PhantomData<M>,
        _phantom_n: PhantomData<N>,
    }

    impl<'a, M: Unsigned, N: Unsigned> serde::de::Visitor<'a> for ListOfBytesListVisitor<M, N> {
        type Value = Value<M, N>;

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
                let transaction = VariableList::new(inner_vec).map_err(|e| {
                    serde::de::Error::custom(format!("transaction too large: {:?}", e))
                })?;
                outer.push(transaction).map_err(|e| {
                    serde::de::Error::custom(format!("too many transactions: {:?}", e))
                })?;
            }

            Ok(outer)
        }
    }

    pub fn serialize<S, M: Unsigned, N: Unsigned>(
        value: &Value<M, N>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for transaction in value {
            // It's important to match on the inner values of the transaction. Serializing the
            // entire `Transaction` will result in appending the SSZ union prefix byte. The
            // execution node does not want that.
            let hex = hex::encode(&transaction[..]);
            seq.serialize_element(&hex)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, M: Unsigned, N: Unsigned>(
        deserializer: D,
    ) -> Result<Value<M, N>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let visitor: ListOfBytesListVisitor<M, N> = <_>::default();
        deserializer.deserialize_any(visitor)
    }
}
