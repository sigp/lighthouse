use super::*;
use serde::{Deserialize, Serialize};
use types::{EthSpec, FixedVector, Transactions, Unsigned, VariableList};

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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransparentJsonPayloadId(#[serde(with = "eth2_serde_utils::bytes_8_hex")] pub PayloadId);

impl From<PayloadId> for TransparentJsonPayloadId {
    fn from(id: PayloadId) -> Self {
        Self(id)
    }
}

impl From<TransparentJsonPayloadId> for PayloadId {
    fn from(wrapper: TransparentJsonPayloadId) -> Self {
        wrapper.0
    }
}

/// On the request, use a transparent wrapper.
pub type JsonPayloadIdRequest = TransparentJsonPayloadId;

/// On the response, expect without the object wrapper (non-transparent).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPayloadIdResponse {
    #[serde(with = "eth2_serde_utils::bytes_8_hex")]
    pub payload_id: PayloadId,
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec", rename_all = "camelCase")]
pub struct JsonExecutionPayloadHeaderV1<T: EthSpec, Txns: Transactions<T>> {
    pub parent_hash: Hash256,
    pub fee_recipient: Address,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
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
    pub transactions_root: Txns,
}

impl<T: EthSpec, Txns: Transactions<T>> From<JsonExecutionPayloadHeaderV1<T, Txns>>
    for ExecutionPayload<T, Txns>
{
    fn from(e: JsonExecutionPayloadHeaderV1<T, Txns>) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonExecutionPayloadHeaderV1 {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            random,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions_root,
        } = e;

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            random,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions: transactions_root,
        }
    }
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec", rename_all = "camelCase")]
pub struct JsonExecutionPayloadV1<T: EthSpec, Txns: Transactions<T>> {
    pub parent_hash: Hash256,
    pub fee_recipient: Address,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
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
    pub transactions: Txns,
}

impl<T: EthSpec, Txns: Transactions<T>> From<ExecutionPayload<T, Txns>>
    for JsonExecutionPayloadV1<T, Txns>
{
    fn from(e: ExecutionPayload<T, Txns>) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let ExecutionPayload {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            random,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
        } = e;

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            random,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
        }
    }
}

impl<T: EthSpec, Txns: Transactions<T>> From<JsonExecutionPayloadV1<T, Txns>>
    for ExecutionPayload<T, Txns>
{
    fn from(e: JsonExecutionPayloadV1<T, Txns>) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonExecutionPayloadV1 {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            random,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
        } = e;

        Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            random,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPayloadAttributesV1 {
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub timestamp: u64,
    pub random: Hash256,
    pub suggested_fee_recipient: Address,
}

impl From<PayloadAttributes> for JsonPayloadAttributesV1 {
    fn from(p: PayloadAttributes) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let PayloadAttributes {
            timestamp,
            random,
            suggested_fee_recipient,
        } = p;

        Self {
            timestamp,
            random,
            suggested_fee_recipient,
        }
    }
}

impl From<JsonPayloadAttributesV1> for PayloadAttributes {
    fn from(j: JsonPayloadAttributesV1) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonPayloadAttributesV1 {
            timestamp,
            random,
            suggested_fee_recipient,
        } = j;

        Self {
            timestamp,
            random,
            suggested_fee_recipient,
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
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let ForkChoiceState {
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
        } = f;

        Self {
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
        }
    }
}

impl From<JsonForkChoiceStateV1> for ForkChoiceState {
    fn from(j: JsonForkChoiceStateV1) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonForkChoiceStateV1 {
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
        } = j;

        Self {
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
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
    pub validation_error: Option<String>,
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
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let ExecutePayloadResponse {
            status,
            latest_valid_hash,
            validation_error,
        } = e;

        Self {
            status: status.into(),
            latest_valid_hash,
            validation_error,
        }
    }
}

impl From<JsonExecutePayloadV1Response> for ExecutePayloadResponse {
    fn from(j: JsonExecutePayloadV1Response) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonExecutePayloadV1Response {
            status,
            latest_valid_hash,
            validation_error,
        } = j;

        Self {
            status: status.into(),
            latest_valid_hash,
            validation_error,
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
    pub payload_id: Option<TransparentJsonPayloadId>,
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
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonForkchoiceUpdatedV1Response { status, payload_id } = j;

        Self {
            status: status.into(),
            payload_id: payload_id.map(Into::into),
        }
    }
}
impl From<ForkchoiceUpdatedResponse> for JsonForkchoiceUpdatedV1Response {
    fn from(f: ForkchoiceUpdatedResponse) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let ForkchoiceUpdatedResponse { status, payload_id } = f;

        Self {
            status: status.into(),
            payload_id: payload_id.map(Into::into),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JsonProposeBlindedBlockResponseStatus {
    Valid,
    Invalid,
    Syncing,
}
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "E: EthSpec")]
pub struct JsonProposeBlindedBlockResponse<E: EthSpec> {
    pub result: ExecutionPayload<E>,
    pub error: Option<String>,
}

impl<E: EthSpec> From<JsonProposeBlindedBlockResponse<E>> for ExecutionPayload<E> {
    fn from(j: JsonProposeBlindedBlockResponse<E>) -> Self {
        let JsonProposeBlindedBlockResponse { result, error: _ } = j;
        result
    }
}

impl From<JsonProposeBlindedBlockResponseStatus> for ProposeBlindedBlockResponseStatus {
    fn from(j: JsonProposeBlindedBlockResponseStatus) -> Self {
        match j {
            JsonProposeBlindedBlockResponseStatus::Valid => {
                ProposeBlindedBlockResponseStatus::Valid
            }
            JsonProposeBlindedBlockResponseStatus::Invalid => {
                ProposeBlindedBlockResponseStatus::Invalid
            }
            JsonProposeBlindedBlockResponseStatus::Syncing => {
                ProposeBlindedBlockResponseStatus::Syncing
            }
        }
    }
}
impl From<ProposeBlindedBlockResponseStatus> for JsonProposeBlindedBlockResponseStatus {
    fn from(f: ProposeBlindedBlockResponseStatus) -> Self {
        match f {
            ProposeBlindedBlockResponseStatus::Valid => {
                JsonProposeBlindedBlockResponseStatus::Valid
            }
            ProposeBlindedBlockResponseStatus::Invalid => {
                JsonProposeBlindedBlockResponseStatus::Invalid
            }
            ProposeBlindedBlockResponseStatus::Syncing => {
                JsonProposeBlindedBlockResponseStatus::Syncing
            }
        }
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
    use serde::{de, Deserializer, Serializer};
    use std::marker::PhantomData;
    use types::execution_payload::BlockType;
    use types::Transactions;

    // type Value<M, N> = VariableList<Transaction<M>, N>;
    type Value<Txns> = Txns;

    #[derive(Default)]
    pub struct TxnVisitor<E, Txns> {
        _phantom_e: PhantomData<E>,
        _phantom_txn: PhantomData<Txns>,
    }

    impl<'a, E: EthSpec, Txns: Transactions<E>> serde::de::Visitor<'a> for TxnVisitor<E, Txns> {
        type Value = Value<Txns>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            match Txns::block_type() {
                BlockType::Full => write!(formatter, "a list of 0x-prefixed byte lists"),
                BlockType::Blinded => write!(formatter, "32 bytes hex-encoded"),
            }
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'a>,
        {
            Self::Value::visit_seq_execution(seq)
        }

        fn visit_string<Err>(self, v: String) -> Result<Self::Value, Err>
        where
            Err: de::Error,
        {
            Self::Value::visit_string_execution(v)
        }
    }

    pub fn serialize<S, E: EthSpec, Txns: Transactions<E>>(
        value: &Value<Txns>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.serialize_execution(serializer)
    }

    pub fn deserialize<'de, D, E: EthSpec, Txns: Transactions<E>>(
        deserializer: D,
    ) -> Result<Value<Txns>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let visitor: TxnVisitor<E, Txns> = <_>::default();
        deserializer.deserialize_any(visitor)
    }
}
