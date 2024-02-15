use super::*;
use alloy_rlp::RlpEncodable;
use serde::{Deserialize, Serialize};
use strum::EnumString;
use superstruct::superstruct;
use types::beacon_block_body::KzgCommitments;
use types::blob_sidecar::BlobsList;
use types::{
    EthSpec, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadCapella, ExecutionPayloadDeneb,
    ExecutionPayloadMerge, FixedVector, Transactions, Unsigned, VariableList, Withdrawal,
};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonRequestBody<'a> {
    pub jsonrpc: &'a str,
    pub method: &'a str,
    pub params: serde_json::Value,
    pub id: serde_json::Value,
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
    pub id: serde_json::Value,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransparentJsonPayloadId(#[serde(with = "serde_utils::bytes_8_hex")] pub PayloadId);

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
    #[serde(with = "serde_utils::bytes_8_hex")]
    pub payload_id: PayloadId,
}

#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(
        derive(Debug, PartialEq, Default, Serialize, Deserialize,),
        serde(bound = "T: EthSpec", rename_all = "camelCase"),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec", rename_all = "camelCase", untagged)]
pub struct JsonExecutionPayload<T: EthSpec> {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: Address,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
    #[serde(with = "serde_logs_bloom")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    pub prev_randao: Hash256,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub block_number: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    #[serde(with = "serde_utils::u256_hex_be")]
    pub base_fee_per_gas: Uint256,
    pub block_hash: ExecutionBlockHash,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions<T>,
    #[superstruct(only(V2, V3))]
    pub withdrawals: VariableList<JsonWithdrawal, T::MaxWithdrawalsPerPayload>,
    #[superstruct(only(V3))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub blob_gas_used: u64,
    #[superstruct(only(V3))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub excess_blob_gas: u64,
}

impl<T: EthSpec> From<ExecutionPayloadMerge<T>> for JsonExecutionPayloadV1<T> {
    fn from(payload: ExecutionPayloadMerge<T>) -> Self {
        JsonExecutionPayloadV1 {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
        }
    }
}
impl<T: EthSpec> From<ExecutionPayloadCapella<T>> for JsonExecutionPayloadV2<T> {
    fn from(payload: ExecutionPayloadCapella<T>) -> Self {
        JsonExecutionPayloadV2 {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
            withdrawals: payload
                .withdrawals
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}
impl<T: EthSpec> From<ExecutionPayloadDeneb<T>> for JsonExecutionPayloadV3<T> {
    fn from(payload: ExecutionPayloadDeneb<T>) -> Self {
        JsonExecutionPayloadV3 {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
            withdrawals: payload
                .withdrawals
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
        }
    }
}

impl<T: EthSpec> From<ExecutionPayload<T>> for JsonExecutionPayload<T> {
    fn from(execution_payload: ExecutionPayload<T>) -> Self {
        match execution_payload {
            ExecutionPayload::Merge(payload) => JsonExecutionPayload::V1(payload.into()),
            ExecutionPayload::Capella(payload) => JsonExecutionPayload::V2(payload.into()),
            ExecutionPayload::Deneb(payload) => JsonExecutionPayload::V3(payload.into()),
        }
    }
}

impl<T: EthSpec> From<JsonExecutionPayloadV1<T>> for ExecutionPayloadMerge<T> {
    fn from(payload: JsonExecutionPayloadV1<T>) -> Self {
        ExecutionPayloadMerge {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
        }
    }
}
impl<T: EthSpec> From<JsonExecutionPayloadV2<T>> for ExecutionPayloadCapella<T> {
    fn from(payload: JsonExecutionPayloadV2<T>) -> Self {
        ExecutionPayloadCapella {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
            withdrawals: payload
                .withdrawals
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}
impl<T: EthSpec> From<JsonExecutionPayloadV3<T>> for ExecutionPayloadDeneb<T> {
    fn from(payload: JsonExecutionPayloadV3<T>) -> Self {
        ExecutionPayloadDeneb {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
            withdrawals: payload
                .withdrawals
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
        }
    }
}

impl<T: EthSpec> From<JsonExecutionPayload<T>> for ExecutionPayload<T> {
    fn from(json_execution_payload: JsonExecutionPayload<T>) -> Self {
        match json_execution_payload {
            JsonExecutionPayload::V1(payload) => ExecutionPayload::Merge(payload.into()),
            JsonExecutionPayload::V2(payload) => ExecutionPayload::Capella(payload.into()),
            JsonExecutionPayload::V3(payload) => ExecutionPayload::Deneb(payload.into()),
        }
    }
}

#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(
        derive(Debug, PartialEq, Serialize, Deserialize),
        serde(bound = "T: EthSpec", rename_all = "camelCase")
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub struct JsonGetPayloadResponse<T: EthSpec> {
    #[superstruct(only(V1), partial_getter(rename = "execution_payload_v1"))]
    pub execution_payload: JsonExecutionPayloadV1<T>,
    #[superstruct(only(V2), partial_getter(rename = "execution_payload_v2"))]
    pub execution_payload: JsonExecutionPayloadV2<T>,
    #[superstruct(only(V3), partial_getter(rename = "execution_payload_v3"))]
    pub execution_payload: JsonExecutionPayloadV3<T>,
    #[serde(with = "serde_utils::u256_hex_be")]
    pub block_value: Uint256,
    #[superstruct(only(V3))]
    pub blobs_bundle: JsonBlobsBundleV1<T>,
    #[superstruct(only(V3))]
    pub should_override_builder: bool,
}

impl<T: EthSpec> From<JsonGetPayloadResponse<T>> for GetPayloadResponse<T> {
    fn from(json_get_payload_response: JsonGetPayloadResponse<T>) -> Self {
        match json_get_payload_response {
            JsonGetPayloadResponse::V1(response) => {
                GetPayloadResponse::Merge(GetPayloadResponseMerge {
                    execution_payload: response.execution_payload.into(),
                    block_value: response.block_value,
                })
            }
            JsonGetPayloadResponse::V2(response) => {
                GetPayloadResponse::Capella(GetPayloadResponseCapella {
                    execution_payload: response.execution_payload.into(),
                    block_value: response.block_value,
                })
            }
            JsonGetPayloadResponse::V3(response) => {
                GetPayloadResponse::Deneb(GetPayloadResponseDeneb {
                    execution_payload: response.execution_payload.into(),
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle.into(),
                    should_override_builder: response.should_override_builder,
                })
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonWithdrawal {
    #[serde(with = "serde_utils::u64_hex_be")]
    pub index: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub amount: u64,
}

impl From<Withdrawal> for JsonWithdrawal {
    fn from(withdrawal: Withdrawal) -> Self {
        Self {
            index: withdrawal.index,
            validator_index: withdrawal.validator_index,
            address: withdrawal.address,
            amount: withdrawal.amount,
        }
    }
}

impl From<JsonWithdrawal> for Withdrawal {
    fn from(jw: JsonWithdrawal) -> Self {
        Self {
            index: jw.index,
            validator_index: jw.validator_index,
            address: jw.address,
            amount: jw.amount,
        }
    }
}
#[derive(Debug, PartialEq, Clone, RlpEncodable)]
pub struct EncodableJsonWithdrawal<'a> {
    pub index: u64,
    pub validator_index: u64,
    pub address: &'a [u8],
    pub amount: u64,
}

impl<'a> From<&'a JsonWithdrawal> for EncodableJsonWithdrawal<'a> {
    fn from(json_withdrawal: &'a JsonWithdrawal) -> Self {
        Self {
            index: json_withdrawal.index,
            validator_index: json_withdrawal.validator_index,
            address: json_withdrawal.address.as_bytes(),
            amount: json_withdrawal.amount,
        }
    }
}

#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(
        derive(Debug, Clone, PartialEq, Serialize, Deserialize),
        serde(rename_all = "camelCase")
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub struct JsonPayloadAttributes {
    #[serde(with = "serde_utils::u64_hex_be")]
    pub timestamp: u64,
    pub prev_randao: Hash256,
    pub suggested_fee_recipient: Address,
    #[superstruct(only(V2, V3))]
    pub withdrawals: Vec<JsonWithdrawal>,
    #[superstruct(only(V3))]
    pub parent_beacon_block_root: Hash256,
}

impl From<PayloadAttributes> for JsonPayloadAttributes {
    fn from(payload_attributes: PayloadAttributes) -> Self {
        match payload_attributes {
            PayloadAttributes::V1(pa) => Self::V1(JsonPayloadAttributesV1 {
                timestamp: pa.timestamp,
                prev_randao: pa.prev_randao,
                suggested_fee_recipient: pa.suggested_fee_recipient,
            }),
            PayloadAttributes::V2(pa) => Self::V2(JsonPayloadAttributesV2 {
                timestamp: pa.timestamp,
                prev_randao: pa.prev_randao,
                suggested_fee_recipient: pa.suggested_fee_recipient,
                withdrawals: pa.withdrawals.into_iter().map(Into::into).collect(),
            }),
            PayloadAttributes::V3(pa) => Self::V3(JsonPayloadAttributesV3 {
                timestamp: pa.timestamp,
                prev_randao: pa.prev_randao,
                suggested_fee_recipient: pa.suggested_fee_recipient,
                withdrawals: pa.withdrawals.into_iter().map(Into::into).collect(),
                parent_beacon_block_root: pa.parent_beacon_block_root,
            }),
        }
    }
}

impl From<JsonPayloadAttributes> for PayloadAttributes {
    fn from(json_payload_attributes: JsonPayloadAttributes) -> Self {
        match json_payload_attributes {
            JsonPayloadAttributes::V1(jpa) => Self::V1(PayloadAttributesV1 {
                timestamp: jpa.timestamp,
                prev_randao: jpa.prev_randao,
                suggested_fee_recipient: jpa.suggested_fee_recipient,
            }),
            JsonPayloadAttributes::V2(jpa) => Self::V2(PayloadAttributesV2 {
                timestamp: jpa.timestamp,
                prev_randao: jpa.prev_randao,
                suggested_fee_recipient: jpa.suggested_fee_recipient,
                withdrawals: jpa.withdrawals.into_iter().map(Into::into).collect(),
            }),
            JsonPayloadAttributes::V3(jpa) => Self::V3(PayloadAttributesV3 {
                timestamp: jpa.timestamp,
                prev_randao: jpa.prev_randao,
                suggested_fee_recipient: jpa.suggested_fee_recipient,
                withdrawals: jpa.withdrawals.into_iter().map(Into::into).collect(),
                parent_beacon_block_root: jpa.parent_beacon_block_root,
            }),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "E: EthSpec", rename_all = "camelCase")]
pub struct JsonBlobsBundleV1<E: EthSpec> {
    pub commitments: KzgCommitments<E>,
    pub proofs: KzgProofs<E>,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub blobs: BlobsList<E>,
}

impl<E: EthSpec> From<BlobsBundle<E>> for JsonBlobsBundleV1<E> {
    fn from(blobs_bundle: BlobsBundle<E>) -> Self {
        Self {
            commitments: blobs_bundle.commitments,
            proofs: blobs_bundle.proofs,
            blobs: blobs_bundle.blobs,
        }
    }
}
impl<E: EthSpec> From<JsonBlobsBundleV1<E>> for BlobsBundle<E> {
    fn from(json_blobs_bundle: JsonBlobsBundleV1<E>) -> Self {
        Self {
            commitments: json_blobs_bundle.commitments,
            proofs: json_blobs_bundle.proofs,
            blobs: json_blobs_bundle.blobs,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonForkchoiceStateV1 {
    pub head_block_hash: ExecutionBlockHash,
    pub safe_block_hash: ExecutionBlockHash,
    pub finalized_block_hash: ExecutionBlockHash,
}

impl From<ForkchoiceState> for JsonForkchoiceStateV1 {
    fn from(f: ForkchoiceState) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let ForkchoiceState {
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

impl From<JsonForkchoiceStateV1> for ForkchoiceState {
    fn from(j: JsonForkchoiceStateV1) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonForkchoiceStateV1 {
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum JsonPayloadStatusV1Status {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPayloadStatusV1 {
    pub status: JsonPayloadStatusV1Status,
    pub latest_valid_hash: Option<ExecutionBlockHash>,
    pub validation_error: Option<String>,
}

impl From<PayloadStatusV1Status> for JsonPayloadStatusV1Status {
    fn from(e: PayloadStatusV1Status) -> Self {
        match e {
            PayloadStatusV1Status::Valid => JsonPayloadStatusV1Status::Valid,
            PayloadStatusV1Status::Invalid => JsonPayloadStatusV1Status::Invalid,
            PayloadStatusV1Status::Syncing => JsonPayloadStatusV1Status::Syncing,
            PayloadStatusV1Status::Accepted => JsonPayloadStatusV1Status::Accepted,
            PayloadStatusV1Status::InvalidBlockHash => JsonPayloadStatusV1Status::InvalidBlockHash,
        }
    }
}
impl From<JsonPayloadStatusV1Status> for PayloadStatusV1Status {
    fn from(j: JsonPayloadStatusV1Status) -> Self {
        match j {
            JsonPayloadStatusV1Status::Valid => PayloadStatusV1Status::Valid,
            JsonPayloadStatusV1Status::Invalid => PayloadStatusV1Status::Invalid,
            JsonPayloadStatusV1Status::Syncing => PayloadStatusV1Status::Syncing,
            JsonPayloadStatusV1Status::Accepted => PayloadStatusV1Status::Accepted,
            JsonPayloadStatusV1Status::InvalidBlockHash => PayloadStatusV1Status::InvalidBlockHash,
        }
    }
}

impl From<PayloadStatusV1> for JsonPayloadStatusV1 {
    fn from(p: PayloadStatusV1) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let PayloadStatusV1 {
            status,
            latest_valid_hash,
            validation_error,
        } = p;

        Self {
            status: status.into(),
            latest_valid_hash,
            validation_error,
        }
    }
}

impl From<JsonPayloadStatusV1> for PayloadStatusV1 {
    fn from(j: JsonPayloadStatusV1) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonPayloadStatusV1 {
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonForkchoiceUpdatedV1Response {
    pub payload_status: JsonPayloadStatusV1,
    pub payload_id: Option<TransparentJsonPayloadId>,
}

impl From<JsonForkchoiceUpdatedV1Response> for ForkchoiceUpdatedResponse {
    fn from(j: JsonForkchoiceUpdatedV1Response) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonForkchoiceUpdatedV1Response {
            payload_status: status,
            payload_id,
        } = j;

        Self {
            payload_status: status.into(),
            payload_id: payload_id.map(Into::into),
        }
    }
}
impl From<ForkchoiceUpdatedResponse> for JsonForkchoiceUpdatedV1Response {
    fn from(f: ForkchoiceUpdatedResponse) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let ForkchoiceUpdatedResponse {
            payload_status: status,
            payload_id,
        } = f;

        Self {
            payload_status: status.into(),
            payload_id: payload_id.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct JsonExecutionPayloadBodyV1<E: EthSpec> {
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions<E>,
    pub withdrawals: Option<VariableList<JsonWithdrawal, E::MaxWithdrawalsPerPayload>>,
}

impl<E: EthSpec> From<JsonExecutionPayloadBodyV1<E>> for ExecutionPayloadBodyV1<E> {
    fn from(value: JsonExecutionPayloadBodyV1<E>) -> Self {
        Self {
            transactions: value.transactions,
            withdrawals: value.withdrawals.map(|json_withdrawals| {
                Withdrawals::<E>::from(
                    json_withdrawals
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<_>>(),
                )
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransitionConfigurationV1 {
    #[serde(with = "serde_utils::u256_hex_be")]
    pub terminal_total_difficulty: Uint256,
    pub terminal_block_hash: ExecutionBlockHash,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub terminal_block_number: u64,
}

/// Serializes the `logs_bloom` field of an `ExecutionPayload`.
pub mod serde_logs_bloom {
    use super::*;
    use serde::{Deserializer, Serializer};
    use serde_utils::hex::PrefixedHexVisitor;

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
