use crate::engines::ForkchoiceState;
use crate::http::{
    ENGINE_EXCHANGE_TRANSITION_CONFIGURATION_V1, ENGINE_FORKCHOICE_UPDATED_V1,
    ENGINE_FORKCHOICE_UPDATED_V2, ENGINE_GET_PAYLOAD_V1, ENGINE_GET_PAYLOAD_V2,
    ENGINE_NEW_PAYLOAD_V1, ENGINE_NEW_PAYLOAD_V2,
};
use eth2::types::{SsePayloadAttributes, SsePayloadAttributesV1, SsePayloadAttributesV2};
pub use ethers_core::types::Transaction;
use ethers_core::utils::rlp::{self, Decodable, Rlp};
use http::deposit_methods::RpcError;
pub use json_structures::{JsonWithdrawal, TransitionConfigurationV1};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use strum::IntoStaticStr;
use superstruct::superstruct;
pub use types::{
    Address, EthSpec, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadHeader,
    ExecutionPayloadRef, FixedVector, ForkName, Hash256, Uint256, VariableList, Withdrawal,
};
use types::{ExecutionPayloadCapella, ExecutionPayloadMerge};

pub mod auth;
pub mod http;
pub mod json_structures;

pub const LATEST_TAG: &str = "latest";

pub type PayloadId = [u8; 8];

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    Auth(auth::Error),
    BadResponse(String),
    RequestFailed(String),
    InvalidExecutePayloadResponse(&'static str),
    JsonRpc(RpcError),
    Json(serde_json::Error),
    ServerMessage { code: i64, message: String },
    Eip155Failure,
    IsSyncing,
    ExecutionBlockNotFound(ExecutionBlockHash),
    ExecutionHeadBlockNotFound,
    ParentHashEqualsBlockHash(ExecutionBlockHash),
    PayloadIdUnavailable,
    TransitionConfigurationMismatch,
    PayloadConversionLogicFlaw,
    DeserializeTransaction(ssz_types::Error),
    DeserializeTransactions(ssz_types::Error),
    DeserializeWithdrawals(ssz_types::Error),
    BuilderApi(builder_client::Error),
    IncorrectStateVariant,
    RequiredMethodUnsupported(&'static str),
    UnsupportedForkVariant(String),
    BadConversion(String),
    RlpDecoderError(rlp::DecoderError),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        if matches!(
            e.status(),
            Some(StatusCode::UNAUTHORIZED) | Some(StatusCode::FORBIDDEN)
        ) {
            Error::Auth(auth::Error::InvalidToken)
        } else {
            Error::Reqwest(e)
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<auth::Error> for Error {
    fn from(e: auth::Error) -> Self {
        Error::Auth(e)
    }
}

impl From<builder_client::Error> for Error {
    fn from(e: builder_client::Error) -> Self {
        Error::BuilderApi(e)
    }
}

impl From<rlp::DecoderError> for Error {
    fn from(e: rlp::DecoderError) -> Self {
        Error::RlpDecoderError(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum PayloadStatusV1Status {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PayloadStatusV1 {
    pub status: PayloadStatusV1Status,
    pub latest_valid_hash: Option<ExecutionBlockHash>,
    pub validation_error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum BlockByNumberQuery<'a> {
    Tag(&'a str),
}

/// Representation of an exection block with enough detail to determine the terminal PoW block.
///
/// See `get_pow_block_hash_at_total_difficulty`.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionBlock {
    #[serde(rename = "hash")]
    pub block_hash: ExecutionBlockHash,
    #[serde(rename = "number", with = "eth2_serde_utils::u64_hex_be")]
    pub block_number: u64,
    pub parent_hash: ExecutionBlockHash,
    pub total_difficulty: Uint256,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub timestamp: u64,
}

/// Representation of an execution block with enough detail to reconstruct a payload.
#[superstruct(
    variants(Merge, Capella),
    variant_attributes(
        derive(Clone, Debug, PartialEq, Serialize, Deserialize,),
        serde(bound = "T: EthSpec", rename_all = "camelCase"),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec", rename_all = "camelCase", untagged)]
pub struct ExecutionBlockWithTransactions<T: EthSpec> {
    pub parent_hash: ExecutionBlockHash,
    #[serde(alias = "miner")]
    pub fee_recipient: Address,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    #[serde(alias = "mixHash")]
    pub prev_randao: Hash256,
    #[serde(rename = "number", with = "eth2_serde_utils::u64_hex_be")]
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
    #[serde(rename = "hash")]
    pub block_hash: ExecutionBlockHash,
    pub transactions: Vec<Transaction>,
    #[superstruct(only(Capella))]
    pub withdrawals: Vec<JsonWithdrawal>,
}

impl<T: EthSpec> TryFrom<ExecutionPayload<T>> for ExecutionBlockWithTransactions<T> {
    type Error = Error;

    fn try_from(payload: ExecutionPayload<T>) -> Result<Self, Error> {
        let json_payload = match payload {
            ExecutionPayload::Merge(block) => Self::Merge(ExecutionBlockWithTransactionsMerge {
                parent_hash: block.parent_hash,
                fee_recipient: block.fee_recipient,
                state_root: block.state_root,
                receipts_root: block.receipts_root,
                logs_bloom: block.logs_bloom,
                prev_randao: block.prev_randao,
                block_number: block.block_number,
                gas_limit: block.gas_limit,
                gas_used: block.gas_used,
                timestamp: block.timestamp,
                extra_data: block.extra_data,
                base_fee_per_gas: block.base_fee_per_gas,
                block_hash: block.block_hash,
                transactions: block
                    .transactions
                    .iter()
                    .map(|tx| Transaction::decode(&Rlp::new(tx)))
                    .collect::<Result<Vec<_>, _>>()?,
            }),
            ExecutionPayload::Capella(block) => {
                Self::Capella(ExecutionBlockWithTransactionsCapella {
                    parent_hash: block.parent_hash,
                    fee_recipient: block.fee_recipient,
                    state_root: block.state_root,
                    receipts_root: block.receipts_root,
                    logs_bloom: block.logs_bloom,
                    prev_randao: block.prev_randao,
                    block_number: block.block_number,
                    gas_limit: block.gas_limit,
                    gas_used: block.gas_used,
                    timestamp: block.timestamp,
                    extra_data: block.extra_data,
                    base_fee_per_gas: block.base_fee_per_gas,
                    block_hash: block.block_hash,
                    transactions: block
                        .transactions
                        .iter()
                        .map(|tx| Transaction::decode(&Rlp::new(tx)))
                        .collect::<Result<Vec<_>, _>>()?,
                    withdrawals: Vec::from(block.withdrawals)
                        .into_iter()
                        .map(|withdrawal| withdrawal.into())
                        .collect(),
                })
            }
        };
        Ok(json_payload)
    }
}

#[superstruct(
    variants(V1, V2),
    variant_attributes(derive(Clone, Debug, Eq, Hash, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PayloadAttributes {
    #[superstruct(getter(copy))]
    pub timestamp: u64,
    #[superstruct(getter(copy))]
    pub prev_randao: Hash256,
    #[superstruct(getter(copy))]
    pub suggested_fee_recipient: Address,
    #[superstruct(only(V2))]
    pub withdrawals: Vec<Withdrawal>,
}

impl PayloadAttributes {
    pub fn new(
        timestamp: u64,
        prev_randao: Hash256,
        suggested_fee_recipient: Address,
        withdrawals: Option<Vec<Withdrawal>>,
    ) -> Self {
        match withdrawals {
            Some(withdrawals) => PayloadAttributes::V2(PayloadAttributesV2 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
                withdrawals,
            }),
            None => PayloadAttributes::V1(PayloadAttributesV1 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
            }),
        }
    }
}

impl From<PayloadAttributes> for SsePayloadAttributes {
    fn from(pa: PayloadAttributes) -> Self {
        match pa {
            PayloadAttributes::V1(PayloadAttributesV1 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
            }) => Self::V1(SsePayloadAttributesV1 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
            }),
            PayloadAttributes::V2(PayloadAttributesV2 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
                withdrawals,
            }) => Self::V2(SsePayloadAttributesV2 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
                withdrawals,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ForkchoiceUpdatedResponse {
    pub payload_status: PayloadStatusV1,
    pub payload_id: Option<PayloadId>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProposeBlindedBlockResponseStatus {
    Valid,
    Invalid,
    Syncing,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProposeBlindedBlockResponse {
    pub status: ProposeBlindedBlockResponseStatus,
    pub latest_valid_hash: Option<Hash256>,
    pub validation_error: Option<String>,
}

#[superstruct(
    variants(Merge, Capella),
    variant_attributes(derive(Clone, Debug, PartialEq),),
    map_into(ExecutionPayload),
    map_ref_into(ExecutionPayloadRef),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct GetPayloadResponse<T: EthSpec> {
    #[superstruct(only(Merge), partial_getter(rename = "execution_payload_merge"))]
    pub execution_payload: ExecutionPayloadMerge<T>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella<T>,
    pub block_value: Uint256,
}

impl<'a, T: EthSpec> From<GetPayloadResponseRef<'a, T>> for ExecutionPayloadRef<'a, T> {
    fn from(response: GetPayloadResponseRef<'a, T>) -> Self {
        map_get_payload_response_ref_into_execution_payload_ref!(&'a _, response, |inner, cons| {
            cons(&inner.execution_payload)
        })
    }
}

impl<T: EthSpec> From<GetPayloadResponse<T>> for ExecutionPayload<T> {
    fn from(response: GetPayloadResponse<T>) -> Self {
        map_get_payload_response_into_execution_payload!(response, |inner, cons| {
            cons(inner.execution_payload)
        })
    }
}

impl<T: EthSpec> From<GetPayloadResponse<T>> for (ExecutionPayload<T>, Uint256) {
    fn from(response: GetPayloadResponse<T>) -> Self {
        match response {
            GetPayloadResponse::Merge(inner) => (
                ExecutionPayload::Merge(inner.execution_payload),
                inner.block_value,
            ),
            GetPayloadResponse::Capella(inner) => (
                ExecutionPayload::Capella(inner.execution_payload),
                inner.block_value,
            ),
        }
    }
}

impl<T: EthSpec> GetPayloadResponse<T> {
    pub fn execution_payload_ref(&self) -> ExecutionPayloadRef<T> {
        self.to_ref().into()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EngineCapabilities {
    pub new_payload_v1: bool,
    pub new_payload_v2: bool,
    pub forkchoice_updated_v1: bool,
    pub forkchoice_updated_v2: bool,
    pub get_payload_v1: bool,
    pub get_payload_v2: bool,
    pub exchange_transition_configuration_v1: bool,
}

impl EngineCapabilities {
    pub fn to_response(&self) -> Vec<&str> {
        let mut response = Vec::new();
        if self.new_payload_v1 {
            response.push(ENGINE_NEW_PAYLOAD_V1);
        }
        if self.new_payload_v2 {
            response.push(ENGINE_NEW_PAYLOAD_V2);
        }
        if self.forkchoice_updated_v1 {
            response.push(ENGINE_FORKCHOICE_UPDATED_V1);
        }
        if self.forkchoice_updated_v2 {
            response.push(ENGINE_FORKCHOICE_UPDATED_V2);
        }
        if self.get_payload_v1 {
            response.push(ENGINE_GET_PAYLOAD_V1);
        }
        if self.get_payload_v2 {
            response.push(ENGINE_GET_PAYLOAD_V2);
        }
        if self.exchange_transition_configuration_v1 {
            response.push(ENGINE_EXCHANGE_TRANSITION_CONFIGURATION_V1);
        }

        response
    }
}
