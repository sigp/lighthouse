use crate::engines::ForkChoiceState;
pub use ethers_core::types::Transaction;
use http::deposit_methods::RpcError;
pub use json_structures::TransitionConfigurationV1;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use strum::IntoStaticStr;
pub use types::{
    Address, EthSpec, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadHeader, FixedVector,
    Hash256, Uint256, VariableList,
};

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
    BuilderApi(builder_client::Error),
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

/// Representation of an exection block with enough detail to reconstruct a payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PayloadAttributes {
    pub timestamp: u64,
    pub prev_randao: Hash256,
    pub suggested_fee_recipient: Address,
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
