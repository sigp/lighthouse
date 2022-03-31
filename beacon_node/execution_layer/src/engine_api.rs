use crate::engines::ForkChoiceState;
use async_trait::async_trait;
use eth1::http::RpcError;
pub use json_structures::TransitionConfigurationV1;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use slog::Logger;
pub use types::{
    Address, EthSpec, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadHeader, Hash256,
    Uint256,
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
    ServerMessage {
        code: i64,
        message: String,
    },
    Eip155Failure,
    IsSyncing,
    ExecutionBlockNotFound(ExecutionBlockHash),
    ExecutionHeadBlockNotFound,
    ParentHashEqualsBlockHash(ExecutionBlockHash),
    PayloadIdUnavailable,
    TransitionConfigurationMismatch,
    PayloadConversionLogicFlaw,
    InvalidBuilderQuery,
    MissingPayloadId {
        parent_hash: ExecutionBlockHash,
        timestamp: u64,
        prev_randao: Hash256,
        suggested_fee_recipient: Address,
    },
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

pub struct EngineApi;
pub struct BuilderApi;

#[async_trait]
pub trait Builder {
    async fn notify_forkchoice_updated(
        &self,
        forkchoice_state: ForkChoiceState,
        payload_attributes: Option<PayloadAttributes>,
        log: &Logger,
    ) -> Result<ForkchoiceUpdatedResponse, Error>;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PayloadStatusV1Status {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
    InvalidTerminalBlock,
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

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionBlock {
    #[serde(rename = "hash")]
    pub block_hash: ExecutionBlockHash,
    #[serde(rename = "number", with = "eth2_serde_utils::u64_hex_be")]
    pub block_number: u64,
    pub parent_hash: ExecutionBlockHash,
    pub total_difficulty: Uint256,
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
