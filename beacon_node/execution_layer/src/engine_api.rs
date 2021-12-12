use async_trait::async_trait;
use eth1::http::RpcError;
use serde::{Deserialize, Serialize};

pub const LATEST_TAG: &str = "latest";

use crate::engines::ForkChoiceState;
pub use types::{Address, EthSpec, ExecutionPayload, Hash256, Uint256};

pub mod http;
pub mod json_structures;

pub type PayloadId = [u8; 8];

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    BadResponse(String),
    RequestFailed(String),
    JsonRpc(RpcError),
    Json(serde_json::Error),
    ServerMessage { code: i64, message: String },
    Eip155Failure,
    IsSyncing,
    ExecutionBlockNotFound(Hash256),
    ExecutionHeadBlockNotFound,
    ParentHashEqualsBlockHash(Hash256),
    PayloadIdUnavailable,
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

/// A generic interface for an execution engine API.
#[async_trait]
pub trait EngineApi {
    async fn upcheck(&self) -> Result<(), Error>;

    async fn get_block_by_number<'a>(
        &self,
        block_by_number: BlockByNumberQuery<'a>,
    ) -> Result<Option<ExecutionBlock>, Error>;

    async fn get_block_by_hash<'a>(
        &self,
        block_hash: Hash256,
    ) -> Result<Option<ExecutionBlock>, Error>;

    async fn execute_payload_v1<T: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<T>,
    ) -> Result<ExecutePayloadResponse, Error>;

    async fn get_payload_v1<T: EthSpec>(
        &self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayload<T>, Error>;

    async fn forkchoice_updated_v1(
        &self,
        forkchoice_state: ForkChoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, Error>;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ExecutePayloadResponseStatus {
    Valid,
    Invalid,
    Syncing,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExecutePayloadResponse {
    pub status: ExecutePayloadResponseStatus,
    pub latest_valid_hash: Option<Hash256>,
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
    pub block_hash: Hash256,
    #[serde(rename = "number", with = "eth2_serde_utils::u64_hex_be")]
    pub block_number: u64,
    pub parent_hash: Hash256,
    pub total_difficulty: Uint256,
}

#[derive(Clone, Copy, Debug)]
pub struct PayloadAttributes {
    pub timestamp: u64,
    pub random: Hash256,
    pub suggested_fee_recipient: Address,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ForkchoiceUpdatedResponseStatus {
    Success,
    Syncing,
}
#[derive(Clone, Debug, PartialEq)]
pub struct ForkchoiceUpdatedResponse {
    pub status: ForkchoiceUpdatedResponseStatus,
    pub payload_id: Option<PayloadId>,
}
