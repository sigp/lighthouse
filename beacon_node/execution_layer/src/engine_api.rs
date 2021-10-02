use async_trait::async_trait;
use eth1::http::RpcError;
use serde::{Deserialize, Serialize};

pub const LATEST_TAG: &str = "latest";

pub use types::{Address, EthSpec, ExecutionPayload, Hash256, Uint256};

pub mod http;

pub type PayloadId = u64;

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

    async fn prepare_payload(
        &self,
        parent_hash: Hash256,
        timestamp: u64,
        random: Hash256,
        fee_recipient: Address,
    ) -> Result<PayloadId, Error>;

    async fn execute_payload<T: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<T>,
    ) -> Result<ExecutePayloadResponse, Error>;

    async fn get_payload<T: EthSpec>(
        &self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayload<T>, Error>;

    async fn consensus_validated(
        &self,
        block_hash: Hash256,
        status: ConsensusStatus,
    ) -> Result<(), Error>;

    async fn forkchoice_updated(
        &self,
        head_block_hash: Hash256,
        finalized_block_hash: Hash256,
    ) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutePayloadResponse {
    Valid,
    Invalid,
    Syncing,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusStatus {
    Valid,
    Invalid,
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
