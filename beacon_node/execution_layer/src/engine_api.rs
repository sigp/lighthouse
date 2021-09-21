use async_trait::async_trait;
use eth1::http::RpcError;

pub use types::{Address, Hash256};

pub mod http;

pub type PayloadId = u64;

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    BadResponse(String),
    RequestFailed(String),
    JsonRpc(RpcError),
    Json(serde_json::Error),
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

#[async_trait]
pub trait EngineApi {
    async fn upcheck(&self) -> Result<(), Error>;

    async fn prepare_payload(
        &self,
        parent_hash: Hash256,
        timestamp: u64,
        random: Hash256,
        fee_recipient: Address,
    ) -> Result<PayloadId, Error>;
}
