use super::*;
use async_trait::async_trait;
use eth1::http::{hex_to_u64_be, response_result_or_error, send_rpc_request};
pub use reqwest::Client;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

const ENGINE_PREPARE_PAYLOAD: &str = "engine_preparePayload";
const ENGINE_PREPARE_PAYLOAD_TIMEOUT: Duration = Duration::from_millis(500);

pub struct HttpJsonRpc {
    pub client: Client,
    pub url: SensitiveUrl,
}

impl HttpJsonRpc {
    pub fn new(url: SensitiveUrl) -> Result<Self, Error> {
        Ok(Self {
            client: Client::builder().build()?,
            url,
        })
    }
}

#[async_trait]
impl EngineApi for HttpJsonRpc {
    async fn upcheck(&self) -> Result<(), Error> {
        todo!()
    }

    async fn prepare_payload(
        &self,
        parent_hash: Hash256,
        timestamp: u64,
        random: Hash256,
        fee_recipient: Address,
    ) -> Result<PayloadId, Error> {
        let params = json!([PreparePayloadRequest {
            parent_hash,
            timestamp,
            random,
            fee_recipient
        }]);

        let response_body = send_rpc_request(
            &self.url,
            ENGINE_PREPARE_PAYLOAD,
            params,
            ENGINE_PREPARE_PAYLOAD_TIMEOUT,
        )
        .await
        .map_err(Error::RequestFailed)?;

        let result = response_result_or_error(&response_body).map_err(Error::JsonRpc)?;
        let string = result
            .as_str()
            .ok_or(Error::BadResponse("data was not string".to_string()))?;

        hex_to_u64_be(string).map_err(Error::BadResponse)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename = "camelCase")]
struct PreparePayloadRequest {
    parent_hash: Hash256,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    timestamp: u64,
    random: Hash256,
    fee_recipient: Address,
}
