use super::*;
use async_trait::async_trait;
use eth1::http::{response_result_or_error, send_rpc_request};
pub use reqwest::Client;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use types::{execution_payload::serde_logs_bloom, EthSpec, FixedVector, Transaction, VariableList};

const ENGINE_PREPARE_PAYLOAD: &str = "engine_preparePayload";
const ENGINE_PREPARE_PAYLOAD_TIMEOUT: Duration = Duration::from_millis(500);

const ENGINE_EXECUTE_PAYLOAD: &str = "engine_executePayload";
const ENGINE_EXECUTE_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);

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
        let params = json!([JsonPreparePayloadRequest {
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
        let response: JsonPreparePayloadResponse = serde_json::from_value(result)?;

        Ok(response.payload_id)
    }

    async fn execute_payload<T: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<T>,
    ) -> Result<ExecutePayloadResponse, Error> {
        let params = json!([JsonExecutionPayload::from(execution_payload)]);

        let response_body = send_rpc_request(
            &self.url,
            ENGINE_EXECUTE_PAYLOAD,
            params,
            ENGINE_EXECUTE_PAYLOAD_TIMEOUT,
        )
        .await
        .map_err(Error::RequestFailed)?;

        let result = response_result_or_error(&response_body).map_err(Error::JsonRpc)?;

        serde_json::from_value(result).map_err(Into::into)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename = "camelCase")]
struct JsonPreparePayloadRequest {
    parent_hash: Hash256,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    timestamp: u64,
    random: Hash256,
    fee_recipient: Address,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent, rename = "camelCase")]
struct JsonPreparePayloadResponse {
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    payload_id: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct JsonExecutionPayload<T: EthSpec> {
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
    pub base_fee_per_gas: Hash256,
    pub block_hash: Hash256,
    // FIXME(paul): add transaction parsing.
    #[serde(default)]
    pub transactions: VariableList<Transaction<T>, T::MaxTransactionsPerPayload>,
}

impl<T: EthSpec> From<ExecutionPayload<T>> for JsonExecutionPayload<T> {
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
            base_fee_per_gas: e.base_fee_per_gas,
            block_hash: e.block_hash,
            transactions: e.transactions,
        }
    }
}
