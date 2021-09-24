use super::*;
use async_trait::async_trait;
use eth1::http::EIP155_ERROR_STR;
use reqwest::header::CONTENT_TYPE;
pub use reqwest::Client;
use sensitive_url::SensitiveUrl;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use types::{execution_payload::serde_logs_bloom, EthSpec, FixedVector, Transaction, VariableList};

const ETH_SYNCING: &str = "eth_syncing";
const ETH_SYNCING_TIMEOUT: Duration = Duration::from_millis(250);

const ENGINE_PREPARE_PAYLOAD: &str = "engine_preparePayload";
const ENGINE_PREPARE_PAYLOAD_TIMEOUT: Duration = Duration::from_millis(500);

const ENGINE_EXECUTE_PAYLOAD: &str = "engine_executePayload";
const ENGINE_EXECUTE_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);

const ENGINE_GET_PAYLOAD: &str = "engine_getPayload";
const ENGINE_GET_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);

const ENGINE_CONSENSUS_VALIDATED: &str = "engine_consensusValidated";
const ENGINE_CONSENSUS_VALIDATED_TIMEOUT: Duration = Duration::from_millis(500);

const ENGINE_FORKCHOICE_UPDATED: &str = "engine_forkchoiceUpdated";
const ENGINE_FORKCHOICE_UPDATED_TIMEOUT: Duration = Duration::from_millis(500);

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

    pub async fn rpc_request<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
    ) -> Result<T, Error> {
        let body = JsonRequestBody {
            jsonrpc: "2.0",
            method: method,
            params,
            id: 1,
        };

        let body: JsonResponseBody = self
            .client
            .post(self.url.full.clone())
            .timeout(timeout)
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        match (body.result, body.error) {
            (Some(result), None) => serde_json::from_value(result).map_err(Into::into),
            (_, Some(error)) => {
                if error.contains(EIP155_ERROR_STR) {
                    Err(Error::Eip155Error)
                } else {
                    Err(Error::ServerMessage(error))
                }
            }
            (None, None) => Err(Error::NoResultOrError),
        }
    }
}

#[async_trait]
impl EngineApi for HttpJsonRpc {
    async fn upcheck(&self) -> Result<(), Error> {
        let result: serde_json::Value = self
            .rpc_request(ETH_SYNCING, json!([]), ETH_SYNCING_TIMEOUT)
            .await?;

        /*
         * TODO
         *
         * Check the network and chain ids. We omit this to save time for the merge f2f and since it
         * also seems like it might get annoying during development.
         */

        match result.as_bool() {
            Some(false) => Ok(()),
            _ => Err(Error::IsSyncing),
        }
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

        let response: JsonPreparePayloadResponse = self
            .rpc_request(
                ENGINE_PREPARE_PAYLOAD,
                params,
                ENGINE_PREPARE_PAYLOAD_TIMEOUT,
            )
            .await?;

        Ok(response.payload_id)
    }

    async fn execute_payload<T: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<T>,
    ) -> Result<ExecutePayloadResponse, Error> {
        let params = json!([JsonExecutionPayload::from(execution_payload)]);

        self.rpc_request(
            ENGINE_EXECUTE_PAYLOAD,
            params,
            ENGINE_EXECUTE_PAYLOAD_TIMEOUT,
        )
        .await
    }

    async fn get_payload<T: EthSpec>(
        &self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayload<T>, Error> {
        let params = json!([payload_id]);

        self.rpc_request(ENGINE_GET_PAYLOAD, params, ENGINE_GET_PAYLOAD_TIMEOUT)
            .await
    }

    async fn consensus_validated(
        &self,
        block_hash: Hash256,
        status: ConsensusStatus,
    ) -> Result<(), Error> {
        let params = json!([JsonConsensusValidatedRequest { block_hash, status }]);

        self.rpc_request(
            ENGINE_CONSENSUS_VALIDATED,
            params,
            ENGINE_CONSENSUS_VALIDATED_TIMEOUT,
        )
        .await
    }

    async fn forkchoice_updated(
        &self,
        head_block_hash: Hash256,
        finalized_block_hash: Hash256,
    ) -> Result<(), Error> {
        let params = json!([JsonForkChoiceUpdatedRequest {
            head_block_hash,
            finalized_block_hash
        }]);

        self.rpc_request(
            ENGINE_FORKCHOICE_UPDATED,
            params,
            ENGINE_FORKCHOICE_UPDATED_TIMEOUT,
        )
        .await
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename = "camelCase")]
struct JsonRequestBody<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: serde_json::Value,
    id: u32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename = "camelCase")]
struct JsonResponseBody {
    jsonrpc: String,
    error: Option<String>,
    result: Option<serde_json::Value>,
    id: u32,
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

impl<T: EthSpec> From<JsonExecutionPayload<T>> for ExecutionPayload<T> {
    fn from(e: JsonExecutionPayload<T>) -> Self {
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename = "camelCase")]
struct JsonConsensusValidatedRequest {
    block_hash: Hash256,
    status: ConsensusStatus,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename = "camelCase")]
struct JsonForkChoiceUpdatedRequest {
    head_block_hash: Hash256,
    finalized_block_hash: Hash256,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::MockServer;
    use std::future::Future;
    use std::sync::Arc;
    use types::MainnetEthSpec;

    struct Tester {
        server: MockServer,
        echo_client: Arc<HttpJsonRpc>,
    }

    impl Tester {
        pub fn new() -> Self {
            let server = MockServer::unit_testing::<MainnetEthSpec>();
            let echo_url = SensitiveUrl::parse(&format!("{}/echo", server.url())).unwrap();
            let echo_client = Arc::new(HttpJsonRpc::new(echo_url).unwrap());

            Self {
                server,
                echo_client,
            }
        }

        pub async fn assert_request_equals<R, F>(
            self,
            request_func: R,
            expected_json: serde_json::Value,
        ) -> Self
        where
            R: Fn(Arc<HttpJsonRpc>) -> F,
            F: Future<Output = ()>,
        {
            request_func(self.echo_client.clone()).await;
            let request_bytes = self.server.last_echo_request().await;
            let request_json: serde_json::Value =
                serde_json::from_slice(&request_bytes).expect("request was not valid json");
            if request_json != expected_json {
                panic!(
                    "json mismatch!\n\nobserved: {}\n\nexpected: {}\n\n",
                    request_json.to_string(),
                    expected_json.to_string()
                )
            }
            self
        }
    }

    #[tokio::test]
    async fn forkchoice_updated_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .forkchoice_updated(Hash256::repeat_byte(0), Hash256::repeat_byte(1))
                        .await;
                },
                json!("meow"),
            )
            .await;
    }
}
