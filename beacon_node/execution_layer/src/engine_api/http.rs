//! Contains an implementation of `EngineAPI` using the JSON-RPC API via HTTP.

use super::*;
use crate::json_structures::*;
use async_trait::async_trait;
use eth1::http::EIP155_ERROR_STR;
use reqwest::header::CONTENT_TYPE;
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::time::Duration;
use types::EthSpec;

pub use reqwest::Client;

const STATIC_ID: u32 = 1;
pub const JSONRPC_VERSION: &str = "2.0";

pub const RETURN_FULL_TRANSACTION_OBJECTS: bool = false;

pub const ETH_GET_BLOCK_BY_NUMBER: &str = "eth_getBlockByNumber";
pub const ETH_GET_BLOCK_BY_NUMBER_TIMEOUT: Duration = Duration::from_secs(1);

pub const ETH_GET_BLOCK_BY_HASH: &str = "eth_getBlockByHash";
pub const ETH_GET_BLOCK_BY_HASH_TIMEOUT: Duration = Duration::from_secs(1);

pub const ETH_SYNCING: &str = "eth_syncing";
pub const ETH_SYNCING_TIMEOUT: Duration = Duration::from_millis(250);

pub const ENGINE_EXECUTE_PAYLOAD_V1: &str = "engine_executePayloadV1";
pub const ENGINE_EXECUTE_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);

pub const ENGINE_GET_PAYLOAD_V1: &str = "engine_getPayloadV1";
pub const ENGINE_GET_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);

pub const ENGINE_FORKCHOICE_UPDATED_V1: &str = "engine_forkchoiceUpdatedV1";
pub const ENGINE_FORKCHOICE_UPDATED_TIMEOUT: Duration = Duration::from_millis(500);

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
            jsonrpc: JSONRPC_VERSION,
            method,
            params,
            id: STATIC_ID,
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
            (result, None) => serde_json::from_value(result).map_err(Into::into),
            (_, Some(error)) => {
                if error.message.contains(EIP155_ERROR_STR) {
                    Err(Error::Eip155Failure)
                } else {
                    Err(Error::ServerMessage {
                        code: error.code,
                        message: error.message,
                    })
                }
            }
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

    async fn get_block_by_number<'a>(
        &self,
        query: BlockByNumberQuery<'a>,
    ) -> Result<Option<ExecutionBlock>, Error> {
        let params = json!([query, RETURN_FULL_TRANSACTION_OBJECTS]);

        self.rpc_request(
            ETH_GET_BLOCK_BY_NUMBER,
            params,
            ETH_GET_BLOCK_BY_NUMBER_TIMEOUT,
        )
        .await
    }

    async fn get_block_by_hash<'a>(
        &self,
        block_hash: Hash256,
    ) -> Result<Option<ExecutionBlock>, Error> {
        let params = json!([block_hash, RETURN_FULL_TRANSACTION_OBJECTS]);

        self.rpc_request(ETH_GET_BLOCK_BY_HASH, params, ETH_GET_BLOCK_BY_HASH_TIMEOUT)
            .await
    }

    async fn execute_payload_v1<T: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<T>,
    ) -> Result<ExecutePayloadResponse, Error> {
        let params = json!([JsonExecutionPayloadV1::from(execution_payload)]);

        let response: JsonExecutePayloadV1Response = self
            .rpc_request(
                ENGINE_EXECUTE_PAYLOAD_V1,
                params,
                ENGINE_EXECUTE_PAYLOAD_TIMEOUT,
            )
            .await?;

        Ok(response.into())
    }

    async fn get_payload_v1<T: EthSpec>(
        &self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayload<T>, Error> {
        let params = json!([JsonPayloadIdRequest::from(payload_id)]);

        let response: JsonExecutionPayloadV1<T> = self
            .rpc_request(ENGINE_GET_PAYLOAD_V1, params, ENGINE_GET_PAYLOAD_TIMEOUT)
            .await?;

        Ok(response.into())
    }

    async fn forkchoice_updated_v1(
        &self,
        forkchoice_state: ForkChoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, Error> {
        let params = json!([
            JsonForkChoiceStateV1::from(forkchoice_state),
            payload_attributes.map(JsonPayloadAttributesV1::from)
        ]);

        let response: JsonForkchoiceUpdatedV1Response = self
            .rpc_request(
                ENGINE_FORKCHOICE_UPDATED_V1,
                params,
                ENGINE_FORKCHOICE_UPDATED_TIMEOUT,
            )
            .await?;

        Ok(response.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::MockServer;
    use std::future::Future;
    use std::str::FromStr;
    use std::sync::Arc;
    use types::{MainnetEthSpec, Transaction, Unsigned, VariableList};

    struct Tester {
        server: MockServer<MainnetEthSpec>,
        rpc_client: Arc<HttpJsonRpc>,
        echo_client: Arc<HttpJsonRpc>,
    }

    impl Tester {
        pub fn new() -> Self {
            let server = MockServer::unit_testing();

            let rpc_url = SensitiveUrl::parse(&server.url()).unwrap();
            let rpc_client = Arc::new(HttpJsonRpc::new(rpc_url).unwrap());

            let echo_url = SensitiveUrl::parse(&format!("{}/echo", server.url())).unwrap();
            let echo_client = Arc::new(HttpJsonRpc::new(echo_url).unwrap());

            Self {
                server,
                rpc_client,
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
            let request_bytes = self.server.last_echo_request();
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

        pub async fn with_preloaded_responses<R, F>(
            self,
            preloaded_responses: Vec<serde_json::Value>,
            request_func: R,
        ) -> Self
        where
            R: Fn(Arc<HttpJsonRpc>) -> F,
            F: Future<Output = ()>,
        {
            for response in preloaded_responses {
                self.server.push_preloaded_response(response);
            }
            request_func(self.rpc_client.clone()).await;
            self
        }
    }

    const HASH_00: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const HASH_01: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";

    const ADDRESS_00: &str = "0x0000000000000000000000000000000000000000";
    const ADDRESS_01: &str = "0x0101010101010101010101010101010101010101";

    const JSON_NULL: serde_json::Value = serde_json::Value::Null;
    const LOGS_BLOOM_00: &str = "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const LOGS_BLOOM_01: &str = "0x01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101";

    fn encode_transactions<E: EthSpec>(
        transactions: VariableList<
            Transaction<E::MaxBytesPerTransaction>,
            E::MaxTransactionsPerPayload,
        >,
    ) -> Result<serde_json::Value, serde_json::Error> {
        let ep: JsonExecutionPayloadV1<E> = JsonExecutionPayloadV1 {
            transactions,
            ..<_>::default()
        };
        let json = serde_json::to_value(&ep)?;
        Ok(json.get("transactions").unwrap().clone())
    }

    fn decode_transactions<E: EthSpec>(
        transactions: serde_json::Value,
    ) -> Result<
        VariableList<Transaction<E::MaxBytesPerTransaction>, E::MaxTransactionsPerPayload>,
        serde_json::Error,
    > {
        let mut json = json!({
            "parentHash": HASH_00,
            "coinbase": ADDRESS_01,
            "stateRoot": HASH_01,
            "receiptRoot": HASH_00,
            "logsBloom": LOGS_BLOOM_01,
            "random": HASH_01,
            "blockNumber": "0x0",
            "gasLimit": "0x1",
            "gasUsed": "0x2",
            "timestamp": "0x2a",
            "extraData": "0x",
            "baseFeePerGas": "0x1",
            "blockHash": HASH_01,
        });
        // Take advantage of the fact that we own `transactions` and don't need to reserialize it.
        json.as_object_mut()
            .unwrap()
            .insert("transactions".into(), transactions);
        let ep: JsonExecutionPayloadV1<E> = serde_json::from_value(json)?;
        Ok(ep.transactions)
    }

    fn assert_transactions_serde<E: EthSpec>(
        name: &str,
        as_obj: VariableList<Transaction<E::MaxBytesPerTransaction>, E::MaxTransactionsPerPayload>,
        as_json: serde_json::Value,
    ) {
        assert_eq!(
            encode_transactions::<E>(as_obj.clone()).unwrap(),
            as_json,
            "encoding for {}",
            name
        );
        assert_eq!(
            decode_transactions::<E>(as_json).unwrap(),
            as_obj,
            "decoding for {}",
            name
        );
    }

    /// Example: if `spec == &[1, 1]`, then two one-byte transactions will be created.
    fn generate_transactions<E: EthSpec>(
        spec: &[usize],
    ) -> VariableList<Transaction<E::MaxBytesPerTransaction>, E::MaxTransactionsPerPayload> {
        let mut txs = VariableList::default();

        for &num_bytes in spec {
            let mut tx = VariableList::default();
            for _ in 0..num_bytes {
                tx.push(0).unwrap();
            }
            txs.push(tx).unwrap();
        }

        txs
    }

    #[test]
    fn transaction_serde() {
        assert_transactions_serde::<MainnetEthSpec>(
            "empty",
            generate_transactions::<MainnetEthSpec>(&[]),
            json!([]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "one empty tx",
            generate_transactions::<MainnetEthSpec>(&[0]),
            json!(["0x"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "two empty txs",
            generate_transactions::<MainnetEthSpec>(&[0, 0]),
            json!(["0x", "0x"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "one one-byte tx",
            generate_transactions::<MainnetEthSpec>(&[1]),
            json!(["0x00"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "two one-byte txs",
            generate_transactions::<MainnetEthSpec>(&[1, 1]),
            json!(["0x00", "0x00"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "mixed bag",
            generate_transactions::<MainnetEthSpec>(&[0, 1, 3, 0]),
            json!(["0x", "0x00", "0x000000", "0x"]),
        );

        /*
         * Check for too many transactions
         */

        let num_max_txs = <MainnetEthSpec as EthSpec>::MaxTransactionsPerPayload::to_usize();
        let max_txs = (0..num_max_txs).map(|_| "0x00").collect::<Vec<_>>();
        let too_many_txs = (0..=num_max_txs).map(|_| "0x00").collect::<Vec<_>>();

        decode_transactions::<MainnetEthSpec>(serde_json::to_value(max_txs).unwrap()).unwrap();
        assert!(
            decode_transactions::<MainnetEthSpec>(serde_json::to_value(too_many_txs).unwrap())
                .is_err()
        );
    }

    #[tokio::test]
    async fn get_block_by_number_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ETH_GET_BLOCK_BY_NUMBER,
                    "params": ["latest", false]
                }),
            )
            .await;
    }

    #[tokio::test]
    async fn get_block_by_hash_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client.get_block_by_hash(Hash256::repeat_byte(1)).await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ETH_GET_BLOCK_BY_HASH,
                    "params": [HASH_01, false]
                }),
            )
            .await;
    }

    #[tokio::test]
    async fn forkchoice_updated_v1_with_payload_attributes_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .forkchoice_updated_v1(
                            ForkChoiceState {
                                head_block_hash: Hash256::repeat_byte(1),
                                safe_block_hash: Hash256::repeat_byte(1),
                                finalized_block_hash: Hash256::zero(),
                            },
                            Some(PayloadAttributes {
                                timestamp: 5,
                                random: Hash256::zero(),
                                fee_recipient: Address::repeat_byte(0),
                            }),
                        )
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_FORKCHOICE_UPDATED_V1,
                    "params": [{
                        "headBlockHash": HASH_01,
                        "safeBlockHash": HASH_01,
                        "finalizedBlockHash": HASH_00,
                    },
                    {
                        "timestamp":"0x5",
                        "random": HASH_00,
                        "feeRecipient": ADDRESS_00
                    }]
                }),
            )
            .await;
    }

    #[tokio::test]
    async fn get_payload_v1_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client.get_payload_v1::<MainnetEthSpec>([42; 8]).await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_GET_PAYLOAD_V1,
                    "params": ["0x2a2a2a2a2a2a2a2a"]
                }),
            )
            .await;
    }

    #[tokio::test]
    async fn execute_payload_v1_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .execute_payload_v1::<MainnetEthSpec>(ExecutionPayload {
                            parent_hash: Hash256::repeat_byte(0),
                            coinbase: Address::repeat_byte(1),
                            state_root: Hash256::repeat_byte(1),
                            receipt_root: Hash256::repeat_byte(0),
                            logs_bloom: vec![1; 256].into(),
                            random: Hash256::repeat_byte(1),
                            block_number: 0,
                            gas_limit: 1,
                            gas_used: 2,
                            timestamp: 42,
                            extra_data: vec![].into(),
                            base_fee_per_gas: Uint256::from(1),
                            block_hash: Hash256::repeat_byte(1),
                            transactions: vec![].into(),
                        })
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_EXECUTE_PAYLOAD_V1,
                    "params": [{
                        "parentHash": HASH_00,
                        "coinbase": ADDRESS_01,
                        "stateRoot": HASH_01,
                        "receiptRoot": HASH_00,
                        "logsBloom": LOGS_BLOOM_01,
                        "random": HASH_01,
                        "blockNumber": "0x0",
                        "gasLimit": "0x1",
                        "gasUsed": "0x2",
                        "timestamp": "0x2a",
                        "extraData": "0x",
                        "baseFeePerGas": "0x1",
                        "blockHash": HASH_01,
                        "transactions": [],
                    }]
                }),
            )
            .await;
    }

    #[tokio::test]
    async fn forkchoice_updated_v1_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .forkchoice_updated_v1(
                            ForkChoiceState {
                                head_block_hash: Hash256::repeat_byte(0),
                                safe_block_hash: Hash256::repeat_byte(0),
                                finalized_block_hash: Hash256::repeat_byte(1),
                            },
                            None,
                        )
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_FORKCHOICE_UPDATED_V1,
                    "params": [{
                        "headBlockHash": HASH_00,
                        "safeBlockHash": HASH_00,
                        "finalizedBlockHash": HASH_01,
                    }, JSON_NULL]
                }),
            )
            .await;
    }

    fn str_to_payload_id(s: &str) -> PayloadId {
        serde_json::from_str::<TransparentJsonPayloadId>(&format!("\"{}\"", s))
            .unwrap()
            .into()
    }

    #[test]
    fn str_payload_id() {
        assert_eq!(
            str_to_payload_id("0x002a2a2a2a2a2a01"),
            [0, 42, 42, 42, 42, 42, 42, 1]
        );
    }

    /// Test vectors provided by Geth:
    ///
    /// https://notes.ethereum.org/@9AeMAlpyQYaAAyuj47BzRw/rkwW3ceVY
    ///
    /// The `id` field has been modified on these vectors to match the one we use.
    #[tokio::test]
    async fn geth_test_vectors() {
        Tester::new()
            .assert_request_equals(
                // engine_forkchoiceUpdatedV1 (prepare payload) REQUEST validation
                |client| async move {
                    let _ = client
                        .forkchoice_updated_v1(
                            ForkChoiceState {
                                head_block_hash: Hash256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                                safe_block_hash: Hash256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                                finalized_block_hash: Hash256::zero(),
                            },
                            Some(PayloadAttributes {
                                timestamp: 5,
                                random: Hash256::zero(),
                                fee_recipient: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            })
                        )
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_FORKCHOICE_UPDATED_V1,
                    "params": [{
                        "headBlockHash": "0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                        "safeBlockHash": "0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                        "finalizedBlockHash": HASH_00,
                    },
                    {
                        "timestamp":"0x5",
                        "random": HASH_00,
                        "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
                    }]
                })
            )
            .await
            .with_preloaded_responses(
                // engine_forkchoiceUpdatedV1 (prepare payload) RESPONSE validation
                //
                // NOTE THIS HAD TO BE MODIFIED FROM ORIGINAL RESPONSE
                // {
                //      "jsonrpc":"2.0",
                //      "id":67,
                //      "result":{
                //          "status":"VALID", // <- This must be SUCCESS
                //          "payloadId":"0xa247243752eb10b4"
                //      }
                // }
                // see spec for engine_forkchoiceUpdatedV1 response:
                // https://github.com/ethereum/execution-apis/blob/v1.0.0-alpha.4/src/engine/specification.md#response-1
                vec![json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "result": {
                        "status": "SUCCESS",
                        "payloadId": "0xa247243752eb10b4"
                    }
                })],
                |client| async move {
                    let response = client
                        .forkchoice_updated_v1(
                            ForkChoiceState {
                                head_block_hash: Hash256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                                safe_block_hash: Hash256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                                finalized_block_hash: Hash256::zero(),
                            },
                            Some(PayloadAttributes {
                                timestamp: 5,
                                random: Hash256::zero(),
                                fee_recipient: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            })
                        )
                        .await
                        .unwrap();
                    assert_eq!(response, ForkchoiceUpdatedResponse {
                        status: ForkchoiceUpdatedResponseStatus::Success,
                        payload_id:
                            Some(str_to_payload_id("0xa247243752eb10b4")),
                    });
                },
            )
            .await
            .assert_request_equals(
                // engine_getPayloadV1 REQUEST validation
                |client| async move {
                    let _ = client
                        .get_payload_v1::<MainnetEthSpec>(str_to_payload_id("0xa247243752eb10b4"))
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_GET_PAYLOAD_V1,
                    "params": ["0xa247243752eb10b4"]
                })
            )
            .await
            .with_preloaded_responses(
                // engine_getPayloadV1 RESPONSE validation
                vec![json!({
                    "jsonrpc":JSONRPC_VERSION,
                    "id":STATIC_ID,
                    "result":{
                        "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                        "coinbase":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                        "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
                        "receiptRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                        "logsBloom": LOGS_BLOOM_00,
                        "random": HASH_00,
                        "blockNumber":"0x1",
                        "gasLimit":"0x1c9c380",
                        "gasUsed":"0x0",
                        "timestamp":"0x5",
                        "extraData":"0x",
                        "baseFeePerGas":"0x7",
                        "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
                        "transactions":[]
                    }
                })],
                |client| async move {
                    let payload = client
                        .get_payload_v1::<MainnetEthSpec>(str_to_payload_id("0xa247243752eb10b4"))
                        .await
                        .unwrap();

                    let expected = ExecutionPayload {
                            parent_hash: Hash256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                            coinbase: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            state_root: Hash256::from_str("0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45").unwrap(),
                            receipt_root: Hash256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap(),
                            logs_bloom: vec![0; 256].into(),
                            random: Hash256::zero(),
                            block_number: 1,
                            gas_limit: u64::from_str_radix("1c9c380",16).unwrap(),
                            gas_used: 0,
                            timestamp: 5,
                            extra_data: vec![].into(),
                            base_fee_per_gas: Uint256::from(7),
                            block_hash: Hash256::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                            transactions: vec![].into(),
                        };

                    assert_eq!(payload, expected);
                },
            )
            .await
            .assert_request_equals(
                // engine_executePayloadV1 REQUEST validation
                |client| async move {
                    let _ = client
                        .execute_payload_v1::<MainnetEthSpec>(ExecutionPayload {
                            parent_hash: Hash256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                            coinbase: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            state_root: Hash256::from_str("0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45").unwrap(),
                            receipt_root: Hash256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap(),
                            logs_bloom: vec![0; 256].into(),
                            random: Hash256::zero(),
                            block_number: 1,
                            gas_limit: u64::from_str_radix("1c9c380",16).unwrap(),
                            gas_used: 0,
                            timestamp: 5,
                            extra_data: vec![].into(),
                            base_fee_per_gas: Uint256::from(7),
                            block_hash: Hash256::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                            transactions: vec![].into(),
                        })
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_EXECUTE_PAYLOAD_V1,
                    "params": [{
                        "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                        "coinbase":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                        "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
                        "receiptRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                        "logsBloom": LOGS_BLOOM_00,
                        "random": HASH_00,
                        "blockNumber":"0x1",
                        "gasLimit":"0x1c9c380",
                        "gasUsed":"0x0",
                        "timestamp":"0x5",
                        "extraData":"0x",
                        "baseFeePerGas":"0x7",
                        "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
                        "transactions":[]
                    }],
                })
            )
            .await
            .with_preloaded_responses(
                // engine_executePayloadV1 RESPONSE validation
                //
                // NOTE THIS HAD TO BE MODIFIED FROM ORIGINAL RESPONSE
                // {
                //      "jsonrpc":"2.0",
                //      "id":67,
                //      "result":{
                //          "status":"SUCCESS", // <- This must be VALID
                //          "latestValidHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858"
                //      }
                // }
                // see spec for engine_executePayloadV1 response:
                // https://github.com/ethereum/execution-apis/blob/v1.0.0-alpha.4/src/engine/specification.md#response
                vec![json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "id": STATIC_ID,
                    "result":{
                        "status":"VALID",
                        "latestValidHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858"
                    }
                })],
                |client| async move {
                    let response = client
                        .execute_payload_v1::<MainnetEthSpec>(ExecutionPayload::default())
                        .await
                        .unwrap();

                    assert_eq!(response,
                        ExecutePayloadResponse {
                            status: ExecutePayloadResponseStatus::Valid,
                            latest_valid_hash: Some(Hash256::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap()),
                            message: None
                        }
                    );
                },
            )
            .await
            .assert_request_equals(
                // engine_forkchoiceUpdatedV1 REQUEST validation
                |client| async move {
                    let _ = client
                        .forkchoice_updated_v1(
                            ForkChoiceState {
                                head_block_hash: Hash256::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                                safe_block_hash: Hash256::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                                finalized_block_hash: Hash256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                            },
                            None,
                        )
                        .await;
                },
                json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_FORKCHOICE_UPDATED_V1,
                    "params": [
                        {
                            "headBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
                            "safeBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
                            "finalizedBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a"
                        }, JSON_NULL],
                    "id": STATIC_ID
                })
            )
            .await
            .with_preloaded_responses(
                // engine_forkchoiceUpdatedV1 RESPONSE validation
                //
                // Note: this test was modified to provide `null` rather than `0x`. The geth vectors
                // are invalid.
                vec![json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "id": STATIC_ID,
                    "result": {
                        "status":"SUCCESS",
                        "payloadId": serde_json::Value::Null
                    }
                })],
                |client| async move {
                    let response = client
                        .forkchoice_updated_v1(
                            ForkChoiceState {
                                head_block_hash: Hash256::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                                safe_block_hash: Hash256::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                                finalized_block_hash: Hash256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                            },
                            None,
                        )
                        .await
                        .unwrap();
                    assert_eq!(response, ForkchoiceUpdatedResponse {
                        status: ForkchoiceUpdatedResponseStatus::Success,
                        payload_id: None,
                    });
                },
            )
            .await;
    }
}
