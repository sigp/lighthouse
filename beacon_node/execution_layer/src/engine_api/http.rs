//! Contains an implementation of `EngineAPI` using the JSON-RPC API via HTTP.

use super::*;
use async_trait::async_trait;
use eth1::http::EIP155_ERROR_STR;
use reqwest::header::CONTENT_TYPE;
use sensitive_url::SensitiveUrl;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use types::{EthSpec, FixedVector, Transaction, Unsigned, VariableList};

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

pub const ENGINE_PREPARE_PAYLOAD: &str = "engine_preparePayload";
pub const ENGINE_PREPARE_PAYLOAD_TIMEOUT: Duration = Duration::from_millis(500);

pub const ENGINE_EXECUTE_PAYLOAD: &str = "engine_executePayload";
pub const ENGINE_EXECUTE_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);

pub const ENGINE_GET_PAYLOAD: &str = "engine_getPayload";
pub const ENGINE_GET_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);

pub const ENGINE_CONSENSUS_VALIDATED: &str = "engine_consensusValidated";
pub const ENGINE_CONSENSUS_VALIDATED_TIMEOUT: Duration = Duration::from_millis(500);

pub const ENGINE_FORKCHOICE_UPDATED: &str = "engine_forkchoiceUpdated";
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

        let response: JsonPayloadIdResponse = self
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

        let result: ExecutePayloadResponseWrapper = self
            .rpc_request(
                ENGINE_EXECUTE_PAYLOAD,
                params,
                ENGINE_EXECUTE_PAYLOAD_TIMEOUT,
            )
            .await?;

        Ok(result.status)
    }

    async fn get_payload<T: EthSpec>(
        &self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayload<T>, Error> {
        let params = json!([JsonPayloadIdRequest { payload_id }]);

        let response: JsonExecutionPayload<T> = self
            .rpc_request(ENGINE_GET_PAYLOAD, params, ENGINE_GET_PAYLOAD_TIMEOUT)
            .await?;

        Ok(ExecutionPayload::from(response))
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
#[serde(rename_all = "camelCase")]
struct JsonRequestBody<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: serde_json::Value,
    id: u32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct JsonError {
    code: i64,
    message: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonResponseBody {
    jsonrpc: String,
    #[serde(default)]
    error: Option<JsonError>,
    #[serde(default)]
    result: serde_json::Value,
    id: u32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPreparePayloadRequest {
    pub parent_hash: Hash256,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub timestamp: u64,
    pub random: Hash256,
    pub fee_recipient: Address,
}

/// On the request, just provide the `payload_id`, without the object wrapper (transparent).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent, rename_all = "camelCase")]
pub struct JsonPayloadIdRequest {
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub payload_id: u64,
}

/// On the response, expect without the object wrapper (non-transparent).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPayloadIdResponse {
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub payload_id: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutePayloadResponseWrapper {
    pub status: ExecutePayloadResponse,
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec", rename_all = "camelCase")]
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
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    pub base_fee_per_gas: Uint256,
    pub block_hash: Hash256,
    #[serde(with = "serde_transactions")]
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
            extra_data: e.extra_data,
            base_fee_per_gas: Uint256::from_little_endian(e.base_fee_per_gas.as_bytes()),
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
            extra_data: e.extra_data,
            base_fee_per_gas: uint256_to_hash256(e.base_fee_per_gas),
            block_hash: e.block_hash,
            transactions: e.transactions,
        }
    }
}

fn uint256_to_hash256(u: Uint256) -> Hash256 {
    let mut bytes = [0; 32];
    u.to_little_endian(&mut bytes);
    Hash256::from_slice(&bytes)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonConsensusValidatedRequest {
    pub block_hash: Hash256,
    pub status: ConsensusStatus,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonForkChoiceUpdatedRequest {
    pub head_block_hash: Hash256,
    pub finalized_block_hash: Hash256,
}

/// Serializes the `logs_bloom` field of an `ExecutionPayload`.
pub mod serde_logs_bloom {
    use super::*;
    use eth2_serde_utils::hex::PrefixedHexVisitor;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S, U>(bytes: &FixedVector<u8, U>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        U: Unsigned,
    {
        let mut hex_string: String = "0x".to_string();
        hex_string.push_str(&hex::encode(&bytes[..]));

        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D, U>(deserializer: D) -> Result<FixedVector<u8, U>, D::Error>
    where
        D: Deserializer<'de>,
        U: Unsigned,
    {
        let vec = deserializer.deserialize_string(PrefixedHexVisitor)?;

        FixedVector::new(vec)
            .map_err(|e| serde::de::Error::custom(format!("invalid logs bloom: {:?}", e)))
    }
}

/// Serializes the `transactions` field of an `ExecutionPayload`.
pub mod serde_transactions {
    use super::*;
    use eth2_serde_utils::hex;
    use serde::ser::SerializeSeq;
    use serde::{de, Deserializer, Serializer};
    use std::marker::PhantomData;

    type Value<T, N> = VariableList<Transaction<T>, N>;

    #[derive(Default)]
    pub struct ListOfBytesListVisitor<T, N> {
        _phantom_t: PhantomData<T>,
        _phantom_n: PhantomData<N>,
    }

    impl<'a, T: EthSpec, N: Unsigned> serde::de::Visitor<'a> for ListOfBytesListVisitor<T, N> {
        type Value = Value<T, N>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "a list of 0x-prefixed byte lists")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'a>,
        {
            let mut outer = VariableList::default();

            while let Some(val) = seq.next_element::<String>()? {
                let inner_vec = hex::decode(&val).map_err(de::Error::custom)?;
                let opaque_transaction = VariableList::new(inner_vec).map_err(|e| {
                    serde::de::Error::custom(format!("transaction too large: {:?}", e))
                })?;
                let transaction = Transaction::OpaqueTransaction(opaque_transaction);
                outer.push(transaction).map_err(|e| {
                    serde::de::Error::custom(format!("too many transactions: {:?}", e))
                })?;
            }

            Ok(outer)
        }
    }

    pub fn serialize<S, T: EthSpec, N: Unsigned>(
        value: &Value<T, N>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for transaction in value {
            // It's important to match on the inner values of the transaction. Serializing the
            // entire `Transaction` will result in appending the SSZ union prefix byte. The
            // execution node does not want that.
            let hex = match transaction {
                Transaction::OpaqueTransaction(val) => hex::encode(&val[..]),
            };
            seq.serialize_element(&hex)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T: EthSpec, N: Unsigned>(
        deserializer: D,
    ) -> Result<Value<T, N>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let visitor: ListOfBytesListVisitor<T, N> = <_>::default();
        deserializer.deserialize_any(visitor)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::MockServer;
    use std::future::Future;
    use std::str::FromStr;
    use std::sync::Arc;
    use types::MainnetEthSpec;

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

    const LOGS_BLOOM_01: &str = "0x01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101";

    fn encode_transactions<E: EthSpec>(
        transactions: VariableList<Transaction<E>, E::MaxTransactionsPerPayload>,
    ) -> Result<serde_json::Value, serde_json::Error> {
        let ep: JsonExecutionPayload<E> = JsonExecutionPayload {
            transactions,
            ..<_>::default()
        };
        let json = serde_json::to_value(&ep)?;
        Ok(json.get("transactions").unwrap().clone())
    }

    fn decode_transactions<E: EthSpec>(
        transactions: serde_json::Value,
    ) -> Result<VariableList<Transaction<E>, E::MaxTransactionsPerPayload>, serde_json::Error> {
        let json = json!({
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
            "transactions": transactions,
        });
        let ep: JsonExecutionPayload<E> = serde_json::from_value(json)?;
        Ok(ep.transactions)
    }

    fn assert_transactions_serde<E: EthSpec>(
        name: &str,
        as_obj: VariableList<Transaction<E>, E::MaxTransactionsPerPayload>,
        as_json: serde_json::Value,
    ) {
        assert_eq!(
            encode_transactions(as_obj.clone()).unwrap(),
            as_json,
            "encoding for {}",
            name
        );
        assert_eq!(
            decode_transactions(as_json).unwrap(),
            as_obj,
            "decoding for {}",
            name
        );
    }

    /// Example: if `spec == &[1, 1]`, then two one-byte transactions will be created.
    fn generate_opaque_transactions<E: EthSpec>(
        spec: &[usize],
    ) -> VariableList<Transaction<E>, E::MaxTransactionsPerPayload> {
        let mut txs = VariableList::default();

        for &num_bytes in spec {
            let mut tx = VariableList::default();
            for _ in 0..num_bytes {
                tx.push(0).unwrap();
            }
            txs.push(Transaction::OpaqueTransaction(tx)).unwrap();
        }

        txs
    }

    #[test]
    fn transaction_serde() {
        assert_transactions_serde::<MainnetEthSpec>(
            "empty",
            generate_opaque_transactions(&[]),
            json!([]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "one empty tx",
            generate_opaque_transactions(&[0]),
            json!(["0x"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "two empty txs",
            generate_opaque_transactions(&[0, 0]),
            json!(["0x", "0x"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "one one-byte tx",
            generate_opaque_transactions(&[1]),
            json!(["0x00"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "two one-byte txs",
            generate_opaque_transactions(&[1, 1]),
            json!(["0x00", "0x00"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "mixed bag",
            generate_opaque_transactions(&[0, 1, 3, 0]),
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

        /*
         * Check for transaction too large
         */

        use eth2_serde_utils::hex;

        let num_max_bytes = <MainnetEthSpec as EthSpec>::MaxBytesPerOpaqueTransaction::to_usize();
        let max_bytes = (0..num_max_bytes).map(|_| 0_u8).collect::<Vec<_>>();
        let too_many_bytes = (0..=num_max_bytes).map(|_| 0_u8).collect::<Vec<_>>();
        decode_transactions::<MainnetEthSpec>(
            serde_json::to_value(&[hex::encode(&max_bytes)]).unwrap(),
        )
        .unwrap();
        assert!(decode_transactions::<MainnetEthSpec>(
            serde_json::to_value(&[hex::encode(&too_many_bytes)]).unwrap()
        )
        .is_err());
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
    async fn prepare_payload_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .prepare_payload(
                            Hash256::repeat_byte(0),
                            42,
                            Hash256::repeat_byte(1),
                            Address::repeat_byte(0),
                        )
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_PREPARE_PAYLOAD,
                    "params": [{
                        "parentHash": HASH_00,
                        "timestamp": "0x2a",
                        "random": HASH_01,
                        "feeRecipient": ADDRESS_00,
                    }]
                }),
            )
            .await;
    }

    #[tokio::test]
    async fn get_payload_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client.get_payload::<MainnetEthSpec>(42).await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_GET_PAYLOAD,
                    "params": ["0x2a"]
                }),
            )
            .await;
    }

    #[tokio::test]
    async fn execute_payload_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .execute_payload::<MainnetEthSpec>(ExecutionPayload {
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
                            base_fee_per_gas: uint256_to_hash256(Uint256::from(1)),
                            block_hash: Hash256::repeat_byte(1),
                            transactions: vec![].into(),
                        })
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_EXECUTE_PAYLOAD,
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
    async fn consensus_validated_request() {
        Tester::new()
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .consensus_validated(Hash256::repeat_byte(0), ConsensusStatus::Valid)
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_CONSENSUS_VALIDATED,
                    "params": [{
                        "blockHash": HASH_00,
                        "status": "VALID",
                    }]
                }),
            )
            .await
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .consensus_validated(Hash256::repeat_byte(1), ConsensusStatus::Invalid)
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_CONSENSUS_VALIDATED,
                    "params": [{
                        "blockHash": HASH_01,
                        "status": "INVALID",
                    }]
                }),
            )
            .await;
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
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_FORKCHOICE_UPDATED,
                    "params": [{
                        "headBlockHash": HASH_00,
                        "finalizedBlockHash": HASH_01,
                    }]
                }),
            )
            .await;
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
                |client| async move {
                    let _ = client
                        .prepare_payload(
                            Hash256::from_str("0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131").unwrap(),
                            5,
                            Hash256::zero(),
                            Address::zero(),
                        )
                        .await;
                },
                serde_json::from_str(r#"{"jsonrpc":"2.0","method":"engine_preparePayload","params":[{"parentHash":"0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131", "timestamp":"0x5", "random":"0x0000000000000000000000000000000000000000000000000000000000000000", "feeRecipient":"0x0000000000000000000000000000000000000000"}],"id": 1}"#).unwrap()
            )
            .await
            .with_preloaded_responses(
                vec![serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"result":{"payloadId":"0x0"}}"#).unwrap()],
                |client| async move {
                    let payload_id = client
                        .prepare_payload(
                            Hash256::from_str("0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131").unwrap(),
                            5,
                            Hash256::zero(),
                            Address::zero(),
                        )
                        .await
                        .unwrap();

                    assert_eq!(payload_id, 0);
                },
            )
            .await
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .get_payload::<MainnetEthSpec>(0)
                        .await;
                },
                serde_json::from_str(r#"{"jsonrpc":"2.0","method":"engine_getPayload","params":["0x0"],"id":1}"#).unwrap()
            )
            .await
            .with_preloaded_responses(
                // Note: this response has been modified due to errors in the test vectors:
                //
                // https://github.com/ethereum/go-ethereum/pull/23607#issuecomment-930668512
                vec![serde_json::from_str(r#"{"jsonrpc":"2.0","id":67,"result":{"blockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174","parentHash":"0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131","coinbase":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receiptRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x989680","gasUsed":"0x0","timestamp":"0x5","extraData":"0x","baseFeePerGas":"0x0","transactions":[]}}"#).unwrap()],
                |client| async move {
                    let payload = client
                        .get_payload::<MainnetEthSpec>(0)
                        .await
                        .unwrap();

                    let expected =  ExecutionPayload {
                            parent_hash: Hash256::from_str("0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131").unwrap(),
                            coinbase: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            state_root: Hash256::from_str("0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45").unwrap(),
                            receipt_root: Hash256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap(),
                            logs_bloom: vec![0; 256].into(),
                            random: Hash256::zero(),
                            block_number: 1,
                            gas_limit: 10000000,
                            gas_used: 0,
                            timestamp: 5,
                            extra_data: vec![].into(),
                            base_fee_per_gas: uint256_to_hash256(Uint256::from(0)),
                            block_hash: Hash256::from_str("0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174").unwrap(),
                            transactions: vec![].into(),
                        };

                    assert_eq!(payload, expected);
                },
            )
            .await
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .execute_payload::<MainnetEthSpec>(ExecutionPayload {
                            parent_hash: Hash256::from_str("0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131").unwrap(),
                            coinbase: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            state_root: Hash256::from_str("0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45").unwrap(),
                            receipt_root: Hash256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap(),
                            logs_bloom: vec![0; 256].into(),
                            random: Hash256::zero(),
                            block_number: 1,
                            gas_limit: 10000000,
                            gas_used: 0,
                            timestamp: 5,
                            extra_data: vec![].into(),
                            base_fee_per_gas: uint256_to_hash256(Uint256::from(0)),
                            block_hash: Hash256::from_str("0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174").unwrap(),
                            transactions: vec![].into(),
                        })
                        .await;
                },
                // Note: I have renamed the `recieptsRoot` field to `recieptRoot` and `number` to `blockNumber` since I think
                // Geth has an issue. See:
                //
                // https://github.com/ethereum/go-ethereum/pull/23607#issuecomment-930668512
                serde_json::from_str(r#"{"jsonrpc":"2.0","method":"engine_executePayload","params":[{"blockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174","parentHash":"0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131","coinbase":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receiptRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x989680","gasUsed":"0x0","timestamp":"0x5","extraData":"0x","baseFeePerGas":"0x0","transactions":[]}],"id":1}"#).unwrap()
            )
            .await
            .with_preloaded_responses(
                vec![serde_json::from_str(r#"{"jsonrpc":"2.0","id":67,"result":{"status":"VALID"}}"#).unwrap()],
                |client| async move {
                    let response = client
                        .execute_payload::<MainnetEthSpec>(ExecutionPayload::default())
                        .await
                        .unwrap();

                    assert_eq!(response, ExecutePayloadResponse::Valid);
                },
            )
            .await
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .consensus_validated(
                            Hash256::from_str("0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174").unwrap(),
                            ConsensusStatus::Valid
                        )
                        .await;
                },
                serde_json::from_str(r#"{"jsonrpc":"2.0","method":"engine_consensusValidated","params":[{"blockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174", "status":"VALID"}],"id":1}"#).unwrap()
            )
            .await
            .with_preloaded_responses(
                vec![serde_json::from_str(r#"{"jsonrpc":"2.0","id":67,"result":null}"#).unwrap()],
                |client| async move {
                    let _: () = client
                        .consensus_validated(
                            Hash256::zero(),
                            ConsensusStatus::Valid
                        )
                        .await
                        .unwrap();
                },
            )
            .await
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .forkchoice_updated(
                            Hash256::from_str("0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174").unwrap(),
                            Hash256::from_str("0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174").unwrap(),
                        )
                        .await;
                },
                // Note: Geth incorrectly uses `engine_forkChoiceUpdated` (capital `C`). I've
                // modified this vector to correct this. See:
                //
                // https://github.com/ethereum/go-ethereum/pull/23607#issuecomment-930668512
                serde_json::from_str(r#"{"jsonrpc":"2.0","method":"engine_forkchoiceUpdated","params":[{"headBlockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174", "finalizedBlockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174"}],"id":1}"#).unwrap()
            )
            .await
            .with_preloaded_responses(
                vec![serde_json::from_str(r#"{"jsonrpc":"2.0","id":67,"result":null}"#).unwrap()],
                |client| async move {
                    let _: () = client
                        .forkchoice_updated(
                            Hash256::zero(),
                            Hash256::zero(),
                        )
                        .await
                        .unwrap();
                },
            )
            .await;
    }
}
