//! Provides a very minimal set of functions for interfacing with the eth2 deposit contract via an
//! eth1 HTTP JSON-RPC endpoint.
//!
//! All remote functions return a future (i.e., are async).
//!
//! Does not use a web3 library, instead it uses `reqwest` (`hyper`) to call the remote endpoint
//! and `serde` to decode the response.
//!
//! ## Note
//!
//! There is no ABI parsing here, all function signatures and topics are hard-coded as constants.

use futures::future::TryFutureExt;
use reqwest::{header::CONTENT_TYPE, ClientBuilder, StatusCode};
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::ops::Range;
use std::str::FromStr;
use std::time::Duration;
use types::{Address, ExecutionPayload, FixedVector, Hash256, Transaction, Uint256, VariableList};

/// `keccak("DepositEvent(bytes,bytes,bytes,bytes,bytes)")`
pub const DEPOSIT_EVENT_TOPIC: &str =
    "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5";
/// `keccak("get_deposit_root()")[0..4]`
pub const DEPOSIT_ROOT_FN_SIGNATURE: &str = "0xc5f2892f";
/// `keccak("get_deposit_count()")[0..4]`
pub const DEPOSIT_COUNT_FN_SIGNATURE: &str = "0x621fd130";

/// Number of bytes in deposit contract deposit root response.
pub const DEPOSIT_COUNT_RESPONSE_BYTES: usize = 96;
/// Number of bytes in deposit contract deposit root (value only).
pub const DEPOSIT_ROOT_BYTES: usize = 32;

/// Represents an eth1 chain/network id.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Eth1Id {
    Goerli,
    Mainnet,
    Custom(u64),
}

/// Used to identify a block when querying the Eth1 node.
#[derive(Clone, Copy)]
pub enum BlockQuery {
    Number(u64),
    Latest,
}

impl Into<u64> for Eth1Id {
    fn into(self) -> u64 {
        match self {
            Eth1Id::Mainnet => 1,
            Eth1Id::Goerli => 5,
            Eth1Id::Custom(id) => id,
        }
    }
}

impl From<u64> for Eth1Id {
    fn from(id: u64) -> Self {
        let into = |x: Eth1Id| -> u64 { x.into() };
        match id {
            id if id == into(Eth1Id::Mainnet) => Eth1Id::Mainnet,
            id if id == into(Eth1Id::Goerli) => Eth1Id::Goerli,
            id => Eth1Id::Custom(id),
        }
    }
}

impl FromStr for Eth1Id {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u64::from_str_radix(s, 10)
            .map(Into::into)
            .map_err(|e| format!("Failed to parse eth1 network id {}", e))
    }
}

/// Get the eth1 network id of the given endpoint.
pub async fn get_network_id(endpoint: &SensitiveUrl, timeout: Duration) -> Result<Eth1Id, String> {
    let response_body = send_rpc_request(endpoint, "net_version", json!([]), timeout).await?;
    Eth1Id::from_str(
        response_result(&response_body)?
            .ok_or("No result was returned for network id")?
            .as_str()
            .ok_or("Data was not string")?,
    )
}

/// Get the eth1 chain id of the given endpoint.
pub async fn get_chain_id(endpoint: &SensitiveUrl, timeout: Duration) -> Result<Eth1Id, String> {
    let response_body = send_rpc_request(endpoint, "eth_chainId", json!([]), timeout).await?;
    hex_to_u64_be(
        response_result(&response_body)?
            .ok_or("No result was returned for chain id")?
            .as_str()
            .ok_or("Data was not string")?,
    )
    .map(Into::into)
}

#[derive(Debug, PartialEq, Clone)]
pub struct Block {
    pub hash: Hash256,
    pub timestamp: u64,
    pub number: u64,
}

/// Returns the current block number.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub async fn get_block_number(endpoint: &SensitiveUrl, timeout: Duration) -> Result<u64, String> {
    let response_body = send_rpc_request(endpoint, "eth_blockNumber", json!([]), timeout).await?;
    hex_to_u64_be(
        response_result(&response_body)?
            .ok_or("No result field was returned for block number")?
            .as_str()
            .ok_or("Data was not string")?,
    )
    .map_err(|e| format!("Failed to get block number: {}", e))
}

/// Gets a block hash by block number.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub async fn get_block(
    endpoint: &SensitiveUrl,
    query: BlockQuery,
    timeout: Duration,
) -> Result<Block, String> {
    let query_param = match query {
        BlockQuery::Number(block_number) => format!("0x{:x}", block_number),
        BlockQuery::Latest => "latest".to_string(),
    };
    let params = json!([
        query_param,
        false // do not return full tx objects.
    ]);

    let response_body = send_rpc_request(endpoint, "eth_getBlockByNumber", params, timeout).await?;
    let hash = hex_to_bytes(
        response_result(&response_body)?
            .ok_or("No result field was returned for block")?
            .get("hash")
            .ok_or("No hash for block")?
            .as_str()
            .ok_or("Block hash was not string")?,
    )?;
    let hash = if hash.len() == 32 {
        Ok(Hash256::from_slice(&hash))
    } else {
        Err(format!("Block has was not 32 bytes: {:?}", hash))
    }?;

    let timestamp = hex_to_u64_be(
        response_result(&response_body)?
            .ok_or("No result field was returned for timestamp")?
            .get("timestamp")
            .ok_or("No timestamp for block")?
            .as_str()
            .ok_or("Block timestamp was not string")?,
    )?;

    let number = hex_to_u64_be(
        response_result(&response_body)?
            .ok_or("No result field was returned for number")?
            .get("number")
            .ok_or("No number for block")?
            .as_str()
            .ok_or("Block number was not string")?,
    )?;

    if number <= usize::max_value() as u64 {
        Ok(Block {
            hash,
            timestamp,
            number,
        })
    } else {
        Err(format!("Block number {} is larger than a usize", number))
    }
    .map_err(|e| format!("Failed to get block number: {}", e))
}

#[derive(Serialize)]
struct AssembleBlockRequest {
    #[serde(rename = "parentHash")]
    parent_hash: Hash256,
    #[serde(with = "serde_utils::u64_hex_be")]
    timestamp: u64,
}

/// A redefinition of the `ExecutionPayload` struct which will serialize/deserialize in accordance
/// with the Eth1 JSON schema.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct JsonExecutionPayload {
    #[serde(rename = "blockHash")]
    block_hash: Hash256,
    #[serde(rename = "parentHash")]
    parent_hash: Hash256,
    miner: Address,
    #[serde(rename = "stateRoot")]
    state_root: Hash256,
    #[serde(with = "serde_utils::u64_hex_be")]
    number: u64,
    #[serde(with = "serde_utils::u64_hex_be", rename = "gasLimit")]
    gas_limit: u64,
    #[serde(with = "serde_utils::u64_hex_be", rename = "gasUsed")]
    gas_used: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    timestamp: u64,
    #[serde(rename = "receiptsRoot")]
    receipts_root: Hash256,
    #[serde(rename = "logsBloom")]
    logs_bloom: String,
    #[serde(with = "serde_utils::list_of_bytes_lists")]
    transactions: Vec<Vec<u8>>,
}

pub async fn consensus_assemble_block(
    endpoint: &str,
    parent_hash: Hash256,
    timestamp: u64,
    timeout: Duration,
) -> Result<ExecutionPayload, String> {
    let params = json!([AssembleBlockRequest {
        parent_hash,
        timestamp,
    }]);

    let response_body =
        send_rpc_request(endpoint, "consensus_assembleBlock", params, timeout).await?;
    let result = response_result(&response_body)?
        .ok_or("No result field was returned for consensus_assembleBlock")?;

    let response: JsonExecutionPayload = serde_json::from_value(result)
        .map_err(|e| format!("Unable to parse consensus_assembleBlock JSON: {:?}", e))?;

    let logs_bloom = base64::decode(&response.logs_bloom)
        .map_err(|e| format!("Failed to decode logs_bloom base64: {:?}", e))?;

    let transactions = response
        .transactions
        .into_iter()
        .map(VariableList::new)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("Invalid transactions in consensus_assembleBlock: {:?}", e))?;

    Ok(ExecutionPayload {
        block_hash: response.block_hash,
        parent_hash: response.parent_hash,
        coinbase: response.miner,
        state_root: response.state_root,
        number: response.number,
        gas_limit: response.gas_limit,
        gas_used: response.gas_used,
        timestamp: response.timestamp,
        receipt_root: response.receipts_root,
        logs_bloom: FixedVector::new(logs_bloom)
            .map_err(|e| format!("Invalid logs_bloom in consensus_assembleBlock: {:?}", e))?,
        transactions: VariableList::new(transactions).map_err(|e| {
            format!(
                "Invalid transactions list in consensus_assembleBlock: {:?}",
                e
            )
        })?,
    })
}

#[derive(Debug, PartialEq, Deserialize)]
struct NewBlockResponse {
    valid: bool,
}

pub async fn consensus_new_block(
    endpoint: &str,
    execution_payload: &ExecutionPayload,
    timeout: Duration,
) -> Result<bool, String> {
    let json_execution_payload = JsonExecutionPayload {
        block_hash: execution_payload.block_hash,
        parent_hash: execution_payload.parent_hash,
        miner: execution_payload.coinbase,
        state_root: execution_payload.state_root,
        number: execution_payload.number,
        gas_limit: execution_payload.gas_limit,
        gas_used: execution_payload.gas_used,
        timestamp: execution_payload.timestamp,
        receipts_root: execution_payload.receipt_root,
        logs_bloom: base64::encode(&execution_payload.logs_bloom[..]),
        transactions: execution_payload
            .transactions
            .iter()
            .map(|variable_list| variable_list.clone().into())
            .collect(),
    };

    let params = json!([json_execution_payload]);

    let response_body = send_rpc_request(endpoint, "consensus_newBlock", params, timeout).await?;
    let result = response_result(&response_body)?
        .ok_or("No result field was returned for consensus_newBlock")?;

    serde_json::from_value::<NewBlockResponse>(result)
        .map(|response| response.valid)
        .map_err(|e| format!("Unable to parse consensus_newBlock JSON: {:?}", e))
}

/// Returns the value of the `get_deposit_count()` call at the given `address` for the given
/// `block_number`.
///
/// Assumes that the `address` has the same ABI as the eth2 deposit contract.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub async fn get_deposit_count(
    endpoint: &SensitiveUrl,
    address: &str,
    block_number: u64,
    timeout: Duration,
) -> Result<Option<u64>, String> {
    let result = call(
        endpoint,
        address,
        DEPOSIT_COUNT_FN_SIGNATURE,
        block_number,
        timeout,
    )
    .await?;
    match result {
        None => Err("Deposit root response was none".to_string()),
        Some(bytes) => {
            if bytes.is_empty() {
                Ok(None)
            } else if bytes.len() == DEPOSIT_COUNT_RESPONSE_BYTES {
                let mut array = [0; 8];
                array.copy_from_slice(&bytes[32 + 32..32 + 32 + 8]);
                Ok(Some(u64::from_le_bytes(array)))
            } else {
                Err(format!(
                    "Deposit count response was not {} bytes: {:?}",
                    DEPOSIT_COUNT_RESPONSE_BYTES, bytes
                ))
            }
        }
    }
}

/// Returns the value of the `get_hash_tree_root()` call at the given `block_number`.
///
/// Assumes that the `address` has the same ABI as the eth2 deposit contract.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub async fn get_deposit_root(
    endpoint: &SensitiveUrl,
    address: &str,
    block_number: u64,
    timeout: Duration,
) -> Result<Option<Hash256>, String> {
    let result = call(
        endpoint,
        address,
        DEPOSIT_ROOT_FN_SIGNATURE,
        block_number,
        timeout,
    )
    .await?;
    match result {
        None => Err("Deposit root response was none".to_string()),
        Some(bytes) => {
            if bytes.is_empty() {
                Ok(None)
            } else if bytes.len() == DEPOSIT_ROOT_BYTES {
                Ok(Some(Hash256::from_slice(&bytes)))
            } else {
                Err(format!(
                    "Deposit root response was not {} bytes: {:?}",
                    DEPOSIT_ROOT_BYTES, bytes
                ))
            }
        }
    }
}

/// Performs a instant, no-transaction call to the contract `address` with the given `0x`-prefixed
/// `hex_data`.
///
/// Returns bytes, if any.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
async fn call(
    endpoint: &SensitiveUrl,
    address: &str,
    hex_data: &str,
    block_number: u64,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, String> {
    let params = json! ([
        {
            "to": address,
            "data": hex_data,
        },
        format!("0x{:x}", block_number)
    ]);

    let response_body = send_rpc_request(endpoint, "eth_call", params, timeout).await?;
    match response_result(&response_body)? {
        None => Ok(None),
        Some(result) => {
            let hex = result
                .as_str()
                .map(|s| s.to_string())
                .ok_or("'result' value was not a string")?;

            Ok(Some(hex_to_bytes(&hex)?))
        }
    }
}

/// A reduced set of fields from an Eth1 contract log.
#[derive(Debug, PartialEq, Clone)]
pub struct Log {
    pub(crate) block_number: u64,
    pub(crate) data: Vec<u8>,
}

/// Returns logs for the `DEPOSIT_EVENT_TOPIC`, for the given `address` in the given
/// `block_height_range`.
///
/// It's not clear from the Ethereum JSON-RPC docs if this range is inclusive or not.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub async fn get_deposit_logs_in_range(
    endpoint: &SensitiveUrl,
    address: &str,
    block_height_range: Range<u64>,
    timeout: Duration,
) -> Result<Vec<Log>, String> {
    let params = json! ([{
        "address": address,
        "topics": [DEPOSIT_EVENT_TOPIC],
        "fromBlock": format!("0x{:x}", block_height_range.start),
        "toBlock": format!("0x{:x}", block_height_range.end),
    }]);

    let response_body = send_rpc_request(endpoint, "eth_getLogs", params, timeout).await?;
    response_result(&response_body)?
        .ok_or("No result field was returned for deposit logs")?
        .as_array()
        .cloned()
        .ok_or("'result' value was not an array")?
        .into_iter()
        .map(|value| {
            let block_number = value
                .get("blockNumber")
                .ok_or("No block number field in log")?
                .as_str()
                .ok_or("Block number was not string")?;

            let data = value
                .get("data")
                .ok_or("No block number field in log")?
                .as_str()
                .ok_or("Data was not string")?;

            Ok(Log {
                block_number: hex_to_u64_be(&block_number)?,
                data: hex_to_bytes(data)?,
            })
        })
        .collect::<Result<Vec<Log>, String>>()
        .map_err(|e| format!("Failed to get logs in range: {}", e))
}

/// Sends an RPC request to `endpoint`, using a POST with the given `body`.
///
/// Tries to receive the response and parse the body as a `String`.
pub async fn send_rpc_request(
    endpoint: &SensitiveUrl,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<String, String> {
    let body = json! ({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    })
    .to_string();

    // Note: it is not ideal to create a new client for each request.
    //
    // A better solution would be to create some struct that contains a built client and pass it
    // around (similar to the `web3` crate's `Transport` structs).
    let response = ClientBuilder::new()
        .timeout(timeout)
        .build()
        .expect("The builder should always build a client")
        .post(endpoint.full.clone())
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .map_err(|e| format!("Request failed: {:?}", e))
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!(
            "Response HTTP status was not 200 OK:  {}.",
            response.status()
        ));
    };
    let encoding = response
        .headers()
        .get(CONTENT_TYPE)
        .ok_or("No content-type header in response")?
        .to_str()
        .map(|s| s.to_string())
        .map_err(|e| format!("Failed to parse content-type header: {}", e))?;

    response
        .bytes()
        .map_err(|e| format!("Failed to receive body: {:?}", e))
        .await
        .and_then(move |bytes| match encoding.as_str() {
            "application/json" => Ok(bytes),
            "application/json; charset=utf-8" => Ok(bytes),
            other => Err(format!("Unsupported encoding: {}", other)),
        })
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|e| format!("Failed to receive body: {:?}", e))
}

/// Accepts an entire HTTP body (as a string) and returns the `result` field, as a serde `Value`.
fn response_result(response: &str) -> Result<Option<Value>, String> {
    let json = serde_json::from_str::<Value>(&response)
        .map_err(|e| format!("Failed to parse response: {:?}", e))?;

    if let Some(error) = json.get("error") {
        Err(format!("Eth1 node returned error: {}", error))
    } else {
        Ok(json
            .get("result")
            .cloned()
            .map(Some)
            .unwrap_or_else(|| None))
    }
}

/// Parses a `0x`-prefixed, **big-endian** hex string as a u64.
///
/// Note: the JSON-RPC encodes integers as big-endian. The deposit contract uses little-endian.
/// Therefore, this function is only useful for numbers encoded by the JSON RPC.
///
/// E.g., `0x01 == 1`
fn hex_to_u64_be(hex: &str) -> Result<u64, String> {
    u64::from_str_radix(strip_prefix(hex)?, 16)
        .map_err(|e| format!("Failed to parse hex as u64: {:?}", e))
}

/// Parses a `0x`-prefixed, big-endian hex string as bytes.
///
/// E.g., `0x0102 == vec![1, 2]`
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    hex::decode(strip_prefix(hex)?).map_err(|e| format!("Failed to parse hex as bytes: {:?}", e))
}

/// Removes the `0x` prefix from some bytes. Returns an error if the prefix is not present.
fn strip_prefix(hex: &str) -> Result<&str, String> {
    if let Some(stripped) = hex.strip_prefix("0x") {
        Ok(stripped)
    } else {
        Err("Hex string did not start with `0x`".to_string())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct JsonTransaction {
    #[serde(with = "serde_utils::u64_hex_be")]
    pub nonce: u64,
    #[serde(rename = "gasPrice")]
    pub gas_price: Uint256,
    #[serde(rename = "gas", with = "serde_utils::u64_hex_be")]
    pub gas_limit: u64,
    pub to: Option<Address>,
    pub value: Uint256,
    #[serde(with = "serde_utils::hex_vec")]
    pub input: Vec<u8>,
    pub v: Uint256,
    pub r: Uint256,
    pub s: Uint256,
}

impl Into<Result<Transaction, String>> for JsonTransaction {
    fn into(self) -> Result<Transaction, String> {
        Ok(Transaction {
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            recipient: self.to,
            value: self.value,
            input: VariableList::new(self.input)
                .map_err(|e| format!("Invalid transaction input field: {:?}", e))?,
            v: self.v,
            r: self.r,
            s: self.s,
        })
    }
}

impl From<Transaction> for JsonTransaction {
    fn from(t: Transaction) -> JsonTransaction {
        Self {
            nonce: t.nonce,
            gas_price: t.gas_price,
            gas_limit: t.gas_limit,
            to: t.recipient,
            value: t.value,
            input: t.input.to_vec(),
            v: t.v,
            r: t.r,
            s: t.s,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_assemble_block_request() {
        let reference = r#"{"parentHash":"0xa68f81fa333010c7f6b84536793a722aa20b3d7eb73b54ca8ea2a0fd5834ddaf","timestamp":"0x607e8240"}"#;

        let local = AssembleBlockRequest {
            parent_hash: serde_json::from_str(
                "\"0xa68f81fa333010c7f6b84536793a722aa20b3d7eb73b54ca8ea2a0fd5834ddaf\"",
            )
            .unwrap(),
            timestamp: 1618903616,
        };

        assert_eq!(serde_json::to_string(&local).unwrap(), reference);
    }

    #[test]
    fn decode_json_execution_payload() {
        // Pretty is easy to troubleshoot since serde gives the line number with the issue, this
        // makes it easy to find the offending field.
        let reference_pretty = r#"{
			"blockHash": "0x927be870eaa59bac61d9e118904d898de2a20cba1dea5dd8856c2cc7a38364a2",
			"parentHash": "0xa68f81fa333010c7f6b84536793a722aa20b3d7eb73b54ca8ea2a0fd5834ddaf",
			"miner": "0x1000000000000000000000000000000000000000",
			"stateRoot": "0x0aef2cef869e5b93c69722bbea2f76d477ccefa1862a5a48450726d7a067db42",
			"number": "0x1",
			"gasLimit": "0x400000",
			"gasUsed": "0x5208",
			"timestamp": "0x607e8240",
			"receiptsRoot": "0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"transactions": [
			  "0xf8698004825208944a776e9369831f50564e430aacdd58b6be78a10b880de0b6b3a76400008082059ca07c3cc5403b459b15ff24a961d58d525c860b432fa3dc98c914342f8089a766bba02d6402409be46cec176d180d04f9f0cc0c00bb20c254a633949aff1b0962f2ab"
			]
		  }"#;

        // Compact is necessary to check that the encoding is accurate.
        let reference_compact = r#"{"blockHash":"0x927be870eaa59bac61d9e118904d898de2a20cba1dea5dd8856c2cc7a38364a2","parentHash":"0xa68f81fa333010c7f6b84536793a722aa20b3d7eb73b54ca8ea2a0fd5834ddaf","miner":"0x1000000000000000000000000000000000000000","stateRoot":"0x0aef2cef869e5b93c69722bbea2f76d477ccefa1862a5a48450726d7a067db42","number":"0x1","gasLimit":"0x400000","gasUsed":"0x5208","timestamp":"0x607e8240","receiptsRoot":"0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","transactions":["0xf8698004825208944a776e9369831f50564e430aacdd58b6be78a10b880de0b6b3a76400008082059ca07c3cc5403b459b15ff24a961d58d525c860b432fa3dc98c914342f8089a766bba02d6402409be46cec176d180d04f9f0cc0c00bb20c254a633949aff1b0962f2ab"]}"#;

        let decoded: JsonExecutionPayload =
            serde_json::from_str(reference_pretty).expect("should decode reference string");

        assert_eq!(
            serde_json::to_string(&decoded).unwrap(),
            reference_compact,
            "should encode exactly as reference string"
        );
    }

    #[test]
    fn decode_new_block_response() {
        assert_eq!(
            serde_json::from_str::<NewBlockResponse>(r#"{"valid":true}"#).unwrap(),
            NewBlockResponse { valid: true }
        );
        assert_eq!(
            serde_json::from_str::<NewBlockResponse>(r#"{"valid":false}"#).unwrap(),
            NewBlockResponse { valid: false }
        );
    }
}
