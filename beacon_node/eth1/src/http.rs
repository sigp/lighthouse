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
use types::Hash256;

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
        s.parse::<u64>()
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
