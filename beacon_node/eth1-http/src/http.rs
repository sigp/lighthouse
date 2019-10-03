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

use futures::{Future, Stream};
use reqwest::{r#async::ClientBuilder, StatusCode};
use serde_json::{json, Value};
use std::ops::Range;
use std::time::Duration;
use types::Hash256;

/// `keccak("DepositEvent(bytes,bytes,bytes,bytes,bytes)")`
pub const DEPOSIT_EVENT_TOPIC: &str =
    "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5";
/// `keccak("get_deposit_root()")[0..4]`
pub const DEPOSIT_ROOT_FN_SIGNATURE: &str = "0x863a311b";
/// `keccak("get_deposit_count()")[0..4]`
pub const DEPOSIT_COUNT_FN_SIGNATURE: &str = "0x621fd130";

/// Number of bytes in deposit contract deposit root response.
pub const DEPOSIT_COUNT_RESPONSE_BYTES: usize = 96;
/// Number of bytes in deposit contract deposit root (value only).
pub const DEPOSIT_ROOT_BYTES: usize = 32;

#[derive(Debug, PartialEq, Clone)]
pub struct Block {
    pub hash: Hash256,
    pub timestamp: u64,
    pub number: u64,
}

/// Returns the current block number.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub fn get_block_number(
    endpoint: &str,
    timeout: Duration,
) -> impl Future<Item = u64, Error = String> {
    send_rpc_request(endpoint, "eth_blockNumber", json!([]), timeout)
        .and_then(|response_body| {
            hex_to_u64_be(
                response_result(&response_body)?
                    .as_str()
                    .ok_or_else(|| "Data was not string")?,
            )
        })
        .map_err(|e| format!("Failed to get block number: {}", e))
}

/// Gets a block hash by block number.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub fn get_block(
    endpoint: &str,
    block_number: u64,
    timeout: Duration,
) -> impl Future<Item = Block, Error = String> {
    let params = json!([
        format!("0x{:x}", block_number),
        false // do not return full tx objects.
    ]);

    send_rpc_request(endpoint, "eth_getBlockByNumber", params, timeout)
        .and_then(|response_body| {
            let hash = hex_to_bytes(
                response_result(&response_body)?
                    .get("hash")
                    .ok_or_else(|| "No hash for block")?
                    .as_str()
                    .ok_or_else(|| "Block hash was not string")?,
            )?;
            let hash = if hash.len() == 32 {
                Ok(Hash256::from_slice(&hash))
            } else {
                Err(format!("Block has was not 32 bytes: {:?}", hash))
            }?;

            let timestamp = hex_to_u64_be(
                response_result(&response_body)?
                    .get("timestamp")
                    .ok_or_else(|| "No timestamp for block")?
                    .as_str()
                    .ok_or_else(|| "Block timestamp was not string")?,
            )?;

            let number = hex_to_u64_be(
                response_result(&response_body)?
                    .get("number")
                    .ok_or_else(|| "No number for block")?
                    .as_str()
                    .ok_or_else(|| "Block number was not string")?,
            )?;

            Ok(Block {
                hash,
                timestamp,
                number,
            })
        })
        .map_err(|e| format!("Failed to get block number: {}", e))
}

/// Returns the value of the `get_deposit_count()` call at the given `address` for the given
/// `block_number`.
///
/// Assumes that the `address` has the same ABI as the eth2 deposit contract.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub fn get_deposit_count(
    endpoint: &str,
    address: &str,
    block_number: u64,
    timeout: Duration,
) -> impl Future<Item = Option<u64>, Error = String> {
    call(
        endpoint,
        address,
        DEPOSIT_COUNT_FN_SIGNATURE,
        block_number,
        timeout,
    )
    .and_then(|bytes| {
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
    })
}

/// Returns the value of the `get_hash_tree_root()` call at the given `block_number`.
///
/// Assumes that the `address` has the same ABI as the eth2 deposit contract.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub fn get_deposit_root(
    endpoint: &str,
    address: &str,
    block_number: u64,
    timeout: Duration,
) -> impl Future<Item = Option<Hash256>, Error = String> {
    call(
        endpoint,
        address,
        DEPOSIT_ROOT_FN_SIGNATURE,
        block_number,
        timeout,
    )
    .and_then(|bytes| {
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
    })
}

/// Performs a instant, no-transaction call to the contract `address` with the given `0x`-prefixed
/// `hex_data`.
///
/// Returns bytes, if any.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
fn call(
    endpoint: &str,
    address: &str,
    hex_data: &str,
    block_number: u64,
    timeout: Duration,
) -> impl Future<Item = Vec<u8>, Error = String> {
    let params = json! ([
        {
            "to": address,
            "data": hex_data,
        },
        format!("0x{:x}", block_number)
    ]);

    send_rpc_request(endpoint, "eth_call", params, timeout)
        .and_then(|response_body| {
            hex_to_bytes(
                response_result(&response_body)?
                    .as_str()
                    .ok_or_else(|| "'result' value was not a string".to_string())?,
            )
        })
        .map_err(|e| format!("Failed to get logs in range: {}", e))
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
pub fn get_deposit_logs_in_range(
    endpoint: &str,
    address: &str,
    block_height_range: Range<u64>,
    timeout: Duration,
) -> impl Future<Item = Vec<Log>, Error = String> {
    let params = json! ([{
        "address": address,
        "topics": [DEPOSIT_EVENT_TOPIC],
        "fromBlock": format!("0x{:x}", block_height_range.start),
        "toBlock": format!("0x{:x}", block_height_range.end),
    }]);;

    send_rpc_request(endpoint, "eth_getLogs", params, timeout)
        .and_then(|response_body| {
            response_result(&response_body)?
                .as_array()
                .cloned()
                .ok_or_else(|| "'result' value was not an array".to_string())?
                .into_iter()
                .map(|value| {
                    let block_number = value
                        .get("blockNumber")
                        .ok_or_else(|| "No block number field in log")?
                        .as_str()
                        .ok_or_else(|| "Block number was not string")?;

                    let data = value
                        .get("data")
                        .ok_or_else(|| "No block number field in log")?
                        .as_str()
                        .ok_or_else(|| "Data was not string")?;

                    Ok(Log {
                        block_number: hex_to_u64_be(&block_number)?,
                        data: hex_to_bytes(data)?,
                    })
                })
                .collect::<Result<Vec<Log>, String>>()
        })
        .map_err(|e| format!("Failed to get logs in range: {}", e))
}

/// Sends an RPC request to `endpoint`, using a POST with the given `body`.
///
/// Tries to receive the response and parse the body as a `String`.
fn send_rpc_request(
    endpoint: &str,
    method: &str,
    params: Value,
    timeout: Duration,
) -> impl Future<Item = String, Error = String> {
    let body = json! ({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    })
    .to_string();

    ClientBuilder::new()
        .timeout(timeout)
        .build()
        .expect("The builder should always build a client")
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(body)
        .send()
        .map_err(|e| format!("Request failed: {:?}", e))
        .and_then(|response| {
            if response.status() != StatusCode::OK {
                Err(format!(
                    "Response HTTP status was not 200 OK:  {}.",
                    response.status()
                ))
            } else {
                Ok(response)
            }
        })
        .and_then(|response| {
            response
                .into_body()
                .concat2()
                .map(|chunk| chunk.iter().cloned().collect::<Vec<u8>>())
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .map_err(|e| format!("Failed to receive body: {:?}", e))
        })
}

/// Accepts an entire HTTP body (as a string) and returns the `result` field, as a serde `Value`.
fn response_result(response: &str) -> Result<Value, String> {
    serde_json::from_str::<Value>(&response)
        .map_err(|e| format!("Failed to parse response: {:?}", e))?
        .get("result")
        .cloned()
        .ok_or_else(|| "Rpc response did not have a `result` field".to_string())
}

/// Parses a `0x`-prefixed, **big-endian** hex string as a u64.
///
/// Note: the JSON-RPC encodes integers as big-endian. The deposit contract uses little-endian.
/// Therefore, this function is only useful for numbers encoded by the JSON RPC.
///
/// E.g., `0x01 == 1`
fn hex_to_u64_be(hex: &str) -> Result<u64, String> {
    if hex.starts_with("0x") {
        u64::from_str_radix(&hex[2..], 16)
            .map_err(|e| format!("Failed to parse hex as u64: {:?}", e))
    } else {
        Err("Hex string did not start with `0x`".to_string())
    }
}

/// Parses a `0x`-prefixed, big-endian hex string as bytes.
///
/// E.g., `0x0102 == vec![1, 2]`
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.starts_with("0x") {
        hex::decode(&hex[2..]).map_err(|e| format!("Failed to parse hex as bytes: {:?}", e))
    } else {
        Err("Hex string did not start with `0x`".to_string())
    }
}
