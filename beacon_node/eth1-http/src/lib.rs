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

pub const DEPOSIT_ROOT_BYTES: usize = 32;
pub const DEPOSIT_COUNT_RESPONSE_BYTES: usize = 96;

/// Returns the current block number.
///
/// Uses HTTP JSON RPC at `endpoint`. E.g., `http://localhost:8545`.
pub fn get_block_number(
    endpoint: &str,
    timeout: Duration,
) -> impl Future<Item = u64, Error = String> {
    send_rpc_request(endpoint, "eth_blockNumber", json!([]), timeout)
        .and_then(|response_body| {
            hex_to_u64(
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
pub fn get_block_hash(
    endpoint: &str,
    block_number: u64,
    timeout: Duration,
) -> impl Future<Item = Hash256, Error = String> {
    let params = json!([
        format!("0x{:x}", block_number),
        false // do not return full tx objects.
    ]);

    send_rpc_request(endpoint, "eth_getBlockByNumber", params, timeout)
        .and_then(|response_body| {
            let bytes = hex_to_bytes(
                response_result(&response_body)?
                    .get("hash")
                    .ok_or_else(|| "No hash for block")?
                    .as_str()
                    .ok_or_else(|| "Block hash was not string")?,
            )?;
            if bytes.len() == 32 {
                Ok(Hash256::from_slice(&bytes))
            } else {
                Err(format!("Block has was not 32 bytes: {:?}", bytes))
            }
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
) -> impl Future<Item = u64, Error = String> {
    call(
        endpoint,
        address,
        DEPOSIT_COUNT_FN_SIGNATURE,
        block_number,
        timeout,
    )
    .and_then(|bytes| {
        if bytes.len() == DEPOSIT_COUNT_RESPONSE_BYTES {
            let mut array = [0; 8];
            array.copy_from_slice(&bytes[32 + 32..32 + 32 + 8]);
            Ok(u64::from_le_bytes(array))
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
) -> impl Future<Item = Hash256, Error = String> {
    call(
        endpoint,
        address,
        DEPOSIT_ROOT_FN_SIGNATURE,
        block_number,
        timeout,
    )
    .and_then(|bytes| {
        if bytes.len() == DEPOSIT_ROOT_BYTES {
            Ok(Hash256::from_slice(&bytes))
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
    block_number: u64,
    data: Vec<u8>,
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
                        block_number: hex_to_u64(&block_number)?,
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
                Err(format!("Received error {}.", response.status()))
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

fn hex_to_u64(hex: &str) -> Result<u64, String> {
    let hex = if hex.starts_with("0x") {
        &hex[2..]
    } else {
        hex
    };

    u64::from_str_radix(hex, 16).map_err(|e| format!("Failed to parse hex as u64: {:?}", e))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = if hex.starts_with("0x") {
        &hex[2..]
    } else {
        hex
    };

    hex::decode(hex).map_err(|e| format!("Failed to parse hex as u64: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth1_test_rig::DepositContract;
    use tokio::runtime::Runtime;
    use types::{DepositData, Epoch, EthSpec, Fork, Hash256, Keypair, MainnetEthSpec, Signature};

    const ENDPOINT: &str = "http://localhost:8545";

    fn runtime() -> Runtime {
        Runtime::new().expect("should create runtime")
    }

    fn timeout() -> Duration {
        Duration::from_secs(1)
    }

    fn random_deposit_data() -> DepositData {
        let keypair = Keypair::random();

        let mut deposit = DepositData {
            pubkey: keypair.pk.into(),
            withdrawal_credentials: Hash256::zero(),
            amount: 32_000_000_000,
            signature: Signature::empty_signature().into(),
        };

        deposit.signature = deposit.create_signature(
            &keypair.sk,
            Epoch::new(0),
            &Fork::default(),
            &MainnetEthSpec::default_spec(),
        );

        deposit
    }

    fn blocking_block_number() -> u64 {
        runtime()
            .block_on(get_block_number(ENDPOINT, timeout()))
            .expect("should get block number")
    }

    fn blocking_block_hash(block_number: u64) -> Hash256 {
        runtime()
            .block_on(get_block_hash(ENDPOINT, block_number, timeout()))
            .expect("should get block number")
    }

    fn blocking_deposit_logs(deposit_contract: &DepositContract, range: Range<u64>) -> Vec<Log> {
        runtime()
            .block_on(get_deposit_logs_in_range(
                ENDPOINT,
                &deposit_contract.address(),
                range,
                timeout(),
            ))
            .expect("should get logs")
    }

    fn blocking_deposit_root(deposit_contract: &DepositContract, block_number: u64) -> Hash256 {
        runtime()
            .block_on(get_deposit_root(
                ENDPOINT,
                &deposit_contract.address(),
                block_number,
                timeout(),
            ))
            .expect("should get deposit root")
    }

    fn blocking_deposit_count(deposit_contract: &DepositContract, block_number: u64) -> u64 {
        runtime()
            .block_on(get_deposit_count(
                ENDPOINT,
                &deposit_contract.address(),
                block_number,
                timeout(),
            ))
            .expect("should get deposit count")
    }

    #[test]
    fn incrementing_deposits() {
        let deposit_contract =
            DepositContract::deploy(ENDPOINT).expect("should deploy deposit contract");

        let block_number = blocking_block_number();
        let logs = blocking_deposit_logs(&deposit_contract, 0..block_number);
        assert_eq!(logs.len(), 0);

        let mut old_root = blocking_deposit_root(&deposit_contract, block_number);
        let mut old_block_hash = blocking_block_hash(block_number);
        let mut old_block_number = block_number;

        assert_eq!(
            blocking_deposit_count(&deposit_contract, block_number),
            0,
            "should have deposit count zero"
        );

        for i in 1..=3 {
            deposit_contract
                .deposit(random_deposit_data())
                .expect("should perform a deposit");

            // Check the logs.
            let block_number = blocking_block_number();
            let logs = blocking_deposit_logs(&deposit_contract, 0..block_number);
            assert_eq!(logs.len(), i, "the number of logs should be as expected");

            // Check the deposit count.
            assert_eq!(
                blocking_deposit_count(&deposit_contract, block_number),
                i as u64,
                "should have a correct deposit count"
            );

            // Check the deposit root.
            let new_root = blocking_deposit_root(&deposit_contract, block_number);
            assert_ne!(
                new_root, old_root,
                "deposit root should change with each deposit"
            );
            old_root = new_root;

            // Check the block hash.
            let new_block_hash = blocking_block_hash(block_number);
            assert_ne!(
                new_block_hash, old_block_hash,
                "block hash should change with each deposit"
            );
            old_block_hash = new_block_hash;

            // Check the block number.
            assert!(
                block_number > old_block_number,
                "block number should increase"
            );
            old_block_number = block_number;
        }
    }
}
