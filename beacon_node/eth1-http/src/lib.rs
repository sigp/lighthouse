use futures::{Future, Stream};
use reqwest::{r#async::ClientBuilder, StatusCode};
use serde_json::{json, Value};
use std::ops::Range;
use std::time::Duration;

/// The topic for deposit contract events.
const DEPOSIT_EVENT_TOPIC: &str =
    "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5";

pub fn get_block_number(
    endpoint: &str,
    timeout: Duration,
) -> impl Future<Item = u64, Error = String> {
    let body = json! ({
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 1
    });

    send_rpc_request(endpoint, body.to_string(), timeout)
        .and_then(|response_body| {
            hex_to_u64(
                response_result(&response_body)?
                    .as_str()
                    .ok_or_else(|| "Data was not string")?,
            )
        })
        .map_err(|e| format!("Failed to get block number: {}", e))
}

#[derive(Debug, PartialEq, Clone)]
pub struct Log {
    block_number: u64,
    data: Vec<u8>,
}

pub fn get_deposit_logs_in_range(
    endpoint: &str,
    address: &str,
    block_height_range: Range<u64>,
    timeout: Duration,
) -> impl Future<Item = Vec<Log>, Error = String> {
    let body = json! ({
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{
            "address": address,
            "topics": [DEPOSIT_EVENT_TOPIC],
            "fromBlock": format!("0x{:x}", block_height_range.start),
            "toBlock": format!("0x{:x}", block_height_range.end),
        }],
        "id": 1
    });

    send_rpc_request(endpoint, body.to_string(), timeout)
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
    body: String,
    timeout: Duration,
) -> impl Future<Item = String, Error = String> {
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

    #[test]
    fn block_number() {
        runtime()
            .block_on(get_block_number(
                "http://localhost:8545",
                Duration::from_secs(1),
            ))
            .expect("should resolve future successfully");
    }

    #[test]
    fn deposit_log() {
        let deposit_contract =
            DepositContract::deploy(ENDPOINT).expect("should deploy deposit contract");

        // Ensure we start with no logs
        let logs = blocking_deposit_logs(&deposit_contract, 0..blocking_block_number());
        assert_eq!(logs.len(), 0);

        for i in 1..=3 {
            // Add a deposit
            deposit_contract
                .deposit(random_deposit_data())
                .expect("should perform a deposit");

            // Ensure a log has been added each time
            let logs = blocking_deposit_logs(&deposit_contract, 0..blocking_block_number());
            assert_eq!(logs.len(), i);
        }
    }
}
