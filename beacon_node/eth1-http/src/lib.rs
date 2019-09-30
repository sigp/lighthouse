use futures::{Future, IntoFuture, Stream};
use reqwest::{r#async::ClientBuilder, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::ops::Range;
use std::time::Duration;

#[derive(Deserialize)]
struct RpcResponse<T> {
    id: u64,
    jsonrpc: String,
    result: T,
}

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
        .and_then(|s| response_result_as_u64(&s))
        .map_err(|e| format!("Failed to get block number: {}", e))
}

pub fn get_logs_in_range(
    endpoint: &str,
    address: &str,
    // TODO: add filter for topic.
    block_height_range: Range<u64>,
    timeout: Duration,
) -> impl Future<Item = u64, Error = String> {
    let body = json! ({
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{
            "address": address,
            "fromBlock": block_height_range.start,
            "toBlock": block_height_range.end,
        }],
        "id": 1
    });

    send_rpc_request(endpoint, body.to_string(), timeout)
        .and_then(|s| response_result_as_u64(&s))
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

/// Accepts an entire HTTP body (as a string) and returns the `result` field, as a u64.
fn response_result_as_u64(response: &str) -> Result<u64, String> {
    let response: RpcResponse<String> = serde_json::from_str(&response)
        .map_err(|e| format!("Failed to parse response: {:?}", e))?;
    let result = &response.result;

    // Trim the 0x from the start, if it exists.
    let result = if result.starts_with("0x") {
        &result[2..]
    } else {
        result
    };

    u64::from_str_radix(result, 16).map_err(|e| format!("Failed to parse result as u64: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_number() {
        let mut runtime = tokio::runtime::Runtime::new().expect("should start runtime");

        runtime
            .block_on(get_block_number(
                "http://localhost:8545",
                Duration::from_secs(1),
            ))
            .expect("should resolve future successfully");
    }
}
