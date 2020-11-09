use futures::compat::Future01CompatExt;
use serde_json::json;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use web3::{
    transports::{EventLoopHandle, Http},
    Transport, Web3,
};

/// How long we will wait for ganache to indicate that it is ready.
const GANACHE_STARTUP_TIMEOUT_MILLIS: u64 = 10_000;

const NETWORK_ID: u64 = 42;
const CHAIN_ID: u64 = 42;

/// Provides a dedicated `ganachi-cli` instance with a connected `Web3` instance.
///
/// Requires that `ganachi-cli` is installed and available on `PATH`.
pub struct GanacheInstance {
    pub port: u16,
    child: Child,
    _event_loop: Arc<EventLoopHandle>,
    pub web3: Web3<Http>,
}

impl GanacheInstance {
    /// Start a new `ganache-cli` process, waiting until it indicates that it is ready to accept
    /// RPC connections.
    pub fn new() -> Result<Self, String> {
        let port = unused_port()?;

        let mut child = Command::new("ganache-cli")
            .stdout(Stdio::piped())
            .arg("--defaultBalanceEther")
            .arg("1000000000")
            .arg("--gasLimit")
            .arg("1000000000")
            .arg("--accounts")
            .arg("10")
            .arg("--port")
            .arg(format!("{}", port))
            .arg("--mnemonic")
            .arg("\"vast thought differ pull jewel broom cook wrist tribe word before omit\"")
            .arg("--networkId")
            .arg(format!("{}", NETWORK_ID))
            .arg("--chainId")
            .arg(format!("{}", CHAIN_ID))
            .spawn()
            .map_err(|e| {
                format!(
                    "Failed to start ganache-cli. \
                     Is it ganache-cli installed and available on $PATH? Error: {:?}",
                    e
                )
            })?;

        let stdout = child
            .stdout
            .ok_or_else(|| "Unable to get stdout for ganache child process")?;

        let start = Instant::now();
        let mut reader = BufReader::new(stdout);
        loop {
            if start + Duration::from_millis(GANACHE_STARTUP_TIMEOUT_MILLIS) <= Instant::now() {
                break Err(
                    "Timed out waiting for ganache to start. Is ganache-cli installed?".to_string(),
                );
            }

            let mut line = String::new();
            if let Err(e) = reader.read_line(&mut line) {
                break Err(format!("Failed to read line from ganache process: {:?}", e));
            } else if line.starts_with("Listening on") {
                break Ok(());
            } else {
                continue;
            }
        }?;

        let (event_loop, transport) = Http::new(&endpoint(port)).map_err(|e| {
            format!(
                "Failed to start HTTP transport connected to ganache: {:?}",
                e
            )
        })?;
        let web3 = Web3::new(transport);

        child.stdout = Some(reader.into_inner());

        Ok(Self {
            child,
            port,
            _event_loop: Arc::new(event_loop),
            web3,
        })
    }

    /// Returns the endpoint that this instance is listening on.
    pub fn endpoint(&self) -> String {
        endpoint(self.port)
    }

    /// Returns the network id of the ganache instance
    pub fn network_id(&self) -> u64 {
        NETWORK_ID
    }

    /// Returns the chain id of the ganache instance
    pub fn chain_id(&self) -> u64 {
        CHAIN_ID
    }

    /// Increase the timestamp on future blocks by `increase_by` seconds.
    pub async fn increase_time(&self, increase_by: u64) -> Result<(), String> {
        self.web3
            .transport()
            .execute("evm_increaseTime", vec![json!(increase_by)])
            .compat()
            .await
            .map(|_json_value| ())
            .map_err(|e| format!("Failed to increase time on EVM (is this ganache?): {:?}", e))
    }

    /// Returns the current block number, as u64
    pub async fn block_number(&self) -> Result<u64, String> {
        self.web3
            .eth()
            .block_number()
            .compat()
            .await
            .map(|v| v.as_u64())
            .map_err(|e| format!("Failed to get block number: {:?}", e))
    }

    /// Mines a single block.
    pub async fn evm_mine(&self) -> Result<(), String> {
        self.web3
            .transport()
            .execute("evm_mine", vec![])
            .compat()
            .await
            .map(|_| ())
            .map_err(|_| {
                "utils should mine new block with evm_mine (only works with ganache-cli!)"
                    .to_string()
            })
    }
}

fn endpoint(port: u16) -> String {
    format!("http://localhost:{}", port)
}

/// A bit of hack to find an unused TCP port.
///
/// Does not guarantee that the given port is unused after the function exists, just that it was
/// unused before the function started (i.e., it does not reserve a port).
pub fn unused_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Failed to create TCP listener to find unused port: {:?}", e))?;

    let local_addr = listener.local_addr().map_err(|e| {
        format!(
            "Failed to read TCP listener local_addr to find unused port: {:?}",
            e
        )
    })?;

    Ok(local_addr.port())
}

impl Drop for GanacheInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
