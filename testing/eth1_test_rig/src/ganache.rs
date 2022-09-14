use serde_json::json;
use std::io::prelude::*;
use std::io::BufReader;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use unused_port::unused_tcp_port;
use web3::{transports::Http, Transport, Web3};

/// How long we will wait for ganache to indicate that it is ready.
const GANACHE_STARTUP_TIMEOUT_MILLIS: u64 = 10_000;

/// Provides a dedicated `ganachi-cli` instance with a connected `Web3` instance.
///
/// Requires that `ganachi-cli` is installed and available on `PATH`.
pub struct GanacheInstance {
    pub port: u16,
    child: Child,
    pub web3: Web3<Http>,
    chain_id: u64,
}

impl GanacheInstance {
    fn new_from_child(mut child: Child, port: u16, chain_id: u64) -> Result<Self, String> {
        let stdout = child
            .stdout
            .ok_or("Unable to get stdout for ganache child process")?;

        let start = Instant::now();
        let mut reader = BufReader::new(stdout);
        loop {
            if start + Duration::from_millis(GANACHE_STARTUP_TIMEOUT_MILLIS) <= Instant::now() {
                break Err(
                    "Timed out waiting for ganache to start. Is ganache installed?".to_string(),
                );
            }

            let mut line = String::new();
            if let Err(e) = reader.read_line(&mut line) {
                break Err(format!("Failed to read line from ganache process: {:?}", e));
            } else if line.starts_with("RPC Listening on") {
                break Ok(());
            } else {
                continue;
            }
        }?;

        let transport = Http::new(&endpoint(port)).map_err(|e| {
            format!(
                "Failed to start HTTP transport connected to ganache: {:?}",
                e
            )
        })?;
        let web3 = Web3::new(transport);

        child.stdout = Some(reader.into_inner());

        Ok(Self {
            port,
            child,
            web3,
            chain_id,
        })
    }

    /// Start a new `ganache` process, waiting until it indicates that it is ready to accept
    /// RPC connections.
    pub fn new(chain_id: u64) -> Result<Self, String> {
        let port = unused_tcp_port()?;
        let binary = match cfg!(windows) {
            true => "ganache.cmd",
            false => "ganache",
        };
        let child = Command::new(binary)
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
            .arg("--chain.chainId")
            .arg(format!("{}", chain_id))
            .spawn()
            .map_err(|e| {
                format!(
                    "Failed to start {}. \
                    Is it installed and available on $PATH? Error: {:?}",
                    binary, e
                )
            })?;

        Self::new_from_child(child, port, chain_id)
    }

    pub fn fork(&self) -> Result<Self, String> {
        let port = unused_tcp_port()?;
        let binary = match cfg!(windows) {
            true => "ganache.cmd",
            false => "ganache",
        };
        let child = Command::new(binary)
            .stdout(Stdio::piped())
            .arg("--fork")
            .arg(self.endpoint())
            .arg("--port")
            .arg(format!("{}", port))
            .arg("--chain.chainId")
            .arg(format!("{}", self.chain_id))
            .spawn()
            .map_err(|e| {
                format!(
                    "Failed to start {}. \
                    Is it installed and available on $PATH? Error: {:?}",
                    binary, e
                )
            })?;

        Self::new_from_child(child, port, self.chain_id)
    }

    /// Returns the endpoint that this instance is listening on.
    pub fn endpoint(&self) -> String {
        endpoint(self.port)
    }

    /// Returns the chain id of the ganache instance
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Increase the timestamp on future blocks by `increase_by` seconds.
    pub async fn increase_time(&self, increase_by: u64) -> Result<(), String> {
        self.web3
            .transport()
            .execute("evm_increaseTime", vec![json!(increase_by)])
            .await
            .map(|_json_value| ())
            .map_err(|e| format!("Failed to increase time on EVM (is this ganache?): {:?}", e))
    }

    /// Returns the current block number, as u64
    pub async fn block_number(&self) -> Result<u64, String> {
        self.web3
            .eth()
            .block_number()
            .await
            .map(|v| v.as_u64())
            .map_err(|e| format!("Failed to get block number: {:?}", e))
    }

    /// Mines a single block.
    pub async fn evm_mine(&self) -> Result<(), String> {
        self.web3
            .transport()
            .execute("evm_mine", vec![])
            .await
            .map(|_| ())
            .map_err(|_| {
                "utils should mine new block with evm_mine (only works with ganache!)".to_string()
            })
    }
}

fn endpoint(port: u16) -> String {
    format!("http://127.0.0.1:{}", port)
}

impl Drop for GanacheInstance {
    fn drop(&mut self) {
        if cfg!(windows) {
            // Calling child.kill() in Windows will only kill the process
            // that spawned ganache, leaving the actual ganache process
            // intact. You have to kill the whole process tree. What's more,
            // if you don't spawn ganache with --keepAliveTimeout=0, Windows
            // will STILL keep the server running even after you've ended
            // the process tree and it's disappeared from the task manager.
            // Unbelievable...
            Command::new("taskkill")
                .arg("/pid")
                .arg(self.child.id().to_string())
                .arg("/T")
                .arg("/F")
                .output()
                .expect("failed to execute taskkill");
        } else {
            let _ = self.child.kill();
        }
    }
}
