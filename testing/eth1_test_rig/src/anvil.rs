use ethers_core::utils::{Anvil, AnvilInstance};
use ethers_providers::{Http, Middleware, Provider};
use serde_json::json;
use std::convert::TryFrom;
use unused_port::unused_tcp4_port;

/// Provides a dedicated `anvil` instance.
///
/// Requires that `anvil` is installed and available on `PATH`.
pub struct AnvilCliInstance {
    pub port: u16,
    pub anvil: AnvilInstance,
    pub client: Provider<Http>,
    chain_id: u64,
}

impl AnvilCliInstance {
    fn new_from_child(anvil_instance: Anvil, chain_id: u64, port: u16) -> Result<Self, String> {
        let client = Provider::<Http>::try_from(&endpoint(port))
            .map_err(|e| format!("Failed to start HTTP transport connected to anvil: {:?}", e))?;
        Ok(Self {
            port,
            anvil: anvil_instance.spawn(),
            client,
            chain_id,
        })
    }
    pub fn new(chain_id: u64) -> Result<Self, String> {
        let port = unused_tcp4_port()?;

        let anvil = Anvil::new()
            .port(port)
            .mnemonic("vast thought differ pull jewel broom cook wrist tribe word before omit")
            .arg("--balance")
            .arg("1000000000")
            .arg("--gas-limit")
            .arg("1000000000")
            .arg("--accounts")
            .arg("10")
            .arg("--chain-id")
            .arg(format!("{}", chain_id));

        Self::new_from_child(anvil, chain_id, port)
    }

    pub fn fork(&self) -> Result<Self, String> {
        let port = unused_tcp4_port()?;

        let anvil = Anvil::new()
            .port(port)
            .arg("--chain-id")
            .arg(format!("{}", self.chain_id()))
            .fork(self.endpoint());

        Self::new_from_child(anvil, self.chain_id, port)
    }

    /// Returns the endpoint that this instance is listening on.
    pub fn endpoint(&self) -> String {
        endpoint(self.port)
    }

    /// Returns the chain id of the anvil instance
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Increase the timestamp on future blocks by `increase_by` seconds.
    pub async fn increase_time(&self, increase_by: u64) -> Result<(), String> {
        self.client
            .request("evm_increaseTime", vec![json!(increase_by)])
            .await
            .map(|_json_value: u64| ())
            .map_err(|e| format!("Failed to increase time on EVM (is this anvil?): {:?}", e))
    }

    /// Returns the current block number, as u64
    pub async fn block_number(&self) -> Result<u64, String> {
        self.client
            .get_block_number()
            .await
            .map(|v| v.as_u64())
            .map_err(|e| format!("Failed to get block number: {:?}", e))
    }

    /// Mines a single block.
    pub async fn evm_mine(&self) -> Result<(), String> {
        self.client
            .request("evm_mine", ())
            .await
            .map(|_: String| ())
            .map_err(|_| {
                "utils should mine new block with evm_mine (only works with anvil/ganache!)"
                    .to_string()
            })
    }
}

fn endpoint(port: u16) -> String {
    format!("http://127.0.0.1:{}", port)
}
