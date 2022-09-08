use ethers_core::utils::{Anvil, AnvilInstance};
use ethers_providers::{Http, Middleware, Provider};
use serde_json::json;
use std::convert::TryFrom;
use unused_port::unused_tcp_port;

/// How long we will wait for ganache to indicate that it is ready.
// const GANACHE_STARTUP_TIMEOUT_MILLIS: u64 = 10_000;

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
    pub fn new(chain_id: u64) -> Result<Self, String> {
        let port = unused_tcp_port()?;

        let anvil = Anvil::new()
            .port(port)
            .mnemonic("vast thought differ pull jewel broom cook wrist tribe word before omit")
            .arg("--defaultBalanceEther")
            .arg("1000000000")
            .arg("--gasLimit")
            .arg("1000000000")
            .arg("--accounts")
            .arg("10")
            .arg("--chain.chainId")
            .arg(format!("{}", chain_id))
            .spawn();

        // let start = Instant::now();
        // let mut reader = BufReader::new(stdout);
        // loop {
        //     if start + Duration::from_millis(GANACHE_STARTUP_TIMEOUT_MILLIS) <= Instant::now() {
        //         break Err(
        //             "Timed out waiting for ganache to start. Is ganache installed?".to_string(),
        //         );
        //     }

        //     let mut line = String::new();
        //     if let Err(e) = reader.read_line(&mut line) {
        //         break Err(format!("Failed to read line from ganache process: {:?}", e));
        //     } else if line.starts_with("RPC Listening on") {
        //         break Ok(());
        //     } else {
        //         continue;
        //     }
        // }?;
        let client = Provider::<Http>::try_from(&endpoint(port))
            .map_err(|e| format!("Failed to start HTTP transport connected to anvil: {:?}", e))?;
        Ok(Self {
            port,
            anvil,
            client,
            chain_id,
        })
    }

    // pub fn fork(&self) -> Result<Self, String> {
    //     let port = unused_tcp_port()?;
    //     let binary = match cfg!(windows) {
    //         true => "ganache.cmd",
    //         false => "ganache",
    //     };
    //     let child = Command::new(binary)
    //         .stdout(Stdio::piped())
    //         .arg("--fork")
    //         .arg(self.endpoint())
    //         .arg("--port")
    //         .arg(format!("{}", port))
    //         .arg("--chain.chainId")
    //         .arg(format!("{}", self.chain_id))
    //         .spawn()
    //         .map_err(|e| {
    //             format!(
    //                 "Failed to start {}. \
    //                 Is it installed and available on $PATH? Error: {:?}",
    //                 binary, e
    //             )
    //         })?;

    //     Self::new_from_child(child, port, self.chain_id)
    // }

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
        self.client
            .request("evm_increaseTime", vec![json!(increase_by)])
            .await
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
            .request("evm_mine", Vec::<String>::new())
            .await
            .map(|_: String| ())
            .map_err(|_| {
                "utils should mine new block with evm_mine (only works with ganache!)".to_string()
            })
    }
}

fn endpoint(port: u16) -> String {
    format!("http://localhost:{}", port)
}

// impl Drop for Anvil {
//     fn drop(&mut self) {
//         if cfg!(windows) {
//             // Calling child.kill() in Windows will only kill the process
//             // that spawned ganache, leaving the actual ganache process
//             // intact. You have to kill the whole process tree. What's more,
//             // if you don't spawn ganache with --keepAliveTimeout=0, Windows
//             // will STILL keep the server running even after you've ended
//             // the process tree and it's disappeared from the task manager.
//             // Unbelievable...
//             Command::new("taskkill")
//                 .arg("/pid")
//                 .arg(self.child.id().to_string())
//                 .arg("/T")
//                 .arg("/F")
//                 .output()
//                 .expect("failed to execute taskkill");
//         } else {
//             let _ = self.child.kill();
//         }
//     }
// }
