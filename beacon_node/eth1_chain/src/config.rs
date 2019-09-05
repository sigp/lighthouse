use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Endpoint to Eth1 node's rpc.
    pub endpoint: String,
    /// Path to deposit contract ABI.
    pub abi_path: PathBuf,
    /// Deposit contract address.
    pub address: String,
}

impl Default for Config {
    // Local testnet default config from
    // https://github.com/ChainSafe/lodestar#starting-private-eth1-chain
    fn default() -> Self {
        Config {
            endpoint: "ws://localhost:8545".into(),
            abi_path: PathBuf::from("deposit_contract.json"), // TODO: Should be some better default.
            address: "8c594691C0E592FFA21F153a16aE41db5beFcaaa".into(),
        }
    }
}
