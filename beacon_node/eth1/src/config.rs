use serde::{Deserialize, Serialize};

// Contract address generated from the default mnemonic in the test environment.
const DEFAULT_CONTRACT_ADDRESS: &str = "8c594691C0E592FFA21F153a16aE41db5beFcaaa";
const DEFAULT_SERVER_ADDRESS: &str = "wss://localhost:8545";

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Endpoint to Eth1 node's rpc.
    pub endpoint: String,
    /// Deposit contract address.
    pub address: String,
}

impl Default for Config {
    // Local testnet default config from
    // https://github.com/ChainSafe/lodestar#starting-private-eth1-chain
    fn default() -> Self {
        Config {
            endpoint: DEFAULT_SERVER_ADDRESS.into(),
            address: DEFAULT_CONTRACT_ADDRESS.into(),
        }
    }
}
