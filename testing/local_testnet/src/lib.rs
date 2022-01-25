pub mod config;
pub mod process;
pub mod testnet;

const GANACHE_CMD: &str = "ganache-cli";
const LCLI_CMD: &str = "lcli";
const BEACON_CMD: &str = "beacon";
const VALIDATOR_CMD: &str = "validator";
const BOOT_NODE_CMD: &str = "boot_node";
const DEFAULT_CONFIG_PATH: &str = "./default.toml";
