pub mod config;
pub mod process;
pub mod testnet;

const DEFAULT_CONFIG: &str = include_str!("../default.toml");
const DEFAULT_KEY: &str = "default";
const GANACHE_CMD: &str = "ganache-cli";
const LCLI_CMD: &str = "lcli";
const BEACON_CMD: &str = "beacon";
const VALIDATOR_CMD: &str = "validator";
const BOOT_NODE_CMD: &str = "boot_node";
