use crate::config::IntegrationTestConfig;
use std::fs;

pub mod config;
pub mod process;
pub mod testnet;

const GANACHE_CMD: &str = "ganache-cli";
const LCLI_CMD: &str = "lcli";
const BEACON_CMD: &str = "beacon";
const VALIDATOR_CMD: &str = "validator";
const BOOT_NODE_CMD: &str = "boot_node";
const DEFAULT_CONFIG_PATH: &str = "./default.toml";

fn parse_file_config_maps(file_name: &str) -> Result<IntegrationTestConfig, String> {
    if file_name.ends_with(".toml") {
        fs::read_to_string(file_name)
            .map_err(|e| e.to_string())
            .and_then(|toml| toml::from_str(toml.as_str()).map_err(|e| e.to_string()))
    } else {
        Err("config file must have extension `.toml`".to_string())
    }
}
