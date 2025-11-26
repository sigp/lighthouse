use crate::cli::LeanNode;
use lean_config::LeanClientPaths;
use std::path::PathBuf;

/// Runtime configuration derived from CLI arguments for the lean client.
#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
    pub validators_path: PathBuf,
    pub nodes_path: PathBuf,
    pub node_id: String,
    pub private_key: PathBuf,
    pub socket_port: u16,
    pub genesis_json_path: Option<PathBuf>,
    pub enable_metrics: bool,
}

impl Config {
    /// Build the runtime configuration from CLI inputs and resolved data directory.
    pub fn from_cli(cli: LeanNode, data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            config_path: cli.config,
            validators_path: cli.validators,
            nodes_path: cli.nodes,
            node_id: cli.node_id,
            private_key: cli.private_key,
            socket_port: cli.socket_port,
            genesis_json_path: cli.genesis_json,
            enable_metrics: cli.metrics,
        }
    }
}

impl From<Config> for LeanClientPaths {
    fn from(value: Config) -> Self {
        LeanClientPaths {
            data_dir: value.data_dir,
            config_path: value.config_path,
            validators_path: value.validators_path,
            nodes_path: value.nodes_path,
            node_id: value.node_id,
            node_key_path: value.private_key,
            genesis_json_path: value.genesis_json_path,
        }
    }
}
