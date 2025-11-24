use crate::genesis::GenesisStateBytes;
use std::fs;
use std::path::Path;
use tracing::{debug, info};

/// Raw configuration bytes for a network
#[derive(Clone, Debug)]
pub struct NetworkConfigBytes {
    /// Config YAML file contents as raw bytes
    pub config: Vec<u8>,
    /// Bootstrap nodes YAML file contents as raw bytes
    pub bootstrap_nodes: Option<Vec<u8>>,
}

impl NetworkConfigBytes {
    /// Load network configuration from a directory
    pub fn load_from_dir<P: AsRef<Path>>(dir: P) -> Result<Self, String> {
        let dir_path = dir.as_ref();
        debug!("Loading network configuration from {:?}", dir_path);

        // Load config.yaml
        let config_path = dir_path.join("config.yaml");
        let config = fs::read(&config_path)
            .map_err(|e| format!("Failed to read config.yaml from {:?}: {}", config_path, e))?;

        // Try to load bootstrap_nodes.yaml (optional)
        let bootstrap_nodes_path = dir_path.join("bootstrap_nodes.yaml");
        let bootstrap_nodes = if bootstrap_nodes_path.exists() {
            Some(fs::read(&bootstrap_nodes_path).map_err(|e| {
                format!(
                    "Failed to read bootstrap_nodes.yaml from {:?}: {}",
                    bootstrap_nodes_path, e
                )
            })?)
        } else {
            None
        };

        info!("Loaded network config from {:?}", dir_path);

        Ok(NetworkConfigBytes {
            config,
            bootstrap_nodes,
        })
    }
}

/// Specifies a lean network configuration
#[derive(Clone, Debug)]
pub struct LeanNetworkConfig {
    /// Network name (e.g., "mainnet", "holesky", "testnet")
    pub name: String,
    /// Raw configuration bytes
    pub config_bytes: NetworkConfigBytes,
    /// Genesis state bytes
    pub genesis_state_bytes: Option<GenesisStateBytes>,
}

impl LeanNetworkConfig {
    /// Create a new network configuration
    pub fn new(
        name: String,
        config_bytes: NetworkConfigBytes,
        genesis_state_bytes: Option<GenesisStateBytes>,
    ) -> Self {
        Self {
            name,
            config_bytes,
            genesis_state_bytes,
        }
    }

    /// Load network configuration from a directory
    pub fn load_from_dir<P: AsRef<Path>>(name: String, dir: P) -> Result<Self, String> {
        let dir_path = dir.as_ref();
        debug!("Loading network '{}' from {:?}", name, dir_path);

        let config_bytes = NetworkConfigBytes::load_from_dir(dir_path)?;

        // Try to load genesis state
        let genesis_path = dir_path.join("genesis.ssz");
        let genesis_state_bytes = if genesis_path.exists() {
            let bytes = fs::read(&genesis_path).map_err(|e| {
                format!("Failed to read genesis.ssz from {:?}: {}", genesis_path, e)
            })?;
            Some(GenesisStateBytes::Vec(bytes))
        } else {
            None
        };

        Ok(Self {
            name,
            config_bytes,
            genesis_state_bytes,
        })
    }

    /// Get the config YAML as bytes
    pub fn config_bytes(&self) -> &[u8] {
        &self.config_bytes.config
    }

    /// Get the bootstrap nodes YAML as bytes (if available)
    pub fn bootstrap_nodes_bytes(&self) -> Option<&[u8]> {
        self.config_bytes.bootstrap_nodes.as_deref()
    }

    /// Get the genesis state as bytes (if available)
    pub fn genesis_state_bytes(&self) -> Option<&[u8]> {
        self.genesis_state_bytes.as_ref().map(|gs| gs.as_ref())
    }
}
