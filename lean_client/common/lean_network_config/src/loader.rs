use crate::bootstrap::load_bootstrap_nodes;
use std::fs;
use std::path::Path;
use tracing::info;

/// Configuration information extracted from network files
#[derive(Clone, Debug)]
pub struct ConfigInfo {
    /// Raw configuration YAML bytes
    pub config_bytes: Vec<u8>,
    /// ENR records from bootstrap_nodes.yaml as raw strings
    pub bootstrap_enrs: Vec<String>,
}

/// Load network configuration and bootstrap nodes
///
/// # Arguments
/// * `config_path` - Path to config.yaml
/// * `nodes_path` - Path to bootstrap_nodes.yaml
///
/// # Returns
/// ConfigInfo containing raw configuration bytes and ENR strings
pub fn load_network_files<P: AsRef<Path>>(
    config_path: P,
    nodes_path: P,
) -> Result<ConfigInfo, String> {
    let config_path = config_path.as_ref();
    let nodes_path = nodes_path.as_ref();

    // Load config.yaml
    let config_bytes = fs::read(config_path)
        .map_err(|e| format!("Failed to read config from {:?}: {}", config_path, e))?;

    // Load bootstrap nodes ENRs
    let bootstrap_enrs = load_bootstrap_nodes(nodes_path)?;

    info!(
        config_path = ?config_path,
        bootstrap_nodes_count = bootstrap_enrs.len(),
        "Loaded network configuration files"
    );

    Ok(ConfigInfo {
        config_bytes,
        bootstrap_enrs,
    })
}
