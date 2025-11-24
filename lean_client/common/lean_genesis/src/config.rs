//! Configuration file utilities for genesis generation
//!
//! Provides utilities for reading and writing config.yaml files used with PK's eth-beacon-genesis tool.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::info;

/// Configuration structure matching PK's tool format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigYaml {
    #[serde(rename = "GENESIS_TIME")]
    pub genesis_time: u64,
    #[serde(rename = "VALIDATOR_COUNT")]
    pub validator_count: u64,
    pub shuffle: Option<String>,
    pub config: ConfigSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSection {
    #[serde(rename = "activeEpoch")]
    pub active_epoch: Option<u64>,
}

/// Loads a config.yaml file
pub fn load_config_yaml(config_path: &Path) -> Result<ConfigYaml, String> {
    let yaml_content = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config.yaml: {}", e))?;

    let config: ConfigYaml = serde_yaml::from_str(&yaml_content)
        .map_err(|e| format!("Failed to parse config.yaml: {}", e))?;

    Ok(config)
}

/// Saves a config.yaml file
pub fn save_config_yaml(config: &ConfigYaml, output_path: &Path) -> Result<(), String> {
    info!(path = ?output_path, "Saving config.yaml");

    // Create parent directories if needed
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    let yaml_content = serde_yaml::to_string(config)
        .map_err(|e| format!("Failed to serialize config to YAML: {}", e))?;

    fs::write(output_path, yaml_content)
        .map_err(|e| format!("Failed to write config.yaml: {}", e))?;

    info!(path = ?output_path, "Config.yaml saved successfully");
    Ok(())
}
