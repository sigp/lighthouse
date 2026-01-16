//! Validator configuration parsing and management

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tracing::info;

/// ENR fields for node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrFields {
    /// IP address for the node
    pub ip: Option<String>,
    /// QUIC port
    pub quic: Option<u16>,
    /// UDP port
    pub udp: Option<u16>,
    /// TCP port
    pub tcp: Option<u16>,
}

/// Validator configuration entry for a single node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEntry {
    /// Node name identifier
    pub name: String,
    /// Number of validators for this node
    pub count: u64,
    /// Private key in hex format (for node identity)
    #[serde(default)]
    pub privkey: String,
    /// ENR fields for peer discovery
    #[serde(default, rename = "enrFields")]
    pub enr_fields: Option<EnrFields>,
    /// Metrics port for this node
    #[serde(default, rename = "metricsPort")]
    pub metrics_port: Option<u16>,
}

/// Configuration section of validator-config.yaml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfigSection {
    /// Log2 of the number of active epochs (e.g., 24 means 2^24 active epochs)
    #[serde(default, rename = "activeEpoch")]
    pub active_epoch: Option<u64>,
    /// Key type (e.g., "hash-sig")
    #[serde(default, rename = "keyType")]
    pub key_type: Option<String>,
}

/// Validator configuration structure matching lean-quickstart format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// List of validator entries, one per node
    pub validators: Vec<ValidatorEntry>,
    /// Configuration section
    #[serde(default)]
    pub config: Option<ValidatorConfigSection>,
    /// Shuffle algorithm (optional, can be at top level)
    #[serde(default)]
    pub shuffle: Option<String>,
}

impl ValidatorConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        info!(path = ?path, "Loading validator configuration");

        let yaml_content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read validator configuration: {}", e))?;

        // Try parsing as complex format first
        if let Ok(config) = serde_yaml::from_str::<ValidatorConfig>(&yaml_content) {
            return Ok(config);
        }

        // Try parsing as simple format (node_name -> validator_indices)
        let node_map: BTreeMap<String, Vec<u64>> = serde_yaml::from_str(&yaml_content)
            .map_err(|e| format!("Failed to parse validator configuration as both complex and simple formats: {}", e))?;

        // Convert simple format to ValidatorConfig
        let validators = node_map
            .into_iter()
            .map(|(name, indices)| {
                let count = indices.len() as u64;
                ValidatorEntry {
                    name,
                    count,
                    privkey: String::new(),
                    enr_fields: None,
                    metrics_port: None,
                }
            })
            .collect();

        Ok(ValidatorConfig {
            validators,
            config: None,
            shuffle: None,
        })
    }

    /// Saves validator configuration to a YAML file
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        info!(path = ?path, "Saving validator configuration");

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create validator config directory: {}", e))?;
        }

        let yaml_content = serde_yaml::to_string(self)
            .map_err(|e| format!("Failed to serialize validator config to YAML: {}", e))?;

        fs::write(path, yaml_content)
            .map_err(|e| format!("Failed to write validator-config.yaml: {}", e))?;

        Ok(())
    }

    /// Calculates the total number of validators across all nodes
    pub fn total_validator_count(&self) -> u64 {
        self.validators.iter().map(|v| v.count).sum()
    }

    /// Generates validator index assignments per node
    ///
    /// Returns a map from node name to (start_index, end_index) range
    pub fn validator_assignments(&self) -> std::collections::HashMap<String, (u64, u64)> {
        let mut assignments = std::collections::HashMap::new();
        let mut current_index = 0u64;

        for entry in &self.validators {
            let start_index = current_index;
            let end_index = current_index + entry.count;
            assignments.insert(entry.name.clone(), (start_index, end_index));
            current_index = end_index;
        }

        assignments
    }
}
