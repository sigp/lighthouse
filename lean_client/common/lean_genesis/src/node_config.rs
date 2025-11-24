//! Node configuration utilities
//!
//! Note: ENR generation is handled by PK's eth-beacon-genesis tool.
//! This module provides utilities for reading nodes.yaml files.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::info;

/// Node entry in nodes.yaml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    /// Node name
    pub name: String,
    /// ENR (Ethereum Node Record) string
    pub enr: String,
    /// Node ID (derived from ENR)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

/// Nodes configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodesConfig {
    /// List of node entries
    pub nodes: Vec<NodeEntry>,
}

impl NodesConfig {
    /// Saves nodes configuration to a YAML file
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        info!(path = ?path, "Saving nodes.yaml");

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create nodes config directory: {}", e))?;
        }

        let yaml_content = serde_yaml::to_string(self)
            .map_err(|e| format!("Failed to serialize nodes config to YAML: {}", e))?;

        fs::write(path, yaml_content).map_err(|e| format!("Failed to write nodes.yaml: {}", e))?;

        Ok(())
    }
}
