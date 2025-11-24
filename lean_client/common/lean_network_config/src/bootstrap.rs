use serde::Deserialize;
use std::fs;
use std::path::Path;
use tracing::{debug, error, warn};

/// Loads bootstrap nodes from a YAML file (raw bytes)
///
/// # Arguments
/// * `path` - Path to the bootstrap_nodes.yaml file
///
/// # Returns
/// A vector of raw ENR string bytes. Invalid entries are skipped with warnings.
pub fn load_bootstrap_nodes<P: AsRef<Path>>(path: P) -> Result<Vec<String>, String> {
    parse_bootstrap_nodes_yaml(
        &fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read bootstrap nodes file: {}", e))?,
    )
}

/// Parse bootstrap nodes from YAML content
///
/// # Arguments
/// * `content` - YAML file contents as a string
///
/// # Returns
/// A vector of ENR strings. Invalid entries are skipped with warnings.
pub fn parse_bootstrap_nodes_yaml(content: &str) -> Result<Vec<String>, String> {
    if content.trim().is_empty() {
        return Err("Bootstrap nodes YAML is empty".to_string());
    }

    debug!(
        "Parsing bootstrap nodes YAML, content length: {} bytes",
        content.len()
    );

    #[derive(Debug, Deserialize)]
    struct EnrRecord {
        enr: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum BootstrapEntry {
        Plain(String),
        Record(EnrRecord),
    }

    // Parse as YAML array of ENR strings or objects of the form `{ enr: "<value>" }`
    let enr_records: Vec<BootstrapEntry> = serde_yaml::from_str(content).map_err(|e| {
        format!(
            "Failed to parse bootstrap nodes YAML: {}. Content preview: {}",
            e,
            content.chars().take(200).collect::<String>()
        )
    })?;

    debug!(
        "Parsed {} ENR records from bootstrap nodes YAML",
        enr_records.len()
    );

    let mut valid_records = Vec::new();
    let mut empty_count = 0;

    for (i, entry) in enr_records.iter().enumerate() {
        let enr_str = match entry {
            BootstrapEntry::Plain(value) => value.trim(),
            BootstrapEntry::Record(record) => record.enr.trim(),
        };

        if enr_str.is_empty() {
            warn!("ENR record #{} is empty, skipping", i);
            empty_count += 1;
            continue;
        }

        // Basic validation: ENR records should start with "enr:"
        if !enr_str.starts_with("enr:") {
            warn!(
                "ENR record #{} does not start with 'enr:', skipping: {}",
                i, enr_str
            );
            continue;
        }

        valid_records.push(enr_str.to_string());
    }

    if valid_records.is_empty() {
        let error_msg = if empty_count == enr_records.len() {
            format!("All {} ENR records are empty", enr_records.len())
        } else {
            format!(
                "No valid ENR records found. Total: {}, Empty: {}",
                enr_records.len(),
                empty_count
            )
        };
        error!("No valid bootstrap nodes found. {}", error_msg);
        return Err(error_msg);
    }

    debug!(
        "Successfully parsed {} valid ENR records ({} invalid/empty)",
        valid_records.len(),
        enr_records.len() - valid_records.len()
    );

    Ok(valid_records)
}
