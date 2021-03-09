use std::time::{SystemTime, UNIX_EPOCH};

use eth2::lighthouse::SystemHealth;
use lighthouse_version::VERSION_NUMBER;
use serde_derive::{Deserialize, Serialize};

pub const VERSION: u64 = 1;

/// An API error serializable to JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: u16,
    pub message: String,
    #[serde(default)]
    pub stacktraces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplorerMetrics {
    #[serde(flatten)]
    pub metadata: Metadata,
    #[serde(flatten)]
    pub process_metrics: Process,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessType {
    Beacon,
    Validator,
    System,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    version: u64,
    timestamp: u64,
    process: ProcessType,
}

impl Metadata {
    pub fn new(process: ProcessType) -> Self {
        Self {
            version: VERSION,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be greater than unix epoch")
                .as_secs(),
            process,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Process {
    Beacon(BeaconProcessMetrics),
    System(SystemMetrics),
    Validator(ValidatorProcessMetrics),
}

/// Common metrics for all processes.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessMetrics {
    cpu_process_seconds_total: u64,
    // alias doesn't work with flattened structs
    // https://github.com/serde-rs/serde/issues/1504
    // TODO: use some alternative
    #[serde(rename = "process_virtual_memory_bytes")]
    memory_process_bytes: u64,

    #[serde(default = "client_name")]
    client_name: String,
    #[serde(default = "client_version")]
    client_version: String,
    #[serde(default = "client_build")]
    client_build: u64,
}

/// Metrics related to the system.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemMetrics {
    cpu_cores: u64,
    cpu_threads: u64,
    cpu_node_system_seconds_total: u64,
    cpu_node_user_seconds_total: u64,
    cpu_node_iowait_seconds_total: u64,
    cpu_node_idle_seconds_total: u64,

    memory_node_bytes_total: u64,
    memory_node_bytes_free: u64,
    memory_node_bytes_cached: u64,
    memory_node_bytes_buffers: u64,

    disk_node_bytes_total: u64,
    disk_node_bytes_free: u64,

    disk_node_io_seconds: u64,
    disk_node_reads_total: u64,
    disk_node_writes_total: u64,

    network_node_bytes_total_receive: u64,
    network_node_bytes_total_transmit: u64,

    misc_node_boot_ts_seconds: u64,
    misc_os: String,
}

impl From<SystemHealth> for SystemMetrics {
    fn from(health: SystemHealth) -> Self {
        Self {
            cpu_cores: health.cpu_cores,
            cpu_threads: health.cpu_threads,
            cpu_node_system_seconds_total: health.system_seconds_total,
            cpu_node_user_seconds_total: health.user_seconds_total,
            cpu_node_iowait_seconds_total: health.iowait_seconds_total,
            cpu_node_idle_seconds_total: health.idle_seconds_total,

            memory_node_bytes_total: health.sys_virt_mem_total,
            memory_node_bytes_free: health.sys_virt_mem_free,
            memory_node_bytes_cached: health.sys_virt_mem_cached,
            memory_node_bytes_buffers: health.sys_virt_mem_buffers,

            disk_node_bytes_total: health.disk_node_bytes_total,
            disk_node_bytes_free: health.disk_node_bytes_free,

            // Unavaliable for now
            disk_node_io_seconds: 0,
            disk_node_reads_total: health.disk_node_reads_total,
            disk_node_writes_total: health.disk_node_writes_total,

            network_node_bytes_total_receive: health.network_node_bytes_total_received,
            network_node_bytes_total_transmit: health.network_node_bytes_total_transmit,

            misc_node_boot_ts_seconds: health.misc_node_boot_ts_seconds,
            misc_os: health.misc_os,
        }
    }
}

/// Metrics specific to the beacon node.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconMetrics {
    #[serde(rename = "store_disk_db_size")]
    disk_beaconchain_bytes_total: u64,
    /*
    network_libp2p_bytes_total_receive: u64,
    network_libp2p_bytes_total_transmit: u64,
    */
    #[serde(rename = "libp2p_peer_connected_peers_total")]
    network_peers_connected: u64,

    #[serde(deserialize_with = "int_to_bool")]
    #[serde(default)]
    sync_eth1_connected: bool,
    #[serde(deserialize_with = "int_to_bool")]
    #[serde(default)]
    sync_eth2_synced: bool,
    #[serde(rename = "beacon_head_state_slot")]
    sync_beacon_head_slot: u64,
    #[serde(default)]
    #[serde(deserialize_with = "int_to_bool")]
    sync_eth1_fallback_configured: bool,
    /*
    sync_eth1_fallback_connected: bool,
    */
}

/// Metrics specific to validator client.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    #[serde(rename = "vc_validators_total_count")]
    validator_total: u64,
    #[serde(rename = "vc_validators_enabled_count")]
    validator_active: u64,

    #[serde(deserialize_with = "int_to_bool")]
    sync_eth2_fallback_configured: bool,
    /*
    sync_eth2_fallback_connected: bool,
    */
}

/// All beacon process metrics.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconProcessMetrics {
    #[serde(flatten)]
    pub common: ProcessMetrics,
    #[serde(flatten)]
    pub beacon: BeaconMetrics,
}

/// All validator process metrics
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorProcessMetrics {
    #[serde(flatten)]
    pub common: ProcessMetrics,
    #[serde(flatten)]
    pub validator: ValidatorMetrics,
}

/// Returns the client name string
fn client_name() -> String {
    "Lighthouse".to_string()
}

/// Returns the client version
fn client_version() -> String {
    VERSION_NUMBER.to_string()
}

/// Returns the client build
/// TODO: placeholder
fn client_build() -> u64 {
    42
}

fn int_to_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use serde::de::Deserialize;
    match u8::deserialize(deserializer)? {
        0 => Ok(false),
        _ => Ok(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let beacon_process = r#"
        {
            "beacon_head_state_slot": 615072,
            "cpu_process_seconds_total": 12,
            "libp2p_peer_connected_peers_total": 0,
            "process_virtual_memory_bytes": 2647228416,
            "store_disk_db_size": 5443346289,
            "sync_eth1_connected": 0,
            "sync_eth1_fallback_configured": 1
          }
        "#;

        let decoded: Result<BeaconProcessMetrics, _> = serde_json::from_str(beacon_process);
        assert!(decoded.is_ok());

        let validator_process = r#"
        {
            "cpu_process_seconds_total": 29,
            "process_virtual_memory_bytes": 1080483840,
            "sync_eth2_fallback_configured": 0,
            "vc_validators_enabled_count": 5,
            "vc_validators_total_count": 5
          }
        "#;

        let decoded: Result<ValidatorProcessMetrics, _> = serde_json::from_str(validator_process);
        assert!(decoded.is_ok());
    }
}
