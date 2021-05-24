use std::time::{SystemTime, UNIX_EPOCH};

use eth2::lighthouse::{ProcessHealth, SystemHealth};
use serde_derive::{Deserialize, Serialize};

pub const VERSION: u64 = 1;
pub const CLIENT_NAME: &str = "lighthouse";

/// An API error serializable to JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: u16,
    pub message: String,
    #[serde(default)]
    pub stacktraces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitoringMetrics {
    #[serde(flatten)]
    pub metadata: Metadata,
    #[serde(flatten)]
    pub process_metrics: Process,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessType {
    BeaconNode,
    Validator,
    System,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    version: u64,
    timestamp: u128,
    process: ProcessType,
}

impl Metadata {
    pub fn new(process: ProcessType) -> Self {
        Self {
            version: VERSION,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be greater than unix epoch")
                .as_millis(),
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
    memory_process_bytes: u64,

    client_name: String,
    client_version: String,
    client_build: u64,
}

impl From<ProcessHealth> for ProcessMetrics {
    fn from(health: ProcessHealth) -> Self {
        Self {
            cpu_process_seconds_total: health.pid_process_seconds_total,
            memory_process_bytes: health.pid_mem_resident_set_size,
            client_name: CLIENT_NAME.to_string(),
            client_version: client_version().unwrap_or_default(),
            client_build: client_build(),
        }
    }
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
        // Export format uses 3 letter os names
        let misc_os = health.misc_os.get(0..3).unwrap_or("unk").to_string();
        Self {
            cpu_cores: health.cpu_cores,
            cpu_threads: health.cpu_threads,
            cpu_node_system_seconds_total: health.cpu_time_total,
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
            misc_os,
        }
    }
}

/// All beacon process metrics.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconProcessMetrics {
    #[serde(flatten)]
    pub common: ProcessMetrics,
    #[serde(flatten)]
    pub beacon: serde_json::Value,
}

/// All validator process metrics
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorProcessMetrics {
    #[serde(flatten)]
    pub common: ProcessMetrics,
    #[serde(flatten)]
    pub validator: serde_json::Value,
}

/// Returns the client version
fn client_version() -> Option<String> {
    let re = regex::Regex::new(r"\d+\.\d+\.\d+").expect("Regex is valid");
    re.find(lighthouse_version::VERSION)
        .map(|m| m.as_str().to_string())
}

/// Returns the client build
/// Note: Lighthouse does not support build numbers, this is effectively a null-value.
fn client_build() -> u64 {
    0
}
