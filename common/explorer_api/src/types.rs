#[derive(Debug, Default, Clone, PartialEq)]
pub struct ExplorerMetrics {
    process_metrics: ProcessMetrics,
    system_metrics: SystemMetrics,
    beacon_metrics: BeaconMetrics,
    validator_metrics: ValidatorMetrics,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ProcessMetrics {
    cpu_process_seconds_total: u64,

    memory_process_bytes: u64,

    client_name: String,
    client_version: String,
    client_build: u64,

    sync_eth1_fallback_configured: bool,
    sync_eth1_fallback_connected: bool,
    sync_eth2_fallback_configured: bool,
    sync_eth2_fallback_connected: bool,
}
#[derive(Debug, Default, Clone, PartialEq)]
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

#[derive(Debug, Default, Clone, PartialEq)]
pub struct BeaconMetrics {
    disk_beaconchain_bytes_total: u64,

    network_libp2p_bytes_total_receive: u64,
    network_libp2p_bytes_total_transmit: u64,
    network_peers_connected: u64,

    sync_eth1_connected: bool,
    sync_eth2_synced: bool,
    sync_beacon_head_slot: u64,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ValidatorMetrics {
    validator_total: u64,
    validator_active: u64,
}
