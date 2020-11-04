use crate::Context;
use beacon_chain::BeaconChainTypes;
use eth2::lighthouse::BeaconHealth;
use lighthouse_metrics::{Encoder, TextEncoder};

pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref PROCESS_RES_MEM: Result<IntGauge> = try_create_int_gauge(
        "process_resident_memory_bytes",
        "Resident memory used by the current process"
    );
    pub static ref PROCESS_VIRT_MEM: Result<IntGauge> = try_create_int_gauge(
        "process_virtual_memory_bytes",
        "Virtual memory used by the current process"
    );
    pub static ref SYSTEM_VIRT_MEM_TOTAL: Result<IntGauge> =
        try_create_int_gauge("system_virt_mem_total_bytes", "Total system virtual memory");
    pub static ref SYSTEM_VIRT_MEM_AVAILABLE: Result<IntGauge> = try_create_int_gauge(
        "system_virt_mem_available_bytes",
        "Available system virtual memory"
    );
    pub static ref SYSTEM_VIRT_MEM_USED: Result<IntGauge> =
        try_create_int_gauge("system_virt_mem_used_bytes", "Used system virtual memory");
    pub static ref SYSTEM_VIRT_MEM_FREE: Result<IntGauge> =
        try_create_int_gauge("system_virt_mem_free_bytes", "Free system virtual memory");
    pub static ref SYSTEM_VIRT_MEM_PERCENTAGE: Result<Gauge> = try_create_float_gauge(
        "system_virt_mem_percentage",
        "Percentage of used virtual memory"
    );
    pub static ref SYSTEM_LOADAVG_1: Result<Gauge> =
        try_create_float_gauge("system_loadavg_1", "Loadavg over 1 minute");
    pub static ref SYSTEM_LOADAVG_5: Result<Gauge> =
        try_create_float_gauge("system_loadavg_5", "Loadavg over 5 minutes");
    pub static ref SYSTEM_LOADAVG_15: Result<Gauge> =
        try_create_float_gauge("system_loadavg_15", "Loadavg over 15 minutes");
    pub static ref SYSTEM_RX_BYTES: Result<IntGauge> = try_create_int_gauge(
        "rx_bytes",
        "Total bytes received across all network interfaces."
    );
    pub static ref SYSTEM_RX_ERRORS: Result<IntGauge> = try_create_int_gauge(
        "rx_errors",
        "Total errors received across all network interfaces."
    );
    pub static ref SYSTEM_RX_PACKETS: Result<IntGauge> = try_create_int_gauge(
        "rx_packets",
        "Total packets received across all network interfaces."
    );
    pub static ref SYSTEM_TX_BYTES: Result<IntGauge> = try_create_int_gauge(
        "tx_bytes",
        "Total bytes transmitted across all network interfaces."
    );
    pub static ref SYSTEM_TX_ERRORS: Result<IntGauge> = try_create_int_gauge(
        "tx_errors",
        "Total errors transmitted across all network interfaces."
    );
    pub static ref SYSTEM_TX_PACKETS: Result<IntGauge> = try_create_int_gauge(
        "tx_packets",
        "Total packets transmitted across all network interfaces."
    );
}

pub fn gather_prometheus_metrics<T: BeaconChainTypes>(
    ctx: &Context<T>,
) -> std::result::Result<String, String> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();

    // There are two categories of metrics:
    //
    // - Dynamically updated: things like histograms and event counters that are updated on the
    // fly.
    // - Statically updated: things which are only updated at the time of the scrape (used where we
    // can avoid cluttering up code with metrics calls).
    //
    // The `lighthouse_metrics` crate has a `DEFAULT_REGISTRY` global singleton (via `lazy_static`)
    // which keeps the state of all the metrics. Dynamically updated things will already be
    // up-to-date in the registry (because they update themselves) however statically updated
    // things need to be "scraped".
    //
    // We proceed by, first updating all the static metrics using `scrape_for_metrics(..)`. Then,
    // using `lighthouse_metrics::gather(..)` to collect the global `DEFAULT_REGISTRY` metrics into
    // a string that can be returned via HTTP.

    if let Some(beacon_chain) = ctx.chain.as_ref() {
        slot_clock::scrape_for_metrics::<T::EthSpec, T::SlotClock>(&beacon_chain.slot_clock);
        beacon_chain::scrape_for_metrics(beacon_chain);
    }

    if let Some(db_paths) = ctx.db_paths.as_ref() {
        store::scrape_for_metrics(&db_paths.chain_db, &db_paths.freezer_db);

        // This will silently fail if we are unable to observe the health. This is desired behaviour
        // since we don't support `BeaconHealth` for all platforms.
        if let Ok(health) = BeaconHealth::observe(db_paths, None, None) {
            set_gauge(
                &PROCESS_RES_MEM,
                health.common.pid_mem_resident_set_size as i64,
            );
            set_gauge(
                &PROCESS_VIRT_MEM,
                health.common.pid_mem_virtual_memory_size as i64,
            );
            set_gauge(
                &SYSTEM_VIRT_MEM_TOTAL,
                health.common.sys_virt_mem_total as i64,
            );
            set_gauge(
                &SYSTEM_VIRT_MEM_AVAILABLE,
                health.common.sys_virt_mem_available as i64,
            );
            set_gauge(
                &SYSTEM_VIRT_MEM_USED,
                health.common.sys_virt_mem_used as i64,
            );
            set_gauge(
                &SYSTEM_VIRT_MEM_FREE,
                health.common.sys_virt_mem_free as i64,
            );
            set_float_gauge(
                &SYSTEM_VIRT_MEM_PERCENTAGE,
                health.common.sys_virt_mem_percent as f64,
            );
            set_float_gauge(&SYSTEM_LOADAVG_1, health.common.sys_loadavg_1);
            set_float_gauge(&SYSTEM_LOADAVG_5, health.common.sys_loadavg_5);
            set_float_gauge(&SYSTEM_LOADAVG_15, health.common.sys_loadavg_15);
            set_gauge(&SYSTEM_RX_BYTES, health.network.rx_bytes as i64);
            set_gauge(&SYSTEM_RX_ERRORS, health.network.rx_errors as i64);
            set_gauge(&SYSTEM_RX_PACKETS, health.network.rx_packets as i64);
            set_gauge(&SYSTEM_TX_BYTES, health.network.tx_bytes as i64);
            set_gauge(&SYSTEM_TX_ERRORS, health.network.tx_errors as i64);
            set_gauge(&SYSTEM_TX_PACKETS, health.network.tx_packets as i64);
        }
    }

    eth2_libp2p::scrape_discovery_metrics();

    encoder
        .encode(&lighthouse_metrics::gather(), &mut buffer)
        .unwrap();

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}
