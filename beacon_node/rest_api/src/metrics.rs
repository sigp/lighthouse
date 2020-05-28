use crate::response_builder::ResponseBuilder;
use crate::{ApiError, ApiResult};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use lighthouse_metrics::{Encoder, TextEncoder};
use rest_types::Health;
use std::path::PathBuf;
use std::sync::Arc;

pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref REQUEST_RESPONSE_TIME: Result<Histogram> = try_create_histogram(
        "http_server_request_duration_seconds",
        "Time taken to build a response to a HTTP request"
    );
    pub static ref REQUEST_COUNT: Result<IntCounter> = try_create_int_counter(
        "http_server_request_total",
        "Total count of HTTP requests received"
    );
    pub static ref SUCCESS_COUNT: Result<IntCounter> = try_create_int_counter(
        "http_server_success_total",
        "Total count of HTTP 200 responses sent"
    );
    pub static ref VALIDATOR_GET_BLOCK_REQUEST_RESPONSE_TIME: Result<Histogram> =
        try_create_histogram(
            "http_server_validator_block_get_request_duration_seconds",
            "Time taken to respond to GET /validator/block"
        );
    pub static ref VALIDATOR_GET_ATTESTATION_REQUEST_RESPONSE_TIME: Result<Histogram> =
        try_create_histogram(
            "http_server_validator_attestation_get_request_duration_seconds",
            "Time taken to respond to GET /validator/attestation"
        );
    pub static ref VALIDATOR_GET_DUTIES_REQUEST_RESPONSE_TIME: Result<Histogram> =
        try_create_histogram(
            "http_server_validator_duties_get_request_duration_seconds",
            "Time taken to respond to GET /validator/duties"
        );
    pub static ref PROCESS_NUM_THREADS: Result<IntGauge> = try_create_int_gauge(
        "process_num_threads",
        "Number of threads used by the current process"
    );
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
}

/// Returns the full set of Prometheus metrics for the Beacon Node application.
///
/// # Note
///
/// This is a HTTP handler method.
pub fn get_prometheus<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    db_path: PathBuf,
    freezer_db_path: PathBuf,
) -> ApiResult {
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

    slot_clock::scrape_for_metrics::<T::EthSpec, T::SlotClock>(&beacon_chain.slot_clock);
    store::scrape_for_metrics(&db_path, &freezer_db_path);
    beacon_chain::scrape_for_metrics(&beacon_chain);

    if let Ok(health) = Health::observe() {
        set_gauge(&PROCESS_NUM_THREADS, health.pid_num_threads as i64);
        set_gauge(&PROCESS_RES_MEM, health.pid_mem_resident_set_size as i64);
        set_gauge(&PROCESS_VIRT_MEM, health.pid_mem_virtual_memory_size as i64);
        set_gauge(&SYSTEM_VIRT_MEM_TOTAL, health.sys_virt_mem_total as i64);
        set_gauge(
            &SYSTEM_VIRT_MEM_AVAILABLE,
            health.sys_virt_mem_available as i64,
        );
        set_gauge(&SYSTEM_VIRT_MEM_USED, health.sys_virt_mem_used as i64);
        set_gauge(&SYSTEM_VIRT_MEM_FREE, health.sys_virt_mem_free as i64);
        set_float_gauge(
            &SYSTEM_VIRT_MEM_PERCENTAGE,
            health.sys_virt_mem_percent as f64,
        );
        set_float_gauge(&SYSTEM_LOADAVG_1, health.sys_loadavg_1);
        set_float_gauge(&SYSTEM_LOADAVG_5, health.sys_loadavg_5);
        set_float_gauge(&SYSTEM_LOADAVG_15, health.sys_loadavg_15);
    }

    encoder
        .encode(&lighthouse_metrics::gather(), &mut buffer)
        .unwrap();

    String::from_utf8(buffer)
        .map(|string| ResponseBuilder::new(&req)?.body_text(string))
        .map_err(|e| ApiError::ServerError(format!("Failed to encode prometheus info: {:?}", e)))?
}
