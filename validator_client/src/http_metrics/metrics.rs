use super::Context;
use std::time::{SystemTime, UNIX_EPOCH};
use types::EthSpec;

pub const SUCCESS: &str = "success";
pub const SLASHABLE: &str = "slashable";
pub const SAME_DATA: &str = "same_data";
pub const UNREGISTERED: &str = "unregistered";
pub const FULL_UPDATE: &str = "full_update";
pub const BEACON_BLOCK: &str = "beacon_block";
pub const ATTESTATIONS: &str = "attestations";
pub const AGGREGATES: &str = "aggregates";

pub use lighthouse_metrics::*;

lazy_static::lazy_static! {
    pub static ref GENESIS_DISTANCE: Result<IntGauge> = try_create_int_gauge(
        "vc_genesis_distance_seconds",
        "Distance between now and genesis time"
    );
    pub static ref ENABLED_VALIDATORS_COUNT: Result<IntGauge> = try_create_int_gauge(
        "vc_validators_enabled_count",
        "Number of enabled validators"
    );
    pub static ref TOTAL_VALIDATORS_COUNT: Result<IntGauge> = try_create_int_gauge(
        "vc_validators_total_count",
        "Number of disabled validators"
    );

    pub static ref SIGNED_BLOCKS_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "vc_signed_beacon_blocks_total",
        "Total count of attempted block signings",
        &["status"]
    );
    pub static ref SIGNED_ATTESTATIONS_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "vc_signed_attestations_total",
        "Total count of attempted Attestation signings",
        &["status"]
    );
    pub static ref SIGNED_AGGREGATES_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "vc_signed_aggregates_total",
        "Total count of attempted SignedAggregateAndProof signings",
        &["status"]
    );
    pub static ref SIGNED_SELECTION_PROOFS_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "vc_signed_selection_proofs_total",
        "Total count of attempted SelectionProof signings",
        &["status"]
    );
    pub static ref DUTIES_SERVICE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "vc_duties_service_task_times_seconds",
        "Duration to perform duties service tasks",
        &["task"]
    );
    pub static ref FORK_SERVICE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "vc_fork_service_task_times_seconds",
        "Duration to perform fork service tasks",
        &["task"]
    );
    pub static ref ATTESTATION_SERVICE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "vc_attestation_service_task_times_seconds",
        "Duration to perform attestation service tasks",
        &["task"]
    );
    pub static ref BLOCK_SERVICE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "vc_beacon_block_service_task_times_seconds",
        "Duration to perform beacon block service tasks",
        &["task"]
    );
}

pub fn gather_prometheus_metrics<T: EthSpec>(
    ctx: &Context<T>,
) -> std::result::Result<String, String> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();

    {
        let shared = ctx.shared.read();

        if let Some(genesis_time) = shared.genesis_time {
            if let Some(now) = SystemTime::now().duration_since(UNIX_EPOCH).ok() {
                let distance = now.as_secs() as i64 - genesis_time as i64;
                set_gauge(&GENESIS_DISTANCE, distance);
            }
        }

        if let Some(validator_store) = &shared.validator_store {
            let initialized_validators_lock = validator_store.initialized_validators();
            let initialized_validators = initialized_validators_lock.read();

            set_gauge(
                &ENABLED_VALIDATORS_COUNT,
                initialized_validators.num_enabled() as i64,
            );
            set_gauge(
                &TOTAL_VALIDATORS_COUNT,
                initialized_validators.num_total() as i64,
            );
        }
    }

    warp_utils::metrics::scrape_health_metrics();

    encoder
        .encode(&lighthouse_metrics::gather(), &mut buffer)
        .unwrap();

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}
