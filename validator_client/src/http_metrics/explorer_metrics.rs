use super::metrics::{ENABLED_VALIDATORS_COUNT, TOTAL_VALIDATORS_COUNT};
use super::Context;
use lighthouse_metrics::{json_encoder::JsonEncoder, Encoder};
use types::EthSpec;

pub use lighthouse_metrics::*;

/// Process names which need to be encoded
/// Note: Only Gauge and Counter metric types can be encoded.
pub const VALIDATOR_PROCESS_METRICS: &'static [&str] = &[
    "cpu_process_seconds_total",
    "process_virtual_memory_bytes",
    "vc_validators_enabled_count",
    "vc_validators_total_count",
    "sync_eth2_fallback_configured",
    "sync_eth2_fallback_connected",
];

pub fn gather_required_metrics<T: EthSpec>(
    ctx: &Context<T>,
) -> std::result::Result<String, String> {
    let mut buffer = vec![];
    let encoder = JsonEncoder::new(
        VALIDATOR_PROCESS_METRICS
            .into_iter()
            .map(|m| m.to_string())
            .collect(),
    );

    let shared = ctx.shared.read();

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

    warp_utils::metrics::scrape_process_health_metrics();

    let metrics = lighthouse_metrics::gather();

    encoder.encode(&metrics, &mut buffer).unwrap();

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}
