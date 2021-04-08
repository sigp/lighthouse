use super::types::{
    BeaconMetrics, BeaconProcessMetrics, ValidatorMetrics, ValidatorProcessMetrics,
};
use lighthouse_metrics::{json_encoder::JsonEncoder, Encoder};
use serde::de::DeserializeOwned;
use std::path::Path;

pub const BEACON_PROCESS_METRICS: &[&str] = &[
    "sync_eth1_fallback_configured",
    "sync_eth1_connected",
    "store_disk_db_size",
    "libp2p_peer_connected_peers_total",
    "beacon_head_state_slot",
    "sync_eth2_synced",
];

pub const VALIDATOR_PROCESS_METRICS: &[&str] = &[
    "vc_validators_enabled_count",
    "vc_validators_total_count",
    "sync_eth2_fallback_configured",
    "sync_eth2_fallback_connected",
];

fn gather_metrics<T: DeserializeOwned>(required_metrics: &[&str]) -> Result<T, String> {
    let mut buffer = vec![];
    let encoder = JsonEncoder::new(required_metrics.iter().map(|m| m.to_string()).collect());

    let metrics = lighthouse_metrics::gather();

    encoder.encode(&metrics, &mut buffer).unwrap();

    let json_string = String::from_utf8(buffer)
        .map_err(|e| format!("Failed to encode prometheus info: {:?}", e))?;

    serde_json::from_str(&json_string).map_err(|e| format!("Failed to decode json string: {}", e))
}

pub fn gather_beacon_metrics(
    db_path: &Path,
    freezer_db_path: &Path,
) -> Result<BeaconProcessMetrics, String> {
    // Update db size metrics
    store::metrics::scrape_for_metrics(db_path, freezer_db_path);

    let beacon_metrics: BeaconMetrics = gather_metrics(BEACON_PROCESS_METRICS)?;
    let process = eth2::lighthouse::ProcessHealth::observe()?.into();

    Ok(BeaconProcessMetrics {
        beacon: beacon_metrics,
        common: process,
    })
}

pub fn gather_validator_metrics() -> Result<ValidatorProcessMetrics, String> {
    let validator_metrics: ValidatorMetrics = gather_metrics(VALIDATOR_PROCESS_METRICS)?;

    let process = eth2::lighthouse::ProcessHealth::observe()?.into();
    Ok(ValidatorProcessMetrics {
        validator: validator_metrics,
        common: process,
    })
}
