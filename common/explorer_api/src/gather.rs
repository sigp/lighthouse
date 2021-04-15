use super::types::{BeaconProcessMetrics, ValidatorProcessMetrics};
use lazy_static::lazy_static;
use lighthouse_metrics::{MetricFamily, MetricType};
use std::collections::HashMap;
use std::path::Path;

/// The required metrics for the beacon and validator processes.
/// The first value in each tuple represents the name of the metric as used in Lighthouse metrics.
/// The second value represents the json key that we send to the remote explorer endpoint.
pub const BEACON_PROCESS_METRICS: &[(&str, &str)] = &[
    (
        "sync_eth1_fallback_configured",
        "sync_eth1_fallback_configured",
    ),
    (
        "sync_eth1_fallback_connected",
        "sync_eth1_fallback_connected",
    ),
    ("sync_eth1_connected", "sync_eth1_connected"),
    ("store_disk_db_size", "disk_beaconchain_bytes_total"),
    (
        "libp2p_peer_connected_peers_total",
        "network_peers_connected",
    ),
    (
        "libp2p_outbound_bytes",
        "network_libp2p_bytes_total_transmit",
    ),
    ("libp2p_inbound_bytes", "network_libp2p_bytes_total_receive"),
    ("notifier_head_slot", "sync_beacon_head_slot"),
    ("sync_eth2_synced", "sync_eth2_synced"),
];

pub const VALIDATOR_PROCESS_METRICS: &[(&str, &str)] = &[
    ("vc_validators_enabled_count", "validator_active"),
    ("vc_validators_total_count", "validator_total"),
    (
        "sync_eth2_fallback_configured",
        "sync_eth2_fallback_configured",
    ),
    (
        "sync_eth2_fallback_connected",
        "sync_eth2_fallback_connected",
    ),
];

lazy_static! {
    /// HashMap representing the `BEACON_PROCESS_METRICS`.
    pub static ref BEACON_METRICS_MAP: HashMap<&'static str, &'static str> = BEACON_PROCESS_METRICS
        .into_iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    /// HashMap representing the `VALIDATOR_PROCESS_METRICS`.
    pub static ref VALIDATOR_METRICS_MAP: HashMap<&'static str, &'static str> =
        VALIDATOR_PROCESS_METRICS
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
}

/// Returns the value from a Counter/Gauge `MetricType` assuming that it has no associated labels
/// else it returns `None`.
fn get_value(mf: &MetricFamily) -> Option<i64> {
    let metric = mf.get_metric().first()?;
    match mf.get_field_type() {
        MetricType::COUNTER => Some(metric.get_counter().get_value() as i64),
        MetricType::GAUGE => Some(metric.get_gauge().get_value() as i64),
        _ => None,
    }
}

/// Collects all metrics and returns a `serde_json::Value` object with the required metrics
/// from the metrics hashmap.
pub fn gather_metrics(metrics_map: &HashMap<&str, &str>) -> Result<serde_json::Value, String> {
    let metric_families = lighthouse_metrics::gather();
    let mut res = serde_json::Map::new();
    for mf in metric_families.iter() {
        let metric_name = mf.get_name();
        if metrics_map.contains_key(&metric_name) {
            let value = get_value(&mf)
                .ok_or_else(|| format!("No value found for metric: {}", metric_name))?;
            let key = metrics_map
                .get(&metric_name)
                .ok_or_else(|| format!("Failed to find value for metric {}", metric_name))?;
            let _ = res.insert(key.to_string(), value.into());
        }
    }
    Ok(serde_json::Value::Object(res))
}

/// Gathers and returns the lighthouse beacon metrics.
pub fn gather_beacon_metrics(
    db_path: &Path,
    freezer_db_path: &Path,
) -> Result<BeaconProcessMetrics, String> {
    // Update db size metrics
    store::metrics::scrape_for_metrics(db_path, freezer_db_path);

    let beacon_metrics = gather_metrics(&BEACON_METRICS_MAP)
        .map_err(|e| format!("Failed to gather beacon metrics: {}", e))?;
    let process = eth2::lighthouse::ProcessHealth::observe()?.into();

    Ok(BeaconProcessMetrics {
        beacon: beacon_metrics,
        common: process,
    })
}

/// Gathers and returns the lighthouse validator metrics.
pub fn gather_validator_metrics() -> Result<ValidatorProcessMetrics, String> {
    let validator_metrics = gather_metrics(&VALIDATOR_METRICS_MAP)
        .map_err(|e| format!("Failed to gather validator metrics: {}", e))?;

    let process = eth2::lighthouse::ProcessHealth::observe()?.into();
    Ok(ValidatorProcessMetrics {
        validator: validator_metrics,
        common: process,
    })
}
