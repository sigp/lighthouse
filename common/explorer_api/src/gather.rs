use super::types::{BeaconProcessMetrics, ValidatorProcessMetrics};
use lazy_static::lazy_static;
use lighthouse_metrics::{MetricFamily, MetricType};
use std::collections::HashMap;
use std::path::Path;

pub const BEACON_PROCESS_METRICS: &[(&'static str, &'static str)] = &[
    (
        "sync_eth1_fallback_configured",
        "sync_eth1_fallback_configured",
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

pub const VALIDATOR_PROCESS_METRICS: &[(&'static str, &'static str)] = &[
    ("vc_validators_enabled_count", "validator_active"),
    ("vc_validators_total_count", "validator_active"),
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
    pub static ref BEACON_METRICS_MAP: HashMap<&'static str, &'static str> = BEACON_PROCESS_METRICS
        .into_iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    pub static ref VALIDATOR_METRICS_MAP: HashMap<&'static str, &'static str> =
        VALIDATOR_PROCESS_METRICS
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
}

/// Gets the value from a Counter/Gauge `MetricType` assuming that it has no associated labels
fn get_value(mf: &MetricFamily) -> Option<i64> {
    let metric = mf.get_metric().first()?;
    match mf.get_field_type() {
        MetricType::COUNTER => Some(metric.get_counter().get_value() as i64),
        MetricType::GAUGE => Some(metric.get_gauge().get_value() as i64),
        _ => None,
    }
}

pub fn gather_metrics(metrics_map: &HashMap<&str, &str>) -> Option<serde_json::Value> {
    let metric_families = lighthouse_metrics::gather();
    let mut res = serde_json::Map::new();
    for mf in metric_families.iter() {
        let metric_name = mf.get_name();
        if metrics_map.contains_key(&metric_name) {
            let value = get_value(&mf)?;
            let key = metrics_map.get(&metric_name)?;
            let _ = res.insert(key.to_string(), value.into());
        }
    }
    Some(serde_json::Value::Object(res))
}

pub fn gather_beacon_metrics(
    db_path: &Path,
    freezer_db_path: &Path,
) -> Result<BeaconProcessMetrics, String> {
    // Update db size metrics
    store::metrics::scrape_for_metrics(db_path, freezer_db_path);

    let beacon_metrics = gather_metrics(&BEACON_METRICS_MAP)
        .ok_or_else(|| "Failed to gather beacon metrics".to_string())?;
    let process = eth2::lighthouse::ProcessHealth::observe()?.into();

    Ok(BeaconProcessMetrics {
        beacon: beacon_metrics,
        common: process,
    })
}

pub fn gather_validator_metrics() -> Result<ValidatorProcessMetrics, String> {
    let validator_metrics = gather_metrics(&VALIDATOR_METRICS_MAP)
        .ok_or_else(|| "Failed to gather validator metrics".to_string())?;

    let process = eth2::lighthouse::ProcessHealth::observe()?.into();
    Ok(ValidatorProcessMetrics {
        validator: validator_metrics,
        common: process,
    })
}
