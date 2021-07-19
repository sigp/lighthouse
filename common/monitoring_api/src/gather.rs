use super::types::{BeaconProcessMetrics, ValidatorProcessMetrics};
use lazy_static::lazy_static;
use lighthouse_metrics::{MetricFamily, MetricType};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;

/// Represents a metric that needs to be fetched from lighthouse metrics registry
/// and sent to the remote monitoring service.
#[derive(Debug, Clone)]
pub struct JsonMetric {
    /// Name of the metric as used in Lighthouse metrics.
    lighthouse_metric_name: &'static str,
    /// Json key for the metric that we send to the remote monitoring endpoint.
    json_output_key: &'static str,
    /// Type of the json value to be sent to the remote monitoring endpoint
    ty: JsonType,
}

impl JsonMetric {
    const fn new(
        lighthouse_metric_name: &'static str,
        json_output_key: &'static str,
        ty: JsonType,
    ) -> Self {
        Self {
            lighthouse_metric_name,
            json_output_key,
            ty,
        }
    }

    /// Return a json value given given the metric type.
    fn get_typed_value(&self, value: i64) -> serde_json::Value {
        match self.ty {
            JsonType::Integer => json!(value),
            JsonType::Boolean => {
                if value > 0 {
                    json!(true)
                } else {
                    json!(false)
                }
            }
        }
    }
}

/// The required metrics for the beacon and validator processes.
const BEACON_PROCESS_METRICS: &[JsonMetric] = &[
    JsonMetric::new(
        "sync_eth1_fallback_configured",
        "sync_eth1_fallback_configured",
        JsonType::Boolean,
    ),
    JsonMetric::new(
        "sync_eth1_fallback_connected",
        "sync_eth1_fallback_connected",
        JsonType::Boolean,
    ),
    JsonMetric::new(
        "sync_eth1_connected",
        "sync_eth1_connected",
        JsonType::Boolean,
    ),
    JsonMetric::new(
        "store_disk_db_size",
        "disk_beaconchain_bytes_total",
        JsonType::Integer,
    ),
    JsonMetric::new(
        "libp2p_peer_connected_peers_total",
        "network_peers_connected",
        JsonType::Integer,
    ),
    JsonMetric::new(
        "libp2p_outbound_bytes",
        "network_libp2p_bytes_total_transmit",
        JsonType::Integer,
    ),
    JsonMetric::new(
        "libp2p_inbound_bytes",
        "network_libp2p_bytes_total_receive",
        JsonType::Integer,
    ),
    JsonMetric::new(
        "notifier_head_slot",
        "sync_beacon_head_slot",
        JsonType::Integer,
    ),
    JsonMetric::new("sync_eth2_synced", "sync_eth2_synced", JsonType::Boolean),
];

const VALIDATOR_PROCESS_METRICS: &[JsonMetric] = &[
    JsonMetric::new(
        "vc_validators_enabled_count",
        "validator_active",
        JsonType::Integer,
    ),
    JsonMetric::new(
        "vc_validators_total_count",
        "validator_total",
        JsonType::Integer,
    ),
    JsonMetric::new(
        "sync_eth2_fallback_configured",
        "sync_eth2_fallback_configured",
        JsonType::Boolean,
    ),
    JsonMetric::new(
        "sync_eth2_fallback_connected",
        "sync_eth2_fallback_connected",
        JsonType::Boolean,
    ),
];

/// Represents the type for the JSON output.
#[derive(Debug, Clone)]
pub enum JsonType {
    Integer,
    Boolean,
}

lazy_static! {
    /// HashMap representing the `BEACON_PROCESS_METRICS`.
    pub static ref BEACON_METRICS_MAP: HashMap<String, JsonMetric> = BEACON_PROCESS_METRICS
        .iter()
        .map(|metric| (metric.lighthouse_metric_name.to_string(), metric.clone()))
        .collect();
    /// HashMap representing the `VALIDATOR_PROCESS_METRICS`.
    pub static ref VALIDATOR_METRICS_MAP: HashMap<String,JsonMetric> =
        VALIDATOR_PROCESS_METRICS
        .iter()
        .map(|metric| (metric.lighthouse_metric_name.to_string(), metric.clone()))
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
pub fn gather_metrics(metrics_map: &HashMap<String, JsonMetric>) -> Option<serde_json::Value> {
    let metric_families = lighthouse_metrics::gather();
    let mut res = serde_json::Map::with_capacity(metrics_map.len());
    for mf in metric_families.iter() {
        let metric_name = mf.get_name();
        if metrics_map.contains_key(metric_name) {
            let value = get_value(&mf).unwrap_or_default();
            let metric = metrics_map.get(metric_name)?;
            let value = metric.get_typed_value(value);
            let _ = res.insert(metric.json_output_key.to_string(), value);
        };
    }
    Some(serde_json::Value::Object(res))
}

/// Gathers and returns the lighthouse beacon metrics.
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

/// Gathers and returns the lighthouse validator metrics.
pub fn gather_validator_metrics() -> Result<ValidatorProcessMetrics, String> {
    let validator_metrics = gather_metrics(&VALIDATOR_METRICS_MAP)
        .ok_or_else(|| "Failed to gather validator metrics".to_string())?;

    let process = eth2::lighthouse::ProcessHealth::observe()?.into();
    Ok(ValidatorProcessMetrics {
        validator: validator_metrics,
        common: process,
    })
}
