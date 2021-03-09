use crate::Context;
use beacon_chain::BeaconChainTypes;
use lighthouse_metrics::Encoder;

pub use lighthouse_metrics::*;
use prometheus::proto::{MetricFamily, MetricType};
use std::io::Write;

pub const REQUIRED_METRICS: &'static [&str] = &[
    "cpu_process_seconds_total",
    "process_virtual_memory_bytes",
    "sync_eth1_fallback_configured",
    "eth1_sync_fallback_configured",
    "sync_eth1_connected",
    "store_disk_db_size",
    "libp2p_peer_connected_peers_total",
    "beacon_head_state_slot",
    "sync_eth2_synced",
];

/// An encoder that encodes all `Count` and `Gauge` metrics to a flat json
/// without any labels.
pub struct JsonEncoder;

impl JsonEncoder {
    pub fn new() -> Self {
        JsonEncoder
    }
}

impl Encoder for JsonEncoder {
    fn encode<W: Write>(&self, metric_families: &[MetricFamily], writer: &mut W) -> Result<()> {
        writer.write_all(b"{\n")?;
        for (i, mf) in metric_families
            .iter()
            .filter(|mf| REQUIRED_METRICS.iter().any(|name| mf.get_name() == *name))
            .enumerate()
        {
            let name = mf.get_name();
            if i != 0 {
                writer.write_all(b",")?;
            }

            for metric in mf.get_metric() {
                let value = match mf.get_field_type() {
                    MetricType::COUNTER => metric.get_counter().get_value().to_string(),
                    MetricType::GAUGE => metric.get_gauge().get_value().to_string(),
                    _ => {
                        return Err(prometheus::Error::Msg(
                            "Cannot encode this metric".to_string(),
                        ))
                    }
                };
                writer.write_all(b"\"")?;
                writer.write_all(name.as_bytes())?;
                writer.write_all(b"\":")?;
                writer.write_all(value.as_bytes())?;
            }
        }
        writer.write_all(b"}")?;

        Ok(())
    }

    fn format_type(&self) -> &str {
        "json"
    }
}

pub fn gather_required_metrics<T: BeaconChainTypes>(
    ctx: &Context<T>,
) -> std::result::Result<String, String> {
    let mut buffer = vec![];
    let encoder = JsonEncoder::new();

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

    if let (Some(db_path), Some(freezer_db_path)) =
        (ctx.db_path.as_ref(), ctx.freezer_db_path.as_ref())
    {
        store::scrape_for_metrics(db_path, freezer_db_path);
    }

    eth2_libp2p::scrape_discovery_metrics();

    warp_utils::metrics::scrape_process_health_metrics();

    let metrics = lighthouse_metrics::gather();

    let json_encoder = JsonEncoder::new();
    let mut json_buffer = vec![];
    json_encoder.encode(&metrics, &mut json_buffer).unwrap();

    // println!(
    //     "{}",
    //     String::from_utf8(json_buffer)
    //         .map_err(|e| format!("Failed to encode prometheus info: {:?}", e))?
    // );

    encoder.encode(&metrics, &mut buffer).unwrap();

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}
