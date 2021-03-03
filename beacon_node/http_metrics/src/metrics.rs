use crate::Context;
use beacon_chain::BeaconChainTypes;
use lighthouse_metrics::{Encoder, TextEncoder};

pub use lighthouse_metrics::*;
use prometheus::proto::{MetricFamily, MetricType};
use std::io::Write;

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
        // TODO: don't write metrics with labels
        for mf in metric_families
            .iter()
            .filter(|mf| mf.get_field_type() == MetricType::COUNTER)
        {
            let name = mf.get_name();
            for metric in mf.get_metric() {
                writer.write_all(b"\"")?;
                writer.write_all(name.as_bytes())?;
                writer.write_all(b"\":")?;
                writer.write_all(metric.get_counter().get_value().to_string().as_bytes())?;
                writer.write_all(b",")?;
                writer.write_all(b"\n")?;
            }
        }

        let gauges: Vec<&MetricFamily> = metric_families
            .iter()
            .filter(|mf| mf.get_field_type() == MetricType::GAUGE)
            .collect();

        for (i, mf) in gauges.iter().enumerate() {
            let name = mf.get_name();
            for metric in mf.get_metric() {
                writer.write_all(b"\"")?;
                writer.write_all(name.as_bytes())?;
                writer.write_all(b"\":")?;
                writer.write_all(metric.get_gauge().get_value().to_string().as_bytes())?;
                if i != gauges.len() - 1 {
                    writer.write_all(b",")?;
                }
                writer.write_all(b"\n")?;
            }
        }
        writer.write_all(b"}")?;

        Ok(())
    }

    fn format_type(&self) -> &str {
        "json"
    }
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

    if let (Some(db_path), Some(freezer_db_path)) =
        (ctx.db_path.as_ref(), ctx.freezer_db_path.as_ref())
    {
        store::scrape_for_metrics(db_path, freezer_db_path);
    }

    eth2_libp2p::scrape_discovery_metrics();

    warp_utils::metrics::scrape_health_metrics();

    let metrics = lighthouse_metrics::gather();

    let json_encoder = JsonEncoder::new();
    let mut json_buffer = vec![];
    json_encoder.encode(&metrics, &mut json_buffer).unwrap();

    println!(
        "{}",
        String::from_utf8(json_buffer)
            .map_err(|e| format!("Failed to encode prometheus info: {:?}", e))?
    );

    encoder.encode(&metrics, &mut buffer).unwrap();

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}
