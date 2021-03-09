use crate::Context;
use beacon_chain::BeaconChainTypes;
use lighthouse_metrics::{json_encoder::JsonEncoder, Encoder};

pub use lighthouse_metrics::*;

/// Process names which need to be encoded
/// Note: Only Gauge and Counter metrics can be encoded.
pub const BEACON_PROCESS_METRICS: &'static [&str] = &[
    "cpu_process_seconds_total",
    "process_virtual_memory_bytes",
    "sync_eth1_fallback_configured",
    "sync_eth1_connected",
    "store_disk_db_size",
    "libp2p_peer_connected_peers_total",
    "beacon_head_state_slot",
    "sync_eth2_synced",
];

pub fn gather_required_metrics<T: BeaconChainTypes>(
    ctx: &Context<T>,
) -> std::result::Result<String, String> {
    let mut buffer = vec![];
    let encoder = JsonEncoder::new(
        BEACON_PROCESS_METRICS
            .into_iter()
            .map(|m| m.to_string())
            .collect(),
    );

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

    encoder.encode(&metrics, &mut buffer).unwrap();

    encoder.encode(&metrics, &mut buffer).unwrap();

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}
