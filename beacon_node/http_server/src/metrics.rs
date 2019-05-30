use crate::{
    key::{BeaconChainKey, LocalMetricsKey, MetricsRegistryKey},
    map_persistent_err_to_500,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use iron::prelude::*;
use iron::{status::Status, Handler, IronResult, Request, Response};
use persistent::Read;
use prometheus::{Encoder, IntGauge, Opts, Registry, TextEncoder};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::Slot;

/// Yields a handler for the metrics endpoint.
pub fn build_handler<T: BeaconChainTypes + 'static>(
    beacon_chain: Arc<BeaconChain<T>>,
    metrics_registry: Registry,
) -> impl Handler {
    let mut chain = Chain::new(handle_metrics::<T>);

    let local_metrics = LocalMetrics::new().unwrap();
    local_metrics.register(&metrics_registry).unwrap();

    chain.link(Read::<BeaconChainKey<T>>::both(beacon_chain));
    chain.link(Read::<MetricsRegistryKey>::both(metrics_registry));
    chain.link(Read::<LocalMetricsKey>::both(local_metrics));

    chain
}

pub struct LocalMetrics {
    present_slot: IntGauge,
    best_slot: IntGauge,
    validator_count: IntGauge,
}

impl LocalMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            present_slot: {
                let opts = Opts::new("present_slot", "slot_at_time_of_scrape");
                IntGauge::with_opts(opts)?
            },
            best_slot: {
                let opts = Opts::new("best_slot", "slot_of_block_at_chain_head");
                IntGauge::with_opts(opts)?
            },
            validator_count: {
                let opts = Opts::new("validator_count", "number_of_validators");
                IntGauge::with_opts(opts)?
            },
        })
    }

    pub fn register(&self, registry: &Registry) -> Result<(), prometheus::Error> {
        registry.register(Box::new(self.present_slot.clone()))?;
        registry.register(Box::new(self.best_slot.clone()))?;
        registry.register(Box::new(self.validator_count.clone()))?;

        Ok(())
    }
}

/// Handle a request for Prometheus metrics.
///
/// Returns a text string containing all metrics.
fn handle_metrics<T: BeaconChainTypes + 'static>(req: &mut Request) -> IronResult<Response> {
    let beacon_chain = req
        .get::<Read<BeaconChainKey<T>>>()
        .map_err(map_persistent_err_to_500)?;

    let r = req
        .get::<Read<MetricsRegistryKey>>()
        .map_err(map_persistent_err_to_500)?;

    let local_metrics = req
        .get::<Read<LocalMetricsKey>>()
        .map_err(map_persistent_err_to_500)?;

    let present_slot = beacon_chain
        .slot_clock
        .present_slot()
        .unwrap_or_else(|_| None)
        .unwrap_or_else(|| Slot::new(0));
    local_metrics.present_slot.set(present_slot.as_u64() as i64);

    let best_slot = beacon_chain.head().beacon_block.slot;
    local_metrics.best_slot.set(best_slot.as_u64() as i64);

    let validator_count = beacon_chain.head().beacon_state.validator_registry.len();
    local_metrics.validator_count.set(validator_count as i64);

    let mut buffer = vec![];
    let encoder = TextEncoder::new();

    // Gather `DEFAULT_REGISTRY` metrics.
    encoder.encode(&prometheus::gather(), &mut buffer).unwrap();

    // Gather metrics from our registry.
    let metric_families = r.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let prom_string = String::from_utf8(buffer).unwrap();

    Ok(Response::with((Status::Ok, prom_string)))
}
