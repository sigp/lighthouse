use crate::{
    key::{BeaconChainKey, MetricsRegistryKey},
    map_persistent_err_to_500,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use iron::prelude::*;
use iron::{status::Status, Handler, IronResult, Request, Response};
use persistent::Read;
use prometheus::{Encoder, IntCounter, Opts, Registry, TextEncoder};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::Slot;

/// Yields a handler for the metrics endpoint.
pub fn build_handler<T: BeaconChainTypes + 'static>(
    beacon_chain: Arc<BeaconChain<T>>,
    metrics_registry: Registry,
) -> impl Handler {
    let mut chain = Chain::new(handle_metrics::<T>);

    chain.link(Read::<BeaconChainKey<T>>::both(beacon_chain));
    chain.link(Read::<MetricsRegistryKey>::both(metrics_registry));

    chain
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

    let present_slot = beacon_chain
        .slot_clock
        .present_slot()
        .unwrap_or_else(|_| None)
        .unwrap_or_else(|| Slot::new(0));
    register_and_set_slot(&r, "present_slot", "slock_clock_reading", present_slot);

    let best_slot = beacon_chain.head().beacon_block.slot;
    register_and_set_slot(&r, "best_slot", "slot_of_block_at_head_of_chain", best_slot);

    let validator_count = beacon_chain.head().beacon_state.validator_registry.len();
    register_and_set(
        &r,
        "validator_count",
        "total_number_of_validators",
        validator_count as i64,
    );

    // Gather the metrics.
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = r.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let prom_string = String::from_utf8(buffer).unwrap();

    Ok(Response::with((Status::Ok, prom_string)))
}

fn register_and_set(registry: &Registry, name: &str, help: &str, value: i64) {
    let counter_opts = Opts::new(name, help);
    let counter = IntCounter::with_opts(counter_opts).unwrap();
    registry.register(Box::new(counter.clone())).unwrap();
    counter.inc_by(value);
}

fn register_and_set_slot(registry: &Registry, name: &str, help: &str, slot: Slot) {
    let counter_opts = Opts::new(name, help);
    let counter = IntCounter::with_opts(counter_opts).unwrap();
    registry.register(Box::new(counter.clone())).unwrap();
    counter.inc_by(slot.as_u64() as i64);
}
