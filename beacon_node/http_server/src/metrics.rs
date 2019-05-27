use crate::{key::BeaconChainKey, map_persistent_err_to_500};
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
) -> impl Handler {
    let mut chain = Chain::new(handle_metrics::<T>);

    chain.link(Read::<BeaconChainKey<T>>::both(beacon_chain));

    chain
}

/// Handle a request for Prometheus metrics.
///
/// Returns a text string containing all metrics.
fn handle_metrics<T: BeaconChainTypes + 'static>(req: &mut Request) -> IronResult<Response> {
    let beacon_chain = req
        .get::<Read<BeaconChainKey<T>>>()
        .map_err(map_persistent_err_to_500)?;

    let r = Registry::new();

    let present_slot = if let Ok(Some(slot)) = beacon_chain.slot_clock.present_slot() {
        slot
    } else {
        Slot::new(0)
    };
    register_and_set_slot(
        &r,
        "present_slot",
        "direct_slock_clock_reading",
        present_slot,
    );

    // Gather the metrics.
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = r.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let prom_string = String::from_utf8(buffer).unwrap();

    Ok(Response::with((Status::Ok, prom_string)))
}

fn register_and_set_slot(registry: &Registry, name: &str, help: &str, slot: Slot) {
    let counter_opts = Opts::new(name, help);
    let counter = IntCounter::with_opts(counter_opts).unwrap();
    registry.register(Box::new(counter.clone())).unwrap();
    counter.inc_by(slot.as_u64() as i64);
}
