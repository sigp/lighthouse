use crate::{
    key::{BeaconChainKey, LocalMetricsKey, MetricsRegistryKey},
    map_persistent_err_to_500,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use iron::prelude::*;
use iron::{status::Status, Handler, IronResult, Request, Response};
use persistent::Read;
use prometheus::{Encoder, Registry, TextEncoder};
use std::sync::Arc;

pub use local_metrics::LocalMetrics;

mod local_metrics;

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

    // Update metrics that are calculated on each scrape.
    local_metrics.update(&beacon_chain);

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
