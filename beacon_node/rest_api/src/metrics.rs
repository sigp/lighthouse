use crate::helpers::get_beacon_chain_from_request;
use crate::response_builder::ResponseBuilder;
use crate::{ApiError, ApiResult, DBPath};
use beacon_chain::BeaconChainTypes;
use hyper::{Body, Request};
use prometheus::{Encoder, TextEncoder};

pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref REQUEST_RESPONSE_TIME: Result<Histogram> = try_create_histogram(
        "http_server_request_duration_seconds",
        "Time taken to build a response to a HTTP request"
    );
    pub static ref REQUEST_COUNT: Result<IntCounter> = try_create_int_counter(
        "http_server_request_total",
        "Total count of HTTP requests received"
    );
    pub static ref SUCCESS_COUNT: Result<IntCounter> = try_create_int_counter(
        "http_server_success_total",
        "Total count of HTTP 200 responses sent"
    );
}

/// Returns the full set of Prometheus metrics for the Beacon Node application.
///
/// # Note
///
/// This is a HTTP handler method.
pub fn get_prometheus<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();

    let beacon_chain = get_beacon_chain_from_request::<T>(&req)?;
    let db_path = req
        .extensions()
        .get::<DBPath>()
        .ok_or_else(|| ApiError::ServerError("DBPath extension missing".to_string()))?;

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

    slot_clock::scrape_for_metrics::<T::EthSpec, T::SlotClock>(&beacon_chain.slot_clock);
    store::scrape_for_metrics(&db_path);
    beacon_chain::scrape_for_metrics(&beacon_chain);

    encoder
        .encode(&lighthouse_metrics::gather(), &mut buffer)
        .unwrap();

    String::from_utf8(buffer)
        .map(|string| ResponseBuilder::new(&req)?.body_text(string))
        .map_err(|e| ApiError::ServerError(format!("Failed to encode prometheus info: {:?}", e)))?
}
