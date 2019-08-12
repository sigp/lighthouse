use crate::{success_response, ApiError, ApiResult, DBPath};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use prometheus::{Encoder, TextEncoder};
use std::sync::Arc;

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

    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;
    let db_path = req
        .extensions()
        .get::<DBPath>()
        .ok_or_else(|| ApiError::ServerError("DBPath extension missing".to_string()))?;

    store::scrape_for_metrics(&db_path);
    beacon_chain::scrape_for_metrics(&beacon_chain);

    encoder.encode(&prometheus::gather(), &mut buffer).unwrap();

    String::from_utf8(buffer)
        .map(|string| success_response(Body::from(string)))
        .map_err(|e| ApiError::ServerError(format!("Failed to encode prometheus info: {:?}", e)))
}
