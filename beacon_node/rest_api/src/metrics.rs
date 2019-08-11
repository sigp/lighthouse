use crate::{success_response, ApiError, ApiResult};
use hyper::{Body, Request};
use prometheus::{Encoder, TextEncoder};

/// Returns the full set of Prometheus metrics for the Beacon Node application.
pub fn get_prometheus(_req: Request<Body>) -> ApiResult {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();

    encoder
        .encode(&beacon_chain::gather_metrics(), &mut buffer)
        .unwrap();

    String::from_utf8(buffer)
        .map(|string| success_response(Body::from(string)))
        .map_err(|e| ApiError::ServerError(format!("Failed to encode prometheus info: {:?}", e)))
}
