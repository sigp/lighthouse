use super::{success_response, ApiResult};
use crate::ApiError;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use std::sync::Arc;
use types::EthSpec;

/// HTTP handler to return the full spec object.
pub fn get_spec<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let json: String = serde_json::to_string(&beacon_chain.spec)
        .map_err(|e| ApiError::ServerError(format!("Unable to serialize spec: {:?}", e)))?;

    Ok(success_response(Body::from(json)))
}

/// HTTP handler to return the full spec object.
pub fn get_slots_per_epoch<T: BeaconChainTypes + 'static>(_req: Request<Body>) -> ApiResult {
    let json: String = serde_json::to_string(&T::EthSpec::slots_per_epoch())
        .map_err(|e| ApiError::ServerError(format!("Unable to serialize epoch: {:?}", e)))?;

    Ok(success_response(Body::from(json)))
}
