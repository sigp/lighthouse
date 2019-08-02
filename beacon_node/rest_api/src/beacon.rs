use super::{success_response, ApiResult};
use crate::{helpers::*, ApiError, UrlQuery};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use std::sync::Arc;
use store::Store;
use types::BeaconState;

/// HTTP handler to return a `BeaconState` at a given `root` or `slot`.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn get_state<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let query_params = ["root", "slot"];
    let (key, value) = UrlQuery::from_request(&req)?.first_of(&query_params)?;

    let state: BeaconState<T::EthSpec> = match (key.as_ref(), value) {
        ("slot", value) => state_at_slot(&beacon_chain, parse_slot(&value)?)?,
        ("root", value) => {
            let root = &parse_root(&value)?;

            beacon_chain
                .store
                .get(root)?
                .ok_or_else(|| ApiError::NotFound(format!("No state for root: {}", root)))?
        }
        _ => unreachable!("Guarded by UrlQuery::from_request()"),
    };

    let json: String = serde_json::to_string(&state)
        .map_err(|e| ApiError::ServerError(format!("Unable to serialize BeaconState: {:?}", e)))?;

    Ok(success_response(Body::from(json)))
}

/// HTTP handler to return a `BeaconState` root at a given or `slot`.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn get_state_root<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let slot_string = UrlQuery::from_request(&req)?.only_one("slot")?;
    let slot = parse_slot(&slot_string)?;

    let root = state_root_at_slot(&beacon_chain, slot)?;

    let json: String = serde_json::to_string(&root)
        .map_err(|e| ApiError::ServerError(format!("Unable to serialize root: {:?}", e)))?;

    Ok(success_response(Body::from(json)))
}
