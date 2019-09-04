use super::{success_response, ApiResult};
use crate::{helpers::*, ApiError, UrlQuery};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use serde::Serialize;
use std::sync::Arc;
use store::Store;
use types::{BeaconBlock, BeaconState, EthSpec, Hash256, Slot};

#[derive(Serialize)]
pub struct HeadResponse {
    pub slot: Slot,
    pub block_root: Hash256,
    pub state_root: Hash256,
    pub finalized_slot: Slot,
    pub finalized_block_root: Hash256,
    pub justified_slot: Slot,
    pub justified_block_root: Hash256,
    pub previous_justified_slot: Slot,
    pub previous_justified_block_root: Hash256,
}

/// HTTP handler to return a `BeaconBlock` at a given `root` or `slot`.
pub fn get_head<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let chain_head = beacon_chain.head();

    let head = HeadResponse {
        slot: chain_head.beacon_state.slot,
        block_root: chain_head.beacon_block_root,
        state_root: chain_head.beacon_state_root,
        finalized_slot: chain_head
            .beacon_state
            .finalized_checkpoint
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch()),
        finalized_block_root: chain_head.beacon_state.finalized_checkpoint.root,
        justified_slot: chain_head
            .beacon_state
            .current_justified_checkpoint
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch()),
        justified_block_root: chain_head.beacon_state.current_justified_checkpoint.root,
        previous_justified_slot: chain_head
            .beacon_state
            .previous_justified_checkpoint
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch()),
        previous_justified_block_root: chain_head.beacon_state.previous_justified_checkpoint.root,
    };

    let json: String = serde_json::to_string(&head)
        .map_err(|e| ApiError::ServerError(format!("Unable to serialize HeadResponse: {:?}", e)))?;

    Ok(success_response(Body::from(json)))
}

#[derive(Serialize)]
#[serde(bound = "T: EthSpec")]
pub struct BlockResponse<T: EthSpec> {
    pub root: Hash256,
    pub beacon_block: BeaconBlock<T>,
}

/// HTTP handler to return a `BeaconBlock` at a given `root` or `slot`.
pub fn get_block<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let query_params = ["root", "slot"];
    let (key, value) = UrlQuery::from_request(&req)?.first_of(&query_params)?;

    let block_root = match (key.as_ref(), value) {
        ("slot", value) => {
            let target = parse_slot(&value)?;

            block_root_at_slot(&beacon_chain, target).ok_or_else(|| {
                ApiError::NotFound(format!("Unable to find BeaconBlock for slot {:?}", target))
            })?
        }
        ("root", value) => parse_root(&value)?,
        _ => return Err(ApiError::ServerError("Unexpected query parameter".into())),
    };

    let block = beacon_chain
        .store
        .get::<BeaconBlock<T::EthSpec>>(&block_root)?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "Unable to find BeaconBlock for root {:?}",
                block_root
            ))
        })?;

    let response = BlockResponse {
        root: block_root,
        beacon_block: block,
    };

    let json: String = serde_json::to_string(&response).map_err(|e| {
        ApiError::ServerError(format!("Unable to serialize BlockResponse: {:?}", e))
    })?;

    Ok(success_response(Body::from(json)))
}

/// HTTP handler to return a `BeaconBlock` root at a given `slot`.
pub fn get_block_root<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let slot_string = UrlQuery::from_request(&req)?.only_one("slot")?;
    let target = parse_slot(&slot_string)?;

    let root = block_root_at_slot(&beacon_chain, target).ok_or_else(|| {
        ApiError::NotFound(format!("Unable to find BeaconBlock for slot {:?}", target))
    })?;

    let json: String = serde_json::to_string(&root)
        .map_err(|e| ApiError::ServerError(format!("Unable to serialize root: {:?}", e)))?;

    Ok(success_response(Body::from(json)))
}

/// HTTP handler to return the `Fork` of the current head.
pub fn get_fork<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let chain_head = beacon_chain.head();

    let json: String = serde_json::to_string(&chain_head.beacon_state.fork).map_err(|e| {
        ApiError::ServerError(format!("Unable to serialize BeaconState::Fork: {:?}", e))
    })?;

    Ok(success_response(Body::from(json)))
}

#[derive(Serialize)]
#[serde(bound = "T: EthSpec")]
pub struct StateResponse<T: EthSpec> {
    pub root: Hash256,
    pub beacon_state: BeaconState<T>,
}

/// HTTP handler to return a `BeaconState` at a given `root` or `slot`.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn get_state<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let (key, value) = match UrlQuery::from_request(&req) {
        Ok(query) => {
            // We have *some* parameters, check them.
            let query_params = ["root", "slot"];
            match query.first_of(&query_params) {
                Ok((k, v)) => (k, v),
                Err(e) => {
                    // Wrong parameters provided, or another error, return the error.
                    return Err(e);
                }
            }
        }
        Err(ApiError::InvalidQueryParams(_)) => {
            // No parameters provided at all, use current slot.
            (
                String::from("slot"),
                beacon_chain.head().beacon_state.slot.to_string(),
            )
        }
        Err(e) => {
            return Err(e);
        }
    };

    let (root, state): (Hash256, BeaconState<T::EthSpec>) = match (key.as_ref(), value) {
        ("slot", value) => state_at_slot(&beacon_chain, parse_slot(&value)?)?,
        ("root", value) => {
            let root = &parse_root(&value)?;

            let state = beacon_chain
                .store
                .get(root)?
                .ok_or_else(|| ApiError::NotFound(format!("No state for root: {:?}", root)))?;

            (*root, state)
        }
        _ => return Err(ApiError::ServerError("Unexpected query parameter".into())),
    };

    let response = StateResponse {
        root,
        beacon_state: state,
    };

    let json: String = serde_json::to_string(&response).map_err(|e| {
        ApiError::ServerError(format!("Unable to serialize StateResponse: {:?}", e))
    })?;

    Ok(success_response(Body::from(json)))
}

/// HTTP handler to return a `BeaconState` root at a given `slot`.
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

/// HTTP handler to return the highest finalized slot.
pub fn get_current_finalized_checkpoint<T: BeaconChainTypes + 'static>(
    req: Request<Body>,
) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let checkpoint = beacon_chain
        .head()
        .beacon_state
        .finalized_checkpoint
        .clone();

    let json: String = serde_json::to_string(&checkpoint)
        .map_err(|e| ApiError::ServerError(format!("Unable to serialize checkpoint: {:?}", e)))?;

    Ok(success_response(Body::from(json)))
}
