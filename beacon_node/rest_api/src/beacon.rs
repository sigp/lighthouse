use crate::helpers::*;
use crate::response_builder::ResponseBuilder;
use crate::{ApiError, ApiResult, BoxFut, NetworkService, UrlQuery};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use serde::Serialize;
use ssz_derive::Encode;
use std::sync::Arc;
use store::Store;
use types::{BeaconBlock, BeaconState, Epoch, EthSpec, Hash256, Slot, Validator};

#[derive(Serialize, Encode)]
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
pub fn get_head<T: BeaconChainTypes + 'static>(req: Request<Body>) -> BoxFut {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .expect("BeaconChain extension must be there, because we put it there.")
        .clone();

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

    success_response(req, &head)
}

#[derive(Serialize, Encode)]
#[serde(bound = "T: EthSpec")]
pub struct BlockResponse<T: EthSpec> {
    pub root: Hash256,
    pub beacon_block: BeaconBlock<T>,
}

/// HTTP handler to return a `BeaconBlock` at a given `root` or `slot`.
pub fn get_block<T: BeaconChainTypes + 'static>(req: Request<Body>) -> BoxFut {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .expect("BeaconChain extension must be there, because we put it there.")
        .clone();

    let query_params = ["root", "slot"];
    let query = try_future!(UrlQuery::from_request(&req));
    let (key, value) = try_future!(query.first_of(&query_params));

    let block_root = match (key.as_ref(), value) {
        ("slot", value) => {
            let target = try_future!(parse_slot(&value));

            try_future!(block_root_at_slot(&beacon_chain, target).ok_or_else(|| {
                ApiError::NotFound(format!("Unable to find BeaconBlock for slot {:?}", target))
            }))
        }
        ("root", value) => try_future!(parse_root(&value)),
        _ => {
            return Box::new(futures::future::err(ApiError::ServerError(
                "Unexpected query parameter".into(),
            )))
        }
    };

    let block = try_future!(try_future!(beacon_chain
        .store
        .get::<BeaconBlock<T::EthSpec>>(&block_root))
    .ok_or_else(|| {
        ApiError::NotFound(format!(
            "Unable to find BeaconBlock for root {:?}",
            block_root
        ))
    }));

    let response = BlockResponse {
        root: block_root,
        beacon_block: block,
    };

    success_response(req, &response)
}

/// HTTP handler to return a `BeaconBlock` root at a given `slot`.
pub fn get_block_root<T: BeaconChainTypes + 'static>(req: Request<Body>) -> BoxFut {
    let (beacon_chain, _head_state) = try_future!(get_beacon_chain_from_request::<T>(&req));

    let slot_string: String =
        try_future!(try_future!(UrlQuery::from_request(&req)).only_one("slot"));
    let target: Slot = try_future!(parse_slot(&slot_string));

    let root = try_future!(block_root_at_slot(&beacon_chain, target).ok_or_else(|| {
        ApiError::NotFound(format!("Unable to find BeaconBlock for slot {:?}", target))
    }));

    success_response(req, &root)
}

/// HTTP handler to return the `Fork` of the current head.
pub fn get_fork<T: BeaconChainTypes + 'static>(req: Request<Body>) -> BoxFut {
    let (_beacon_chain, head_state) = try_future!(get_beacon_chain_from_request::<T>(&req));

    success_response(req, &head_state.fork)
}

/// HTTP handler to return the set of validators for an `Epoch`
///
/// The `Epoch` parameter can be any epoch number. If it is not specified,
/// the current epoch is assumed.
pub fn get_validators<T: BeaconChainTypes + 'static>(req: Request<Body>) -> BoxFut {
    let (beacon_chain, _head_state) = try_future!(get_beacon_chain_from_request::<T>(&req));

    let epoch = match UrlQuery::from_request(&req) {
        // We have some parameters, so make sure it's the epoch one and parse it
        Ok(query) => try_future!(try_future!(query.only_one("epoch"))
            .parse::<u64>()
            .map(Epoch::from)
            .map_err(|e| {
                ApiError::InvalidQueryParams(format!(
                    "Invalid epoch parameter, must be a u64. {:?}",
                    e
                ))
            })),
        // In this case, our url query did not contain any parameters, so we take the default
        Err(_) => try_future!(beacon_chain.epoch().map_err(|e| {
            ApiError::ServerError(format!("Unable to determine current epoch: {:?}", e))
        })),
    };

    let all_validators = &beacon_chain.head().beacon_state.validators;
    let active_vals: Vec<Validator> = all_validators
        .iter()
        .filter(|v| v.is_active_at(epoch))
        .cloned()
        .collect();

    success_response(req, &active_vals)
}

#[derive(Serialize, Encode)]
#[serde(bound = "T: EthSpec")]
pub struct StateResponse<T: EthSpec> {
    pub root: Hash256,
    pub beacon_state: BeaconState<T>,
}

/// HTTP handler to return a `BeaconState` at a given `root` or `slot`.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn get_state<T: BeaconChainTypes + 'static>(req: Request<Body>) -> BoxFut {
    let (beacon_chain, head_state) = try_future!(get_beacon_chain_from_request::<T>(&req));

    let (key, value) = match UrlQuery::from_request(&req) {
        Ok(query) => {
            // We have *some* parameters, just check them.
            let query_params = ["root", "slot"];
            try_future!(query.first_of(&query_params))
        }
        Err(ApiError::InvalidQueryParams(_)) => {
            // No parameters provided at all, use current slot.
            (String::from("slot"), head_state.slot.to_string())
        }
        Err(e) => {
            return Box::new(futures::future::err(e));
        }
    };

    let (root, state): (Hash256, BeaconState<T::EthSpec>) = match (key.as_ref(), value) {
        ("slot", value) => try_future!(state_at_slot(
            &beacon_chain,
            try_future!(parse_slot(&value))
        )),
        ("root", value) => {
            let root = &try_future!(parse_root(&value));

            let state = try_future!(try_future!(beacon_chain.store.get(root))
                .ok_or_else(|| ApiError::NotFound(format!("No state for root: {:?}", root))));

            (*root, state)
        }
        _ => {
            return Box::new(futures::future::err(ApiError::ServerError(
                "Unexpected query parameter".into(),
            )))
        }
    };

    let response = StateResponse {
        root,
        beacon_state: state,
    };

    success_response(req, &response)
}

/// HTTP handler to return a `BeaconState` root at a given `slot`.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn get_state_root<T: BeaconChainTypes + 'static>(req: Request<Body>) -> BoxFut {
    let (beacon_chain, _head_state) = try_future!(get_beacon_chain_from_request::<T>(&req));

    let slot_string = try_future!(try_future!(UrlQuery::from_request(&req)).only_one("slot"));
    let slot = try_future!(parse_slot(&slot_string));

    let root = try_future!(state_root_at_slot(&beacon_chain, slot));

    success_response(req, &root)
}

/// HTTP handler to return the highest finalized slot.
pub fn get_current_finalized_checkpoint<T: BeaconChainTypes + 'static>(
    req: Request<Body>,
) -> BoxFut {
    let (beacon_chain, _head_state) = try_future!(get_beacon_chain_from_request::<T>(&req));

    let checkpoint = beacon_chain
        .head()
        .beacon_state
        .finalized_checkpoint
        .clone();

    success_response(req, &checkpoint)
}

/// HTTP handler to return a `BeaconState` at the genesis block.
pub fn get_genesis_state<T: BeaconChainTypes + 'static>(req: Request<Body>) -> BoxFut {
    let (beacon_chain, _head_state) = try_future!(get_beacon_chain_from_request::<T>(&req));

    let (_root, state) = try_future!(state_at_slot(&beacon_chain, Slot::new(0)));

    success_response(req, &state)
}
