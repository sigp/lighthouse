use crate::helpers::*;
use crate::response_builder::ResponseBuilder;
use crate::validator::get_state_for_epoch;
use crate::{ApiError, ApiResult, BoxFut, UrlQuery};
use beacon_chain::{BeaconChain, BeaconChainTypes, StateSkipConfig};
use futures::{Future, Stream};
use hyper::{Body, Request};
use rest_types::{
    BlockResponse, CanonicalHeadResponse, Committee, HeadBeaconBlock, StateResponse,
    ValidatorRequest, ValidatorResponse,
};
use std::sync::Arc;
use store::Store;
use types::{
    AttesterSlashing, BeaconState, EthSpec, Hash256, ProposerSlashing, PublicKeyBytes,
    RelativeEpoch, Slot,
};

/// HTTP handler to return a `BeaconBlock` at a given `root` or `slot`.
pub fn get_head<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let chain_head = beacon_chain.head()?;

    let head = CanonicalHeadResponse {
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

    ResponseBuilder::new(&req)?.body(&head)
}

/// HTTP handler to return a list of head BeaconBlocks.
pub fn get_heads<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let heads = beacon_chain
        .heads()
        .into_iter()
        .map(|(beacon_block_root, beacon_block_slot)| HeadBeaconBlock {
            beacon_block_root,
            beacon_block_slot,
        })
        .collect::<Vec<_>>();

    ResponseBuilder::new(&req)?.body(&heads)
}

/// HTTP handler to return a `BeaconBlock` at a given `root` or `slot`.
pub fn get_block<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query_params = ["root", "slot"];
    let (key, value) = UrlQuery::from_request(&req)?.first_of(&query_params)?;

    let block_root = match (key.as_ref(), value) {
        ("slot", value) => {
            let target = parse_slot(&value)?;

            block_root_at_slot(&beacon_chain, target)?.ok_or_else(|| {
                ApiError::NotFound(format!(
                    "Unable to find SignedBeaconBlock for slot {:?}",
                    target
                ))
            })?
        }
        ("root", value) => parse_root(&value)?,
        _ => return Err(ApiError::ServerError("Unexpected query parameter".into())),
    };

    let block = beacon_chain.store.get_block(&block_root)?.ok_or_else(|| {
        ApiError::NotFound(format!(
            "Unable to find SignedBeaconBlock for root {:?}",
            block_root
        ))
    })?;

    let response = BlockResponse {
        root: block_root,
        beacon_block: block,
    };

    ResponseBuilder::new(&req)?.body(&response)
}

/// HTTP handler to return a `SignedBeaconBlock` root at a given `slot`.
pub fn get_block_root<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let slot_string = UrlQuery::from_request(&req)?.only_one("slot")?;
    let target = parse_slot(&slot_string)?;

    let root = block_root_at_slot(&beacon_chain, target)?.ok_or_else(|| {
        ApiError::NotFound(format!(
            "Unable to find SignedBeaconBlock for slot {:?}",
            target
        ))
    })?;

    ResponseBuilder::new(&req)?.body(&root)
}

/// HTTP handler to return the `Fork` of the current head.
pub fn get_fork<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body(&beacon_chain.head()?.beacon_state.fork)
}

/// HTTP handler to which accepts a query string of a list of validator pubkeys and maps it to a
/// `ValidatorResponse`.
///
/// This method is limited to as many `pubkeys` that can fit in a URL. See `post_validators` for
/// doing bulk requests.
pub fn get_validators<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let validator_pubkeys = query
        .all_of("validator_pubkeys")?
        .iter()
        .map(|validator_pubkey_str| parse_pubkey_bytes(validator_pubkey_str))
        .collect::<Result<Vec<_>, _>>()?;

    let state_root_opt = if let Some((_key, value)) = query.first_of_opt(&["state_root"]) {
        Some(parse_root(&value)?)
    } else {
        None
    };

    let validators =
        validator_responses_by_pubkey(beacon_chain, state_root_opt, validator_pubkeys)?;

    ResponseBuilder::new(&req)?.body(&validators)
}

/// HTTP handler to return all validators, each as a `ValidatorResponse`.
pub fn get_all_validators<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let state_root_opt = if let Some((_key, value)) = query.first_of_opt(&["state_root"]) {
        Some(parse_root(&value)?)
    } else {
        None
    };

    let mut state = get_state_from_root_opt(&beacon_chain, state_root_opt)?;
    state.update_pubkey_cache()?;

    let validators = state
        .validators
        .iter()
        .map(|validator| validator_response_by_pubkey(&state, validator.pubkey.clone()))
        .collect::<Result<Vec<_>, _>>()?;

    ResponseBuilder::new(&req)?.body(&validators)
}

/// HTTP handler to return all active validators, each as a `ValidatorResponse`.
pub fn get_active_validators<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let state_root_opt = if let Some((_key, value)) = query.first_of_opt(&["state_root"]) {
        Some(parse_root(&value)?)
    } else {
        None
    };

    let mut state = get_state_from_root_opt(&beacon_chain, state_root_opt)?;
    state.update_pubkey_cache()?;

    let validators = state
        .validators
        .iter()
        .filter(|validator| validator.is_active_at(state.current_epoch()))
        .map(|validator| validator_response_by_pubkey(&state, validator.pubkey.clone()))
        .collect::<Result<Vec<_>, _>>()?;

    ResponseBuilder::new(&req)?.body(&validators)
}

/// HTTP handler to which accepts a `ValidatorRequest` and returns a `ValidatorResponse` for
/// each of the given `pubkeys`. When `state_root` is `None`, the canonical head is used.
///
/// This method allows for a basically unbounded list of `pubkeys`, where as the `get_validators`
/// request is limited by the max number of pubkeys you can fit in a URL.
pub fn post_validators<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);

    let future = req
        .into_body()
        .concat2()
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<ValidatorRequest>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into ValidatorRequest: {:?}",
                    e
                ))
            })
        })
        .and_then(|bulk_request| {
            validator_responses_by_pubkey(
                beacon_chain,
                bulk_request.state_root,
                bulk_request.pubkeys,
            )
        })
        .and_then(|validators| response_builder?.body(&validators));

    Box::new(future)
}

/// Returns either the state given by `state_root_opt`, or the canonical head state if it is
/// `None`.
fn get_state_from_root_opt<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    state_root_opt: Option<Hash256>,
) -> Result<BeaconState<T::EthSpec>, ApiError> {
    if let Some(state_root) = state_root_opt {
        beacon_chain
            .get_state(&state_root, None)
            .map_err(|e| {
                ApiError::ServerError(format!(
                    "Database error when reading state root {}: {:?}",
                    state_root, e
                ))
            })?
            .ok_or_else(|| ApiError::NotFound(format!("No state exists with root: {}", state_root)))
    } else {
        Ok(beacon_chain.head()?.beacon_state)
    }
}

/// Maps a vec of `validator_pubkey` to a vec of `ValidatorResponse`, using the state at the given
/// `state_root`. If `state_root.is_none()`, uses the canonial head state.
fn validator_responses_by_pubkey<T: BeaconChainTypes>(
    beacon_chain: Arc<BeaconChain<T>>,
    state_root_opt: Option<Hash256>,
    validator_pubkeys: Vec<PublicKeyBytes>,
) -> Result<Vec<ValidatorResponse>, ApiError> {
    let mut state = get_state_from_root_opt(&beacon_chain, state_root_opt)?;
    state.update_pubkey_cache()?;

    validator_pubkeys
        .into_iter()
        .map(|validator_pubkey| validator_response_by_pubkey(&state, validator_pubkey))
        .collect::<Result<Vec<_>, ApiError>>()
}

/// Maps a `validator_pubkey` to a `ValidatorResponse`, using the given state.
///
/// The provided `state` must have a fully up-to-date pubkey cache.
fn validator_response_by_pubkey<E: EthSpec>(
    state: &BeaconState<E>,
    validator_pubkey: PublicKeyBytes,
) -> Result<ValidatorResponse, ApiError> {
    let validator_index_opt = state
        .get_validator_index(&validator_pubkey)
        .map_err(|e| ApiError::ServerError(format!("Unable to read pubkey cache: {:?}", e)))?;

    if let Some(validator_index) = validator_index_opt {
        let balance = state.balances.get(validator_index).ok_or_else(|| {
            ApiError::ServerError(format!("Invalid balances index: {:?}", validator_index))
        })?;

        let validator = state
            .validators
            .get(validator_index)
            .ok_or_else(|| {
                ApiError::ServerError(format!("Invalid validator index: {:?}", validator_index))
            })?
            .clone();

        Ok(ValidatorResponse {
            pubkey: validator_pubkey,
            validator_index: Some(validator_index),
            balance: Some(*balance),
            validator: Some(validator),
        })
    } else {
        Ok(ValidatorResponse {
            pubkey: validator_pubkey,
            validator_index: None,
            balance: None,
            validator: None,
        })
    }
}

/// HTTP handler
pub fn get_committees<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let epoch = query.epoch()?;

    let mut state = get_state_for_epoch(&beacon_chain, epoch, StateSkipConfig::WithoutStateRoots)?;

    let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), epoch).map_err(|e| {
        ApiError::ServerError(format!("Failed to get state suitable for epoch: {:?}", e))
    })?;

    state
        .build_committee_cache(relative_epoch, &beacon_chain.spec)
        .map_err(|e| ApiError::ServerError(format!("Unable to build committee cache: {:?}", e)))?;

    let committees = state
        .get_beacon_committees_at_epoch(relative_epoch)
        .map_err(|e| ApiError::ServerError(format!("Unable to get all committees: {:?}", e)))?
        .into_iter()
        .map(|c| Committee {
            slot: c.slot,
            index: c.index,
            committee: c.committee.to_vec(),
        })
        .collect::<Vec<_>>();

    ResponseBuilder::new(&req)?.body(&committees)
}

/// HTTP handler to return a `BeaconState` at a given `root` or `slot`.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn get_state<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let head_state = beacon_chain.head()?.beacon_state;

    let (key, value) = match UrlQuery::from_request(&req) {
        Ok(query) => {
            // We have *some* parameters, just check them.
            let query_params = ["root", "slot"];
            query.first_of(&query_params)?
        }
        Err(ApiError::BadRequest(_)) => {
            // No parameters provided at all, use current slot.
            (String::from("slot"), head_state.slot.to_string())
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
                .get_state(root, None)?
                .ok_or_else(|| ApiError::NotFound(format!("No state for root: {:?}", root)))?;

            (*root, state)
        }
        _ => return Err(ApiError::ServerError("Unexpected query parameter".into())),
    };

    let response = StateResponse {
        root,
        beacon_state: state,
    };

    ResponseBuilder::new(&req)?.body(&response)
}

/// HTTP handler to return a `BeaconState` root at a given `slot`.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn get_state_root<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let slot_string = UrlQuery::from_request(&req)?.only_one("slot")?;
    let slot = parse_slot(&slot_string)?;

    let root = state_root_at_slot(&beacon_chain, slot, StateSkipConfig::WithStateRoots)?;

    ResponseBuilder::new(&req)?.body(&root)
}

/// HTTP handler to return a `BeaconState` at the genesis block.
///
/// This is an undocumented convenience method used during testing. For production, simply do a
/// state request at slot 0.
pub fn get_genesis_state<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let (_root, state) = state_at_slot(&beacon_chain, Slot::new(0))?;

    ResponseBuilder::new(&req)?.body(&state)
}

/// Read the genesis time from the current beacon chain state.
pub fn get_genesis_time<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body(&beacon_chain.head_info()?.genesis_time)
}

/// Read the `genesis_validators_root` from the current beacon chain state.
pub fn get_genesis_validators_root<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body(&beacon_chain.head_info()?.genesis_validators_root)
}

pub fn proposer_slashing<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);

    let future = req
        .into_body()
        .concat2()
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<ProposerSlashing>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into ProposerSlashing: {:?}",
                    e
                ))
            })
        })
        .and_then(move |proposer_slashing| {
            let spec = &beacon_chain.spec;
            let state = &beacon_chain.head().unwrap().beacon_state;
            if beacon_chain.eth1_chain.is_some() {
                beacon_chain
                    .op_pool
                    .insert_proposer_slashing(proposer_slashing, state, spec)
                    .map_err(|e| {
                        ApiError::BadRequest(format!(
                            "Error while inserting proposer slashing: {:?}",
                            e
                        ))
                    })
            } else {
                Err(ApiError::BadRequest(
                    "Cannot insert proposer slashing on node without Eth1 connection.".to_string(),
                ))
            }
        })
        .and_then(|_| response_builder?.body(&true));

    Box::new(future)
}

pub fn attester_slashing<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);

    let future = req
        .into_body()
        .concat2()
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<AttesterSlashing<T::EthSpec>>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into AttesterSlashing: {:?}",
                    e
                ))
            })
        })
        .and_then(move |attester_slashing| {
            let spec = &beacon_chain.spec;
            let state = &beacon_chain.head().unwrap().beacon_state;
            if beacon_chain.eth1_chain.is_some() {
                beacon_chain
                    .op_pool
                    .insert_attester_slashing(attester_slashing, state, spec)
                    .map_err(|e| {
                        ApiError::BadRequest(format!(
                            "Error while inserting attester slashing: {:?}",
                            e
                        ))
                    })
            } else {
                Err(ApiError::BadRequest(
                    "Cannot insert attester slashing on node without Eth1 connection.".to_string(),
                ))
            }
        })
        .and_then(|_| response_builder?.body(&true));

    Box::new(future)
}
