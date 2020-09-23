use crate::helpers::*;
use crate::validator::get_state_for_epoch;
use crate::Context;
use crate::{ApiError, UrlQuery};
use beacon_chain::{
    observed_operations::ObservationOutcome, BeaconChain, BeaconChainTypes, StateSkipConfig,
};
use futures::executor::block_on;
use hyper::body::Bytes;
use hyper::{Body, Request};
use rest_types::{
    BlockResponse, CanonicalHeadResponse, Committee, HeadBeaconBlock, StateResponse,
    ValidatorRequest, ValidatorResponse,
};
use std::io::Write;
use std::sync::Arc;

use slog::error;
use types::{
    AttesterSlashing, BeaconState, EthSpec, Hash256, ProposerSlashing, PublicKeyBytes,
    RelativeEpoch, SignedBeaconBlockHash, Slot,
};

/// Returns a summary of the head of the beacon chain.
pub fn get_head<T: BeaconChainTypes>(
    ctx: Arc<Context<T>>,
) -> Result<CanonicalHeadResponse, ApiError> {
    let beacon_chain = &ctx.beacon_chain;
    let chain_head = beacon_chain.head()?;

    Ok(CanonicalHeadResponse {
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
    })
}

/// Return the list of heads of the beacon chain.
pub fn get_heads<T: BeaconChainTypes>(ctx: Arc<Context<T>>) -> Vec<HeadBeaconBlock> {
    ctx.beacon_chain
        .heads()
        .into_iter()
        .map(|(beacon_block_root, beacon_block_slot)| HeadBeaconBlock {
            beacon_block_root,
            beacon_block_slot,
        })
        .collect()
}

/// HTTP handler to return a `BeaconBlock` at a given `root` or `slot`.
pub fn get_block<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<BlockResponse<T::EthSpec>, ApiError> {
    let beacon_chain = &ctx.beacon_chain;
    let query_params = ["root", "slot"];
    let (key, value) = UrlQuery::from_request(&req)?.first_of(&query_params)?;

    let block_root = match (key.as_ref(), value) {
        ("slot", value) => {
            let target = parse_slot(&value)?;

            block_root_at_slot(beacon_chain, target)?.ok_or_else(|| {
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

    Ok(BlockResponse {
        root: block_root,
        beacon_block: block,
    })
}

/// HTTP handler to return a `SignedBeaconBlock` root at a given `slot`.
pub fn get_block_root<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<Hash256, ApiError> {
    let slot_string = UrlQuery::from_request(&req)?.only_one("slot")?;
    let target = parse_slot(&slot_string)?;

    block_root_at_slot(&ctx.beacon_chain, target)?.ok_or_else(|| {
        ApiError::NotFound(format!(
            "Unable to find SignedBeaconBlock for slot {:?}",
            target
        ))
    })
}

fn make_sse_response_chunk(new_head_hash: SignedBeaconBlockHash) -> std::io::Result<Bytes> {
    let mut buffer = Vec::new();
    {
        let mut sse_message = uhttp_sse::SseMessage::new(&mut buffer);
        let untyped_hash: Hash256 = new_head_hash.into();
        write!(sse_message.data()?, "{:?}", untyped_hash)?;
    }
    let bytes: Bytes = buffer.into();
    Ok(bytes)
}

pub fn stream_forks<T: BeaconChainTypes>(ctx: Arc<Context<T>>) -> Result<Body, ApiError> {
    let mut events = ctx.events.lock().add_rx();
    let (mut sender, body) = Body::channel();
    std::thread::spawn(move || {
        while let Ok(new_head_hash) = events.recv() {
            let chunk = match make_sse_response_chunk(new_head_hash) {
                Ok(chunk) => chunk,
                Err(e) => {
                    error!(ctx.log, "Failed to make SSE chunk"; "error" => e.to_string());
                    sender.abort();
                    break;
                }
            };
            match block_on(sender.send_data(chunk)) {
                Err(e) if e.is_closed() => break,
                Err(e) => error!(ctx.log, "Couldn't stream piece {:?}", e),
                Ok(_) => (),
            }
        }
    });
    Ok(body)
}

/// HTTP handler to which accepts a query string of a list of validator pubkeys and maps it to a
/// `ValidatorResponse`.
///
/// This method is limited to as many `pubkeys` that can fit in a URL. See `post_validators` for
/// doing bulk requests.
pub fn get_validators<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<Vec<ValidatorResponse>, ApiError> {
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

    validator_responses_by_pubkey(&ctx.beacon_chain, state_root_opt, validator_pubkeys)
}

/// HTTP handler to return all validators, each as a `ValidatorResponse`.
pub fn get_all_validators<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<Vec<ValidatorResponse>, ApiError> {
    let query = UrlQuery::from_request(&req)?;

    let state_root_opt = if let Some((_key, value)) = query.first_of_opt(&["state_root"]) {
        Some(parse_root(&value)?)
    } else {
        None
    };

    let mut state = get_state_from_root_opt(&ctx.beacon_chain, state_root_opt)?;

    let validators = state.validators.clone();
    validators
        .iter()
        .map(|validator| validator_response_by_pubkey(&mut state, validator.pubkey.clone()))
        .collect::<Result<Vec<_>, _>>()
}

/// HTTP handler to return all active validators, each as a `ValidatorResponse`.
pub fn get_active_validators<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<Vec<ValidatorResponse>, ApiError> {
    let query = UrlQuery::from_request(&req)?;

    let state_root_opt = if let Some((_key, value)) = query.first_of_opt(&["state_root"]) {
        Some(parse_root(&value)?)
    } else {
        None
    };

    let mut state = get_state_from_root_opt(&ctx.beacon_chain, state_root_opt)?;

    let validators = state.validators.clone();
    let current_epoch = state.current_epoch();

    validators
        .iter()
        .filter(|validator| validator.is_active_at(current_epoch))
        .map(|validator| validator_response_by_pubkey(&mut state, validator.pubkey.clone()))
        .collect::<Result<Vec<_>, _>>()
}

/// HTTP handler to which accepts a `ValidatorRequest` and returns a `ValidatorResponse` for
/// each of the given `pubkeys`. When `state_root` is `None`, the canonical head is used.
///
/// This method allows for a basically unbounded list of `pubkeys`, where as the `get_validators`
/// request is limited by the max number of pubkeys you can fit in a URL.
pub fn post_validators<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<Vec<ValidatorResponse>, ApiError> {
    serde_json::from_slice::<ValidatorRequest>(&req.into_body())
        .map_err(|e| {
            ApiError::BadRequest(format!(
                "Unable to parse JSON into ValidatorRequest: {:?}",
                e
            ))
        })
        .and_then(|bulk_request| {
            validator_responses_by_pubkey(
                &ctx.beacon_chain,
                bulk_request.state_root,
                bulk_request.pubkeys,
            )
        })
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
    beacon_chain: &BeaconChain<T>,
    state_root_opt: Option<Hash256>,
    validator_pubkeys: Vec<PublicKeyBytes>,
) -> Result<Vec<ValidatorResponse>, ApiError> {
    let mut state = get_state_from_root_opt(beacon_chain, state_root_opt)?;

    validator_pubkeys
        .into_iter()
        .map(|validator_pubkey| validator_response_by_pubkey(&mut state, validator_pubkey))
        .collect::<Result<Vec<_>, ApiError>>()
}

/// Maps a `validator_pubkey` to a `ValidatorResponse`, using the given state.
///
/// The provided `state` must have a fully up-to-date pubkey cache.
fn validator_response_by_pubkey<E: EthSpec>(
    state: &mut BeaconState<E>,
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
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<Vec<Committee>, ApiError> {
    let query = UrlQuery::from_request(&req)?;

    let epoch = query.epoch()?;

    let mut state =
        get_state_for_epoch(&ctx.beacon_chain, epoch, StateSkipConfig::WithoutStateRoots)?;

    let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), epoch).map_err(|e| {
        ApiError::ServerError(format!("Failed to get state suitable for epoch: {:?}", e))
    })?;

    state
        .build_committee_cache(relative_epoch, &ctx.beacon_chain.spec)
        .map_err(|e| ApiError::ServerError(format!("Unable to build committee cache: {:?}", e)))?;

    Ok(state
        .get_beacon_committees_at_epoch(relative_epoch)
        .map_err(|e| ApiError::ServerError(format!("Unable to get all committees: {:?}", e)))?
        .into_iter()
        .map(|c| Committee {
            slot: c.slot,
            index: c.index,
            committee: c.committee.to_vec(),
        })
        .collect::<Vec<_>>())
}

/// HTTP handler to return a `BeaconState` at a given `root` or `slot`.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn get_state<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<StateResponse<T::EthSpec>, ApiError> {
    let head_state = ctx.beacon_chain.head()?.beacon_state;

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
        ("slot", value) => state_at_slot(&ctx.beacon_chain, parse_slot(&value)?)?,
        ("root", value) => {
            let root = &parse_root(&value)?;

            let state = ctx
                .beacon_chain
                .store
                .get_state(root, None)?
                .ok_or_else(|| ApiError::NotFound(format!("No state for root: {:?}", root)))?;

            (*root, state)
        }
        _ => return Err(ApiError::ServerError("Unexpected query parameter".into())),
    };

    Ok(StateResponse {
        root,
        beacon_state: state,
    })
}

/// HTTP handler to return a `BeaconState` root at a given `slot`.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn get_state_root<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<Hash256, ApiError> {
    let slot_string = UrlQuery::from_request(&req)?.only_one("slot")?;
    let slot = parse_slot(&slot_string)?;

    state_root_at_slot(&ctx.beacon_chain, slot, StateSkipConfig::WithStateRoots)
}

/// HTTP handler to return a `BeaconState` at the genesis block.
///
/// This is an undocumented convenience method used during testing. For production, simply do a
/// state request at slot 0.
pub fn get_genesis_state<T: BeaconChainTypes>(
    ctx: Arc<Context<T>>,
) -> Result<BeaconState<T::EthSpec>, ApiError> {
    state_at_slot(&ctx.beacon_chain, Slot::new(0)).map(|(_root, state)| state)
}

pub fn proposer_slashing<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<bool, ApiError> {
    let body = req.into_body();

    serde_json::from_slice::<ProposerSlashing>(&body)
        .map_err(|e| format!("Unable to parse JSON into ProposerSlashing: {:?}", e))
        .and_then(move |proposer_slashing| {
            if ctx.beacon_chain.eth1_chain.is_some() {
                let obs_outcome = ctx
                    .beacon_chain
                    .verify_proposer_slashing_for_gossip(proposer_slashing)
                    .map_err(|e| format!("Error while verifying proposer slashing: {:?}", e))?;
                if let ObservationOutcome::New(verified_proposer_slashing) = obs_outcome {
                    ctx.beacon_chain
                        .import_proposer_slashing(verified_proposer_slashing);
                    Ok(())
                } else {
                    Err("Proposer slashing for that validator index already known".into())
                }
            } else {
                Err("Cannot insert proposer slashing on node without Eth1 connection.".to_string())
            }
        })
        .map_err(ApiError::BadRequest)?;

    Ok(true)
}

pub fn attester_slashing<T: BeaconChainTypes>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<T>>,
) -> Result<bool, ApiError> {
    let body = req.into_body();
    serde_json::from_slice::<AttesterSlashing<T::EthSpec>>(&body)
        .map_err(|e| {
            ApiError::BadRequest(format!(
                "Unable to parse JSON into AttesterSlashing: {:?}",
                e
            ))
        })
        .and_then(move |attester_slashing| {
            if ctx.beacon_chain.eth1_chain.is_some() {
                ctx.beacon_chain
                    .verify_attester_slashing_for_gossip(attester_slashing)
                    .map_err(|e| format!("Error while verifying attester slashing: {:?}", e))
                    .and_then(|outcome| {
                        if let ObservationOutcome::New(verified_attester_slashing) = outcome {
                            ctx.beacon_chain
                                .import_attester_slashing(verified_attester_slashing)
                                .map_err(|e| {
                                    format!("Error while importing attester slashing: {:?}", e)
                                })
                        } else {
                            Err("Attester slashing only covers already slashed indices".to_string())
                        }
                    })
                    .map_err(ApiError::BadRequest)
            } else {
                Err(ApiError::BadRequest(
                    "Cannot insert attester slashing on node without Eth1 connection.".to_string(),
                ))
            }
        })?;

    Ok(true)
}
