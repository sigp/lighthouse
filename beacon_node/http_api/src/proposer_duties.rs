//! Contains the handler for the `GET validator/duties/proposer/{epoch}` endpoint.

use crate::state_id::StateId;
use beacon_chain::{
    BeaconChain, BeaconChainError, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
};
use eth2::types::{self as api_types};
use slog::{debug, Logger};
use slot_clock::SlotClock;
use state_processing::state_advance::partial_state_advance;
use std::cmp::Ordering;
use types::{BeaconState, ChainSpec, CloneConfig, Epoch, EthSpec, Hash256, Slot};

/// The struct that is returned to the requesting HTTP client.
type ApiDuties = api_types::DutiesResponse<Vec<api_types::ProposerData>>;

/// Handles a request from the HTTP API for proposer duties.
pub fn proposer_duties<T: BeaconChainTypes>(
    request_epoch: Epoch,
    chain: &BeaconChain<T>,
    log: &Logger,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let current_epoch = chain
        .epoch()
        .map_err(warp_utils::reject::beacon_chain_error)?;

    // Determine what the current epoch would be if we fast-forward our system clock by
    // `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
    //
    // Most of the time, `tolerant_current_epoch` will be equal to `current_epoch`. However, during
    // the first `MAXIMUM_GOSSIP_CLOCK_DISPARITY` duration of the epoch `tolerant_current_epoch`
    // will equal `current_epoch + 1`
    let tolerant_current_epoch = chain
        .slot_clock
        .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or_else(|| warp_utils::reject::custom_server_error("unable to read slot clock".into()))?
        .epoch(T::EthSpec::slots_per_epoch());

    if request_epoch == current_epoch || request_epoch == tolerant_current_epoch {
        // If we could consider ourselves in the `request_epoch` when allowing for clock disparity
        // tolerance then serve this request from the cache.
        if let Some(duties) = try_proposer_duties_from_cache(request_epoch, chain)? {
            Ok(duties)
        } else {
            debug!(
                log,
                "Proposer cache miss";
                "request_epoch" =>  request_epoch,
            );
            compute_and_cache_proposer_duties(request_epoch, chain)
        }
    } else if request_epoch > current_epoch {
        // Reject queries about the future as they're very expensive there's no look-ahead for
        // proposer duties.
        Err(warp_utils::reject::custom_bad_request(format!(
            "request epoch {} is ahead of the current epoch {}",
            request_epoch, current_epoch
        )))
    } else {
        // request_epoch < current_epoch
        //
        // Queries about the past are handled with a slow path.
        compute_historic_proposer_duties(request_epoch, chain)
    }
}

/// Attempt to load the proposer duties from the `chain.beacon_proposer_cache`, returning `Ok(None)`
/// if there is a cache miss.
///
/// ## Notes
///
/// The `current_epoch` value should equal the current epoch on the slot clock (with some
/// tolerance), otherwise we risk washing out the proposer cache at the expense of block processing.
fn try_proposer_duties_from_cache<T: BeaconChainTypes>(
    request_epoch: Epoch,
    chain: &BeaconChain<T>,
) -> Result<Option<ApiDuties>, warp::reject::Rejection> {
    let head = chain
        .head_info()
        .map_err(warp_utils::reject::beacon_chain_error)?;
    let head_epoch = head.slot.epoch(T::EthSpec::slots_per_epoch());

    let dependent_root = match head_epoch.cmp(&request_epoch) {
        // head_epoch == request_epoch
        Ordering::Equal => head.proposer_shuffling_decision_root,
        // head_epoch < request_epoch
        Ordering::Less => head.block_root,
        // head_epoch > request_epoch
        Ordering::Greater => {
            return Err(warp_utils::reject::custom_server_error(format!(
                "head epoch {} is later than request epoch {}",
                head_epoch, request_epoch
            )))
        }
    };

    chain
        .beacon_proposer_cache
        .lock()
        .get_epoch::<T::EthSpec>(dependent_root, request_epoch)
        .cloned()
        .map(|indices| {
            convert_to_api_response(chain, request_epoch, dependent_root, indices.to_vec())
        })
        .transpose()
}

/// Compute the proposer duties using the head state, add the duties to the proposer cache and
/// return the proposers.
///
/// This method does *not* attempt to read the values from the cache before computing them. See
/// `try_proposer_duties_from_cache` to read values.
///
/// ## Notes
///
/// The `current_epoch` value should equal the current epoch on the slot clock, otherwise we risk
/// washing out the proposer cache at the expense of block processing.
fn compute_and_cache_proposer_duties<T: BeaconChainTypes>(
    current_epoch: Epoch,
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    // Take a copy of the head of the chain.
    let head = chain
        .head()
        .map_err(warp_utils::reject::beacon_chain_error)?;
    let mut state = head.beacon_state;
    let head_state_root = head.beacon_block.state_root();

    // Advance the state into the requested epoch.
    ensure_state_is_in_epoch(&mut state, head_state_root, current_epoch, &chain.spec)?;

    let indices = state
        .get_beacon_proposer_indices(&chain.spec)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    let dependent_root = state
        // The only block which decides its own shuffling is the genesis block.
        .proposer_shuffling_decision_root(chain.genesis_block_root)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    // Prime the proposer shuffling cache with the newly-learned value.
    chain
        .beacon_proposer_cache
        .lock()
        .insert(
            state.current_epoch(),
            dependent_root,
            indices.clone(),
            state.fork(),
        )
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    convert_to_api_response(chain, current_epoch, dependent_root, indices)
}

/// Compute some proposer duties by reading a `BeaconState` from disk, completely ignoring the
/// `beacon_proposer_cache`.
fn compute_historic_proposer_duties<T: BeaconChainTypes>(
    epoch: Epoch,
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    // If the head is quite old then it might still be relevant for a historical request.
    //
    // Use the `with_head` function to read & clone in a single call to avoid race conditions.
    let state_opt = chain
        .with_head(|head| {
            if head.beacon_state.current_epoch() <= epoch {
                Ok(Some((
                    head.beacon_state_root(),
                    head.beacon_state
                        .clone_with(CloneConfig::committee_caches_only()),
                )))
            } else {
                Ok(None)
            }
        })
        .map_err(warp_utils::reject::beacon_chain_error)?;

    let state = if let Some((state_root, mut state)) = state_opt {
        // If we've loaded the head state it might be from a previous epoch, ensure it's in a
        // suitable epoch.
        ensure_state_is_in_epoch(&mut state, state_root, epoch, &chain.spec)?;
        state
    } else {
        StateId::slot(epoch.start_slot(T::EthSpec::slots_per_epoch())).state(chain)?
    };

    // Ensure the state lookup was correct.
    if state.current_epoch() != epoch {
        return Err(warp_utils::reject::custom_server_error(format!(
            "state epoch {} not equal to request epoch {}",
            state.current_epoch(),
            epoch
        )));
    }

    let indices = state
        .get_beacon_proposer_indices(&chain.spec)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    // We can supply the genesis block root as the block root since we know that the only block that
    // decides its own root is the genesis block.
    let dependent_root = state
        .proposer_shuffling_decision_root(chain.genesis_block_root)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    convert_to_api_response(chain, epoch, dependent_root, indices)
}

/// If required, advance `state` to `target_epoch`.
///
/// ## Details
///
/// - Returns an error if `state.current_epoch() > target_epoch`.
/// - No-op if `state.current_epoch() == target_epoch`.
/// - It must be the case that `state.canonical_root() == state_root`, but this function will not
///     check that.
fn ensure_state_is_in_epoch<E: EthSpec>(
    state: &mut BeaconState<E>,
    state_root: Hash256,
    target_epoch: Epoch,
    spec: &ChainSpec,
) -> Result<(), warp::reject::Rejection> {
    match state.current_epoch().cmp(&target_epoch) {
        // Protects against an inconsistent slot clock.
        Ordering::Greater => Err(warp_utils::reject::custom_server_error(format!(
            "state epoch {} is later than target epoch {}",
            state.current_epoch(),
            target_epoch
        ))),
        // The state needs to be advanced.
        Ordering::Less => {
            let target_slot = target_epoch.start_slot(E::slots_per_epoch());
            partial_state_advance(state, Some(state_root), target_slot, spec)
                .map_err(BeaconChainError::from)
                .map_err(warp_utils::reject::beacon_chain_error)
        }
        // The state is suitable, nothing to do.
        Ordering::Equal => Ok(()),
    }
}

/// Converts the internal representation of proposer duties into one that is compatible with the
/// standard API.
fn convert_to_api_response<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    epoch: Epoch,
    dependent_root: Hash256,
    indices: Vec<usize>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let index_to_pubkey_map = chain
        .validator_pubkey_bytes_many(&indices)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    // Map our internal data structure into the API structure.
    let proposer_data = indices
        .iter()
        .enumerate()
        .filter_map(|(i, &validator_index)| {
            // Offset the index in `indices` to determine the slot for which these
            // duties apply.
            let slot = epoch.start_slot(T::EthSpec::slots_per_epoch()) + Slot::from(i);

            Some(api_types::ProposerData {
                pubkey: *index_to_pubkey_map.get(&validator_index)?,
                validator_index: validator_index as u64,
                slot,
            })
        })
        .collect::<Vec<_>>();

    // Consistency check.
    let slots_per_epoch = T::EthSpec::slots_per_epoch() as usize;
    if proposer_data.len() != slots_per_epoch {
        Err(warp_utils::reject::custom_server_error(format!(
            "{} proposers is not enough for {} slots",
            proposer_data.len(),
            slots_per_epoch,
        )))
    } else {
        Ok(api_types::DutiesResponse {
            dependent_root,
            data: proposer_data,
        })
    }
}
