//! Contains the handler for the `GET validator/duties/proposer/{epoch}` endpoint.

use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::{self as api_types};
use slog::{debug, Logger};
use state_processing::per_slot_processing;
use std::cmp::Ordering;
use types::{Epoch, EthSpec, Hash256, Slot};

/// The struct that is returned to the requesting HTTP client.
type ApiDuties = api_types::DutiesResponse<Vec<api_types::ProposerData>>;

/// Handles a request from the HTTP API for proposer duties.
pub fn proposer_duties<T: BeaconChainTypes>(
    epoch: Epoch,
    chain: &BeaconChain<T>,
    log: &Logger,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let current_epoch = chain
        .epoch()
        .map_err(warp_utils::reject::beacon_chain_error)?;

    match epoch.cmp(&current_epoch) {
        // Reject queries about the future since they're very expensive and we can only speculate
        // about the result since there's no look-ahead on proposer duties.
        Ordering::Greater => Err(warp_utils::reject::custom_bad_request(format!(
            "request epoch {} is ahead of the current epoch {}",
            epoch, current_epoch
        ))),
        // Queries about the current epoch should attempt to find the value in the cache. If it
        // can't be found, it should be computed and then stored in the cache for future gains.
        Ordering::Equal => {
            if let Some(duties) = try_proposer_duties_from_cache(epoch, chain)? {
                Ok(duties)
            } else {
                debug!(
                    log,
                    "Proposer cache miss";
                    "request_epoch" =>  epoch,
                );
                compute_and_cache_proposer_duties(epoch, chain)
            }
        }
        // Queries about the past are handled with a slow path.
        Ordering::Less => compute_historic_proposer_duties(epoch, chain),
    }
}

/// Attempt to load the proposer duties from the `chain.beacon_proposer_cache`, returning `Ok(None)`
/// if there is a cache miss.
///
/// ## Notes
///
/// The `current_epoch` value should equal the current epoch on the slot clock, otherwise we risk
/// washing out the proposer cache at the expense of block processing.
fn try_proposer_duties_from_cache<T: BeaconChainTypes>(
    current_epoch: Epoch,
    chain: &BeaconChain<T>,
) -> Result<Option<ApiDuties>, warp::reject::Rejection> {
    let head = chain
        .head_info()
        .map_err(warp_utils::reject::beacon_chain_error)?;
    let head_epoch = head.slot.epoch(T::EthSpec::slots_per_epoch());

    let dependent_root = match head_epoch.cmp(&current_epoch) {
        Ordering::Equal => head.proposer_shuffling_decision_root,
        Ordering::Less => head.block_root,
        Ordering::Greater => {
            return Err(warp_utils::reject::custom_server_error(format!(
                "head epoch {} is later than current epoch {}",
                head_epoch, current_epoch
            )))
        }
    };

    let indices_opt = chain
        .beacon_proposer_cache
        .lock()
        .get_epoch::<T::EthSpec>(dependent_root, current_epoch)
        .cloned();

    if let Some(indices) = indices_opt {
        Ok(Some(api_duties(
            chain,
            current_epoch,
            dependent_root,
            indices.to_vec(),
        )?))
    } else {
        Ok(None)
    }
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
    let head_block_root = head.beacon_block_root;
    let head_block_slot = head.beacon_block.slot();
    let head_state_root = head.beacon_block.state_root();

    // Protect against an inconsistent slot clock.
    if state.current_epoch() > current_epoch {
        return Err(warp_utils::reject::custom_server_error(format!(
            "state epoch {} is later than current epoch {}",
            state.current_epoch(),
            current_epoch
        )));
    }

    // Advance the state into the requested epoch.
    while state.current_epoch() < current_epoch {
        let state_root_opt = if state.slot == head_block_slot {
            Some(head_state_root)
        } else {
            // Don't calculate state roots since they aren't required for calculating
            // shuffling (achieved by providing Hash256::zero()).
            Some(Hash256::zero())
        };

        per_slot_processing(&mut state, state_root_opt, &chain.spec)
            .map_err(BeaconChainError::from)
            .map_err(warp_utils::reject::beacon_chain_error)?;
    }

    let indices = state
        .get_beacon_proposer_indices(&chain.spec)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    // The dependent root along with the current epoch can be used to uniquely
    // identify this proposer shuffling.
    let dependent_slot = state.proposer_shuffling_decision_slot();
    let dependent_root = if dependent_slot == head_block_slot {
        head_block_root
    } else {
        *state
            .get_block_root(dependent_slot)
            .map_err(BeaconChainError::from)
            .map_err(warp_utils::reject::beacon_chain_error)?
    };

    // Prime the proposer shuffling cache with the newly-learned value.
    chain
        .beacon_proposer_cache
        .lock()
        .insert(
            state.current_epoch(),
            dependent_root,
            indices.clone(),
            state.fork,
        )
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    api_duties(chain, current_epoch, dependent_root, indices)
}

/// Compute some proposer duties by reading a `BeaconState` from disk, completely ignoring the
/// `beacon_proposer_cache`.
fn compute_historic_proposer_duties<T: BeaconChainTypes>(
    epoch: Epoch,
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let state = StateId::slot(epoch.start_slot(T::EthSpec::slots_per_epoch())).state(&chain)?;

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

    let dependent_slot = state.proposer_shuffling_decision_slot();
    // Since the decision slot is one prior to the current epoch it should
    // always be in the block roots array (making some assumptions about the
    // spec constants).
    let dependent_root = *state
        .get_block_root(dependent_slot)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    api_duties(chain, epoch, dependent_root, indices)
}

/// Converts the internal representation of proposer duties into one that is compatible with the
/// standard API.
///
/// ## Notes
///
/// The `chain.validator_pubkey_cache` is used to convert validator indices into pubkeys.
fn api_duties<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    epoch: Epoch,
    dependent_root: Hash256,
    indices: Vec<usize>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    // Map our internal data structure into the API structure.
    let proposer_data = indices
        .into_iter()
        .enumerate()
        .map(|(i, validator_index)| {
            // Use the pubkey cache on the beacon chain to resolve the validator
            // indices to pubkeys.
            let pubkey = chain
                .validator_pubkey_bytes(validator_index)
                .map_err(warp_utils::reject::beacon_chain_error)?
                .ok_or_else(|| {
                    warp_utils::reject::custom_server_error(format!(
                        "unable to resolve validator index {}",
                        i
                    ))
                })?;

            // Offset the index in `indices` to determine the slot for which these
            // duties apply.
            let slot = epoch.start_slot(T::EthSpec::slots_per_epoch()) + Slot::from(i);

            Ok(api_types::ProposerData {
                pubkey,
                validator_index: validator_index as u64,
                slot,
            })
        })
        .collect::<Result<Vec<_>, warp::reject::Rejection>>()?;

    Ok(api_types::DutiesResponse {
        dependent_root,
        data: proposer_data,
    })
}
