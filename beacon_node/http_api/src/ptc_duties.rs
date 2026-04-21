//! Contains the handler for the `POST validator/duties/ptc/{epoch}` endpoint.

use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::{self as api_types, PtcDuty};
use slot_clock::SlotClock;
use state_processing::state_advance::partial_state_advance;
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256, RelativeEpoch};

/// The struct that is returned to the requesting HTTP client.
type ApiDuties = api_types::DutiesResponse<Vec<PtcDuty>>;

/// Handles a request from the HTTP API for PTC duties.
pub fn ptc_duties<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let current_epoch = chain
        .slot_clock
        .now_or_genesis()
        .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
        .ok_or(BeaconChainError::UnableToReadSlot)
        .map_err(warp_utils::reject::unhandled_error)?;

    // Determine what the current epoch would be if we fast-forward our system clock by
    // `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
    //
    // Most of the time, `tolerant_current_epoch` will be equal to `current_epoch`. However, during
    // the first `MAXIMUM_GOSSIP_CLOCK_DISPARITY` duration of the epoch `tolerant_current_epoch`
    // will equal `current_epoch + 1`
    let tolerant_current_epoch = if chain.slot_clock.is_prior_to_genesis().unwrap_or(true) {
        current_epoch
    } else {
        chain
            .slot_clock
            .now_with_future_tolerance(chain.spec.maximum_gossip_clock_disparity())
            .ok_or_else(|| {
                warp_utils::reject::custom_server_error("unable to read slot clock".into())
            })?
            .epoch(T::EthSpec::slots_per_epoch())
    };

    // Check if the request is within acceptable clock tolerance
    let is_within_clock_tolerance = request_epoch == current_epoch
        || request_epoch == current_epoch + 1
        || request_epoch == tolerant_current_epoch + 1;

    if is_within_clock_tolerance {
        // Get the head state epoch
        let head_epoch = chain
            .canonical_head
            .cached_head()
            .snapshot
            .beacon_state
            .current_epoch();

        // Check if the head state can compute duties for this epoch (current or next epoch only)
        let head_can_serve_request = request_epoch == head_epoch || request_epoch == head_epoch + 1;

        if head_can_serve_request {
            compute_ptc_duties_from_head(request_epoch, request_indices, chain)
        } else {
            // Within tolerance but head is lagging
            compute_ptc_duties_from_state(request_epoch, request_indices, chain)
        }
    } else if request_epoch > current_epoch + 1 {
        Err(warp_utils::reject::custom_bad_request(format!(
            "request epoch {} is more than one epoch past the current epoch {}",
            request_epoch, current_epoch
        )))
    } else {
        // request_epoch < current_epoch (historic request)
        compute_ptc_duties_from_state(request_epoch, request_indices, chain)
    }
}

fn compute_ptc_duties_from_head<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let (mut state, execution_optimistic, head_block_root) = {
        let (cached_head, execution_status) = chain
            .canonical_head
            .head_and_execution_status()
            .map_err(warp_utils::reject::unhandled_error)?;
        let head = &cached_head.snapshot;
        (
            head.beacon_state.clone(),
            execution_status.is_optimistic_or_invalid(),
            cached_head.head_block_root(),
        )
    };

    let relative_epoch =
        RelativeEpoch::from_epoch(state.current_epoch(), request_epoch).map_err(|e| {
            warp_utils::reject::custom_server_error(format!("invalid epoch for state: {:?}", e))
        })?;

    state
        .build_committee_cache(relative_epoch, &chain.spec)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::unhandled_error)?;

    let dependent_root = state
        .attester_shuffling_decision_root(head_block_root, relative_epoch)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::unhandled_error)?;

    let duties = compute_duties(&state, request_epoch, request_indices, chain)?;

    convert_to_api_response(duties, dependent_root, execution_optimistic)
}

/// Compute PTC duties by reading a `BeaconState` from disk, building the committee cache
fn compute_ptc_duties_from_state<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    // If the head is quite old then it might still be relevant for a historical request.
    //
    // Avoid holding the `cached_head` longer than necessary.
    let state_opt = {
        let (cached_head, execution_status) = chain
            .canonical_head
            .head_and_execution_status()
            .map_err(warp_utils::reject::unhandled_error)?;
        let head = &cached_head.snapshot;

        if head.beacon_state.current_epoch() <= request_epoch {
            Some((
                head.beacon_state_root(),
                head.beacon_state.clone(),
                execution_status.is_optimistic_or_invalid(),
            ))
        } else {
            None
        }
    };

    let (mut state, execution_optimistic) =
        if let Some((state_root, mut state, execution_optimistic)) = state_opt {
            // If we've loaded the head state it might be from a previous epoch, ensure it's in a
            // suitable epoch.
            ensure_state_knows_ptc_duties_for_epoch(
                &mut state,
                state_root,
                request_epoch,
                &chain.spec,
            )?;
            (state, execution_optimistic)
        } else {
            let (state, execution_optimistic, _finalized) =
                StateId::from_slot(request_epoch.start_slot(T::EthSpec::slots_per_epoch()))
                    .state(chain)?;
            (state, execution_optimistic)
        };

    // Sanity-check the state lookup.
    if !(state.current_epoch() == request_epoch || state.current_epoch() + 1 == request_epoch) {
        return Err(warp_utils::reject::custom_server_error(format!(
            "state epoch {} not suitable for request epoch {}",
            state.current_epoch(),
            request_epoch
        )));
    }

    let relative_epoch =
        RelativeEpoch::from_epoch(state.current_epoch(), request_epoch).map_err(|e| {
            warp_utils::reject::custom_server_error(format!("invalid epoch for state: {:?}", e))
        })?;

    state
        .build_committee_cache(relative_epoch, &chain.spec)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::unhandled_error)?;

    let dependent_root = state
        .attester_shuffling_decision_root(chain.genesis_block_root, relative_epoch)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::unhandled_error)?;

    let duties = compute_duties(&state, request_epoch, request_indices, chain)?;

    convert_to_api_response(duties, dependent_root, execution_optimistic)
}

fn compute_duties<T: BeaconChainTypes>(
    state: &BeaconState<T::EthSpec>,
    epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<Vec<Option<PtcDuty>>, warp::reject::Rejection> {
    let usize_indices = request_indices
        .iter()
        .map(|i| *i as usize)
        .collect::<Vec<_>>();
    let index_to_pubkey_map = chain
        .validator_pubkey_bytes_many(&usize_indices)
        .map_err(warp_utils::reject::unhandled_error)?;

    request_indices
        .iter()
        .map(
            |&validator_index| -> Result<Option<PtcDuty>, warp::reject::Rejection> {
                let pubkey = match index_to_pubkey_map.get(&(validator_index as usize)) {
                    Some(pk) => *pk,
                    None => return Ok(None),
                };

                let slot_opt = state
                    .get_ptc_assignment(validator_index as usize, epoch, &chain.spec)
                    .map_err(warp_utils::reject::unhandled_error)?;

                Ok(slot_opt.map(|slot| PtcDuty {
                    validator_index,
                    slot,
                    pubkey,
                }))
            },
        )
        .collect()
}

fn ensure_state_knows_ptc_duties_for_epoch<E: EthSpec>(
    state: &mut BeaconState<E>,
    state_root: Hash256,
    target_epoch: Epoch,
    spec: &ChainSpec,
) -> Result<(), warp::reject::Rejection> {
    // Protect against an inconsistent slot clock.
    if state.current_epoch() > target_epoch {
        return Err(warp_utils::reject::custom_server_error(format!(
            "state epoch {} is later than target epoch {}",
            state.current_epoch(),
            target_epoch
        )));
    } else if state.current_epoch() + 1 < target_epoch {
        // Since there's a one-epoch look-ahead on PTC duties, it suffices to only advance to
        // the prior epoch.
        let target_slot = target_epoch
            .saturating_sub(1_u64)
            .start_slot(E::slots_per_epoch());

        // A "partial" state advance is adequate since PTC duties don't rely on state roots.
        partial_state_advance(state, Some(state_root), target_slot, spec)
            .map_err(BeaconChainError::from)
            .map_err(warp_utils::reject::unhandled_error)?;
    }

    Ok(())
}

fn convert_to_api_response(
    duties: Vec<Option<PtcDuty>>,
    dependent_root: Hash256,
    execution_optimistic: bool,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let data = duties.into_iter().flatten().collect::<Vec<_>>();

    Ok(api_types::DutiesResponse {
        dependent_root,
        execution_optimistic: Some(execution_optimistic),
        data,
    })
}
