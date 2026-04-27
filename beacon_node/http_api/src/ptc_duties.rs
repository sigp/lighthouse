//! Contains the handler for the `POST validator/duties/ptc/{epoch}` endpoint.

use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::{self as api_types, PtcDuty};
use slot_clock::SlotClock;
use state_processing::state_advance::partial_state_advance;
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256};

type ApiDuties = api_types::DutiesResponse<Vec<PtcDuty>>;

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

    let is_within_clock_tolerance = request_epoch == current_epoch
        || request_epoch == current_epoch + 1
        || request_epoch == tolerant_current_epoch + 1;

    if is_within_clock_tolerance {
        let head_epoch = chain
            .canonical_head
            .cached_head()
            .snapshot
            .beacon_state
            .current_epoch();

        let head_can_serve_request = request_epoch == head_epoch || request_epoch == head_epoch + 1;

        if head_can_serve_request {
            compute_ptc_duties_from_cached_head(request_epoch, request_indices, chain)
        } else {
            compute_ptc_duties_from_state(request_epoch, request_indices, chain)
        }
    } else if request_epoch > current_epoch + 1 {
        Err(warp_utils::reject::custom_bad_request(format!(
            "request epoch {} is more than one epoch past the current epoch {}",
            request_epoch, current_epoch
        )))
    } else {
        compute_ptc_duties_from_state(request_epoch, request_indices, chain)
    }
}

fn compute_ptc_duties_from_cached_head<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let (cached_head, execution_status) = chain
        .canonical_head
        .head_and_execution_status()
        .map_err(warp_utils::reject::unhandled_error)?;
    let state = &cached_head.snapshot.beacon_state;
    let head_block_root = cached_head.head_block_root();

    let (duties, dependent_root) = chain
        .compute_ptc_duties(state, request_epoch, request_indices, head_block_root)
        .map_err(warp_utils::reject::unhandled_error)?;

    convert_to_api_response(
        duties,
        dependent_root,
        execution_status.is_optimistic_or_invalid(),
    )
}

fn compute_ptc_duties_from_state<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
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

    let (state, execution_optimistic) =
        if let Some((state_root, mut state, execution_optimistic)) = state_opt {
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

    if !(state.current_epoch() == request_epoch || state.current_epoch() + 1 == request_epoch) {
        return Err(warp_utils::reject::custom_server_error(format!(
            "state epoch {} not suitable for request epoch {}",
            state.current_epoch(),
            request_epoch
        )));
    }

    let (duties, dependent_root) = chain
        .compute_ptc_duties(
            &state,
            request_epoch,
            request_indices,
            chain.genesis_block_root,
        )
        .map_err(warp_utils::reject::unhandled_error)?;

    convert_to_api_response(duties, dependent_root, execution_optimistic)
}

fn ensure_state_knows_ptc_duties_for_epoch<E: EthSpec>(
    state: &mut BeaconState<E>,
    state_root: Hash256,
    target_epoch: Epoch,
    spec: &ChainSpec,
) -> Result<(), warp::reject::Rejection> {
    if state.current_epoch() > target_epoch {
        return Err(warp_utils::reject::custom_server_error(format!(
            "state epoch {} is later than target epoch {}",
            state.current_epoch(),
            target_epoch
        )));
    } else if state.current_epoch() + 1 < target_epoch {
        let target_slot = target_epoch
            .saturating_sub(1_u64)
            .start_slot(E::slots_per_epoch());

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
    Ok(api_types::DutiesResponse {
        dependent_root,
        execution_optimistic: Some(execution_optimistic),
        data: duties.into_iter().flatten().collect(),
    })
}
