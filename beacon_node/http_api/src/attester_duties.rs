//! Contains the handler for the `GET validator/duties/attester/{epoch}` endpoint.

use crate::state_id::StateId;
use beacon_chain::{
    BeaconChain, BeaconChainError, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
};
use eth2::types::{self as api_types};
use slot_clock::SlotClock;
use state_processing::state_advance::partial_state_advance;
use types::{
    AttestationDuty, BeaconState, ChainSpec, CloneConfig, Epoch, EthSpec, Hash256, RelativeEpoch,
};

/// The struct that is returned to the requesting HTTP client.
type ApiDuties = api_types::DutiesResponse<Vec<api_types::AttesterData>>;

/// Handles a request from the HTTP API for attester duties.
pub fn attester_duties<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
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

    if request_epoch == current_epoch
        || request_epoch == tolerant_current_epoch
        || request_epoch == current_epoch + 1
        || request_epoch == tolerant_current_epoch + 1
    {
        cached_attestation_duties(request_epoch, request_indices, chain)
    } else if request_epoch > current_epoch + 1 {
        Err(warp_utils::reject::custom_bad_request(format!(
            "request epoch {} is more than one epoch past the current epoch {}",
            request_epoch, current_epoch
        )))
    } else {
        // request_epoch < current_epoch
        compute_historic_attester_duties(request_epoch, request_indices, chain)
    }
}

fn cached_attestation_duties<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let head_block_root = chain.canonical_head.cached_head().head_block_root();

    let (duties, dependent_root, execution_status) = chain
        .validator_attestation_duties(request_indices, request_epoch, head_block_root)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    convert_to_api_response(
        duties,
        request_indices,
        dependent_root,
        execution_status.is_optimistic_or_invalid(),
        chain,
    )
}

/// Compute some attester duties by reading a `BeaconState` from disk, completely ignoring the
/// shuffling cache.
fn compute_historic_attester_duties<T: BeaconChainTypes>(
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
            .map_err(warp_utils::reject::beacon_chain_error)?;
        let head = &cached_head.snapshot;

        if head.beacon_state.current_epoch() <= request_epoch {
            Some((
                head.beacon_state_root(),
                head.beacon_state
                    .clone_with(CloneConfig::committee_caches_only()),
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
            ensure_state_knows_attester_duties_for_epoch(
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
        .map_err(warp_utils::reject::beacon_chain_error)?;

    let dependent_root = state
        // The only block which decides its own shuffling is the genesis block.
        .attester_shuffling_decision_root(chain.genesis_block_root, relative_epoch)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    let duties = request_indices
        .iter()
        .map(|&validator_index| {
            state
                .get_attestation_duties(validator_index as usize, relative_epoch)
                .map_err(BeaconChainError::from)
        })
        .collect::<Result<_, _>>()
        .map_err(warp_utils::reject::beacon_chain_error)?;

    convert_to_api_response(
        duties,
        request_indices,
        dependent_root,
        execution_optimistic,
        chain,
    )
}

fn ensure_state_knows_attester_duties_for_epoch<E: EthSpec>(
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
        // Since there's a one-epoch look-head on attester duties, it suffices to only advance to
        // the prior epoch.
        let target_slot = target_epoch
            .saturating_sub(1_u64)
            .start_slot(E::slots_per_epoch());

        // A "partial" state advance is adequate since attester duties don't rely on state roots.
        partial_state_advance(state, Some(state_root), target_slot, spec)
            .map_err(BeaconChainError::from)
            .map_err(warp_utils::reject::beacon_chain_error)?;
    }

    Ok(())
}

/// Convert the internal representation of attester duties into the format returned to the HTTP
/// client.
fn convert_to_api_response<T: BeaconChainTypes>(
    duties: Vec<Option<AttestationDuty>>,
    indices: &[u64],
    dependent_root: Hash256,
    execution_optimistic: bool,
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    // Protect against an inconsistent slot clock.
    if duties.len() != indices.len() {
        return Err(warp_utils::reject::custom_server_error(format!(
            "duties length {} does not match indices length {}",
            duties.len(),
            indices.len()
        )));
    }

    let usize_indices = indices.iter().map(|i| *i as usize).collect::<Vec<_>>();
    let index_to_pubkey_map = chain
        .validator_pubkey_bytes_many(&usize_indices)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    let data = duties
        .into_iter()
        .zip(indices)
        .filter_map(|(duty_opt, &validator_index)| {
            let duty = duty_opt?;
            Some(api_types::AttesterData {
                pubkey: *index_to_pubkey_map.get(&(validator_index as usize))?,
                validator_index,
                committees_at_slot: duty.committees_at_slot,
                committee_index: duty.index,
                committee_length: duty.committee_len as u64,
                validator_committee_index: duty.committee_position as u64,
                slot: duty.slot,
            })
        })
        .collect::<Vec<_>>();

    Ok(api_types::DutiesResponse {
        dependent_root,
        execution_optimistic: Some(execution_optimistic),
        data,
    })
}
