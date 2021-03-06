//! Contains the handler for the `GET validator/duties/attester/{epoch}` endpoint.

use crate::state_id::StateId;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::{self as api_types};
use state_processing::per_slot_processing;
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
    let next_epoch = current_epoch + 1;

    if request_epoch > next_epoch {
        Err(warp_utils::reject::custom_bad_request(format!(
            "request epoch {} is more than one epoch past the current epoch {}",
            request_epoch, current_epoch
        )))
    } else if request_epoch == current_epoch || request_epoch == next_epoch {
        cached_attestation_duties(request_epoch, request_indices, chain)
    } else {
        compute_historic_attester_duties(request_epoch, request_indices, chain)
    }
}

fn cached_attestation_duties<T: BeaconChainTypes>(
    epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    let head = chain
        .head_info()
        .map_err(warp_utils::reject::beacon_chain_error)?;

    let (duties, dependent_root) = chain
        .validator_attestation_duties(&request_indices, epoch, head.block_root)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    api_duties(duties, request_indices, dependent_root, chain)
}

/// Compute some attester duties by reading a `BeaconState` from disk, completely ignoring the
/// shuffling cache.
fn compute_historic_attester_duties<T: BeaconChainTypes>(
    epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<ApiDuties, warp::reject::Rejection> {
    // It's possible that `epoch` is "historical" (i.e., early than the current epoch) but still
    // later than the head.
    let state_opt = chain
        .with_head(|head| {
            if head.beacon_state.current_epoch() < epoch {
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

    let mut state = if let Some((state_root, mut state)) = state_opt {
        // If we've loaded the head state it might be from a previous epoch, ensure it's in a
        // suitable epoch.
        ensure_state_knows_duties_for_epoch(&mut state, state_root, epoch, &chain.spec)?;
        state
    } else {
        StateId::slot(epoch.start_slot(T::EthSpec::slots_per_epoch())).state(&chain)?
    };

    // Ensure the state lookup was correct.
    if state.current_epoch() == epoch || state.current_epoch() + 1 == epoch {
        return Err(warp_utils::reject::custom_server_error(format!(
            "state epoch {} not suitable for request epoch {}",
            state.current_epoch(),
            epoch
        )));
    }

    let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), epoch).map_err(|e| {
        warp_utils::reject::custom_server_error(format!("invalid epoch for state: {:?}", e))
    })?;

    state
        .build_committee_cache(relative_epoch, &chain.spec)
        .map_err(BeaconChainError::from)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    let dependent_slot = state.attester_shuffling_decision_slot(relative_epoch);
    let dependent_root = if state.slot == dependent_slot {
        // The only scenario where this can be true is when there is no prior epoch to the current.
        // In that case, the genesis block decides the shuffling root.
        chain.genesis_block_root
    } else {
        *state
            .get_block_root(dependent_slot)
            .map_err(BeaconChainError::from)
            .map_err(warp_utils::reject::beacon_chain_error)?
    };

    let duties = request_indices
        .iter()
        .map(|&validator_index| {
            state
                .get_attestation_duties(validator_index as usize, relative_epoch)
                .map_err(BeaconChainError::from)
        })
        .collect::<Result<_, _>>()
        .map_err(warp_utils::reject::beacon_chain_error)?;

    api_duties(duties, request_indices, dependent_root, chain)
}

fn ensure_state_knows_duties_for_epoch<E: EthSpec>(
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
    }

    let mut state_root_opt = Some(state_root);

    // Advance the state into the requested epoch.
    while state.current_epoch() < target_epoch - 1 {
        // Don't calculate state roots since they aren't required for calculating
        // shuffling (achieved by using `state_root_opt.take()`).
        per_slot_processing(state, state_root_opt.take(), spec)
            .map_err(BeaconChainError::from)
            .map_err(warp_utils::reject::beacon_chain_error)?;
    }

    Ok(())
}

fn api_duties<T: BeaconChainTypes>(
    duties: Vec<Option<AttestationDuty>>,
    indices: &[u64],
    dependent_root: Hash256,
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
        data,
    })
}
