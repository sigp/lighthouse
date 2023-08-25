use crate::StateId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use safe_arith::SafeArith;
use state_processing::per_block_processing::get_expected_withdrawals;
use state_processing::state_advance::partial_state_advance;
use std::sync::Arc;
use types::{BeaconState, EthSpec, ForkName, Slot, Withdrawals};

const MAX_EPOCH_LOOKAHEAD: u64 = 2;

/// Get the withdrawals computed from the specified state, that will be included in the block
/// that gets built on the specified state.
pub fn get_next_withdrawals<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    mut state: BeaconState<T::EthSpec>,
    state_id: StateId,
    proposal_slot: Slot,
) -> Result<Withdrawals<T::EthSpec>, warp::Rejection> {
    get_next_withdrawals_sanity_checks(chain, &state, proposal_slot)?;

    // advance the state to the epoch of the proposal slot.
    let proposal_epoch = proposal_slot.epoch(T::EthSpec::slots_per_epoch());
    let (state_root, _, _) = state_id.root(chain)?;
    if proposal_epoch != state.current_epoch() {
        if let Err(e) =
            partial_state_advance(&mut state, Some(state_root), proposal_slot, &chain.spec)
        {
            return Err(warp_utils::reject::custom_server_error(format!(
                "failed to advance to the epoch of the proposal slot: {:?}",
                e
            )));
        }
    }

    match get_expected_withdrawals(&state, &chain.spec) {
        Ok(withdrawals) => Ok(withdrawals),
        Err(e) => Err(warp_utils::reject::custom_server_error(format!(
            "failed to get expected withdrawal: {:?}",
            e
        ))),
    }
}

fn get_next_withdrawals_sanity_checks<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    proposal_slot: Slot,
) -> Result<(), warp::Rejection> {
    if proposal_slot <= state.slot() {
        return Err(warp_utils::reject::custom_bad_request(
            "proposal slot must be greater than the pre-state slot".to_string(),
        ));
    }

    let fork = chain.spec.fork_name_at_slot::<T::EthSpec>(proposal_slot);
    if let ForkName::Base | ForkName::Altair | ForkName::Merge = fork {
        return Err(warp_utils::reject::custom_bad_request(
            "the specified state is a pre-capella state.".to_string(),
        ));
    }

    let look_ahead_limit = MAX_EPOCH_LOOKAHEAD
        .safe_mul(T::EthSpec::slots_per_epoch())
        .map_err(warp_utils::reject::arith_error)?;
    if proposal_slot >= state.slot() + look_ahead_limit {
        return Err(warp_utils::reject::custom_bad_request(format!(
            "proposal slot is greater than or equal to the look ahead limit: {look_ahead_limit}"
        )));
    }

    Ok(())
}
