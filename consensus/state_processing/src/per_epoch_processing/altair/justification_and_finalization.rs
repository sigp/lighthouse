use crate::per_epoch_processing::weigh_justification_and_finalization;
use crate::per_epoch_processing::Error;
use safe_arith::SafeArith;
use types::consts::altair::TIMELY_TARGET_FLAG_INDEX;
use types::{BeaconState, ChainSpec, EthSpec};

/// Update the justified and finalized checkpoints for matching target attestations.
pub fn process_justification_and_finalization<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if state.current_epoch() <= T::genesis_epoch().safe_add(1)? {
        return Ok(());
    }

    let previous_epoch = state.previous_epoch();
    let current_epoch = state.current_epoch();
    let previous_indices = state.get_unslashed_participating_indices(
        TIMELY_TARGET_FLAG_INDEX,
        previous_epoch,
        spec,
    )?;
    let current_indices =
        state.get_unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, current_epoch, spec)?;
    let total_active_balance = state.get_total_balance(
        state
            .get_active_validator_indices(current_epoch, spec)?
            .as_slice(),
        spec,
    )?;
    let previous_target_balance = state.get_total_balance(&previous_indices, spec)?;
    let current_target_balance = state.get_total_balance(&current_indices, spec)?;
    weigh_justification_and_finalization(
        state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}
