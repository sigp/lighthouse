use crate::per_epoch_processing::Error;
use crate::per_epoch_processing::{
    weigh_justification_and_finalization, JustificationAndFinalizationState,
};
use safe_arith::SafeArith;
use types::{BeaconState, EthSpec};

/// Process justification and finalization using the progressive balances cache.
pub fn process_justification_and_finalization<E: EthSpec>(
    state: &BeaconState<E>,
) -> Result<JustificationAndFinalizationState<E>, Error> {
    let justification_and_finalization_state = JustificationAndFinalizationState::new(state);
    if state.current_epoch() <= E::genesis_epoch().safe_add(1)? {
        return Ok(justification_and_finalization_state);
    }

    // Load cached balances
    let progressive_balances_cache = state.progressive_balances_cache();
    let previous_target_balance =
        progressive_balances_cache.previous_epoch_target_attesting_balance()?;
    let current_target_balance =
        progressive_balances_cache.current_epoch_target_attesting_balance()?;
    let total_active_balance = state.get_total_active_balance()?;

    weigh_justification_and_finalization(
        justification_and_finalization_state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}
