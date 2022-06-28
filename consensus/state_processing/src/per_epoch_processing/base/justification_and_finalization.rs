use crate::per_epoch_processing::base::TotalBalances;
use crate::per_epoch_processing::Error;
use crate::per_epoch_processing::{
    weigh_justification_and_finalization, JustificationAndFinalizationState,
};
use safe_arith::SafeArith;
use types::{BeaconState, ChainSpec, EthSpec};

/// Update the justified and finalized checkpoints for matching target attestations.
pub fn process_justification_and_finalization<T: EthSpec>(
    state: &BeaconState<T>,
    total_balances: &TotalBalances,
    _spec: &ChainSpec,
) -> Result<JustificationAndFinalizationState<T>, Error> {
    let justification_and_finalization_state = JustificationAndFinalizationState::new(state);

    if state.current_epoch() <= T::genesis_epoch().safe_add(1)? {
        return Ok(justification_and_finalization_state);
    }

    weigh_justification_and_finalization(
        justification_and_finalization_state,
        total_balances.current_epoch(),
        total_balances.previous_epoch_target_attesters(),
        total_balances.current_epoch_target_attesters(),
    )
}
