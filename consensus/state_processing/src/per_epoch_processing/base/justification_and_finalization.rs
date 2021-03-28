use crate::per_epoch_processing::base::TotalBalances;
use crate::per_epoch_processing::weigh_justification_and_finalization;
use crate::per_epoch_processing::Error;
use safe_arith::SafeArith;
use types::{BeaconState, ChainSpec, EthSpec};

/// Update the justified and finalized checkpoints for matching target attestations.
pub fn process_justification_and_finalization<T: EthSpec>(
    state: &mut BeaconState<T>,
    total_balances: &TotalBalances,
    _spec: &ChainSpec,
) -> Result<(), Error> {
    if state.current_epoch() <= T::genesis_epoch().safe_add(1)? {
        return Ok(());
    }

    weigh_justification_and_finalization(
        state,
        total_balances.current_epoch(),
        total_balances.previous_epoch_target_attesters(),
        total_balances.current_epoch_target_attesters(),
    )
}
