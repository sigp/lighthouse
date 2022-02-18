use super::ParticipationCache;
use crate::per_epoch_processing::weigh_justification_and_finalization;
use crate::per_epoch_processing::Error;
use safe_arith::SafeArith;
use types::{BeaconState, EthSpec};

/// Update the justified and finalized checkpoints for matching target attestations.
pub fn process_justification_and_finalization<T: EthSpec>(
    state: &mut BeaconState<T>,
    participation_cache: &ParticipationCache,
) -> Result<(), Error> {
    if state.current_epoch() <= T::genesis_epoch().safe_add(1)? {
        return Ok(());
    }

    let total_active_balance = participation_cache.current_epoch_total_active_balance();
    let previous_target_balance = participation_cache.previous_epoch_target_attesting_balance()?;
    let current_target_balance = participation_cache.current_epoch_target_attesting_balance()?;
    weigh_justification_and_finalization(
        state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}
