use super::ParticipationCache;
use crate::per_epoch_processing::Error;
use crate::per_epoch_processing::{
    weigh_justification_and_finalization, JustificationAndFinalizationState,
};
use crate::EpochProcessingError;
use safe_arith::SafeArith;
use types::beacon_state::Error as BeaconStateError;
use types::consts::altair::TIMELY_TARGET_FLAG_INDEX;
use types::{BeaconState, EthSpec, ProgressiveTotalBalances};

/// Update the justified and finalized checkpoints for matching target attestations.
pub fn process_justification_and_finalization<T: EthSpec>(
    state: &BeaconState<T>,
    participation_cache: &ParticipationCache,
) -> Result<JustificationAndFinalizationState<T>, Error> {
    let justification_and_finalization_state = JustificationAndFinalizationState::new(state);

    if state.current_epoch() <= T::genesis_epoch().safe_add(1)? {
        return Ok(justification_and_finalization_state);
    }

    // Use the balances from the `ProgressiveTotalBalances` cache if available, otherwise calculate them.
    let (total_active_balance, previous_target_balance, current_target_balance) =
        get_progressive_total_balances(state)
            .or_else(|_| calculate_total_balances(state, participation_cache))?;

    weigh_justification_and_finalization(
        justification_and_finalization_state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}

fn get_progressive_total_balances<T: EthSpec>(
    state: &BeaconState<T>,
) -> Result<(u64, u64, u64), EpochProcessingError> {
    let (_, total_active_balance) = state
        .total_active_balance()
        .ok_or(BeaconStateError::TotalActiveBalanceCacheUninitialized)?;

    let progressive_total_balances: &ProgressiveTotalBalances = state.progressive_total_balances();
    let (previous_target_balance, current_target_balance) = (
        progressive_total_balances.previous_epoch_target_attesting_balance()?,
        progressive_total_balances.current_epoch_target_attesting_balance()?,
    );

    Ok((
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    ))
}

fn calculate_total_balances<T: EthSpec>(
    state: &BeaconState<T>,
    participation_cache: &ParticipationCache,
) -> Result<(u64, u64, u64), EpochProcessingError> {
    let previous_epoch = state.previous_epoch();
    let current_epoch = state.current_epoch();
    let previous_indices = participation_cache
        .get_unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, previous_epoch)?;
    let current_indices = participation_cache
        .get_unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, current_epoch)?;
    let total_active_balance = participation_cache.current_epoch_total_active_balance();
    let previous_target_balance = previous_indices.total_balance()?;
    let current_target_balance = current_indices.total_balance()?;
    Ok((
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    ))
}
