/// A collection of all functions that mutates the `ProgressiveBalancesCache`.
use crate::metrics::{
    PARTICIPATION_CURR_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL,
    PARTICIPATION_PREV_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL,
};
use crate::{BlockProcessingError, EpochProcessingError};
use lighthouse_metrics::set_gauge;
use types::{
    is_progressive_balances_enabled, BeaconState, BeaconStateError, ChainSpec, Epoch,
    EpochTotalBalances, EthSpec, ParticipationFlags, ProgressiveBalancesCache, Validator,
};

/// Initializes the `ProgressiveBalancesCache` if it is unbuilt.
pub fn initialize_progressive_balances_cache<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), BeaconStateError> {
    if !is_progressive_balances_enabled(state)
        || state.progressive_balances_cache().is_initialized()
    {
        return Ok(());
    }

    // Calculate the total flag balances for previous & current epoch in a single iteration.
    // This calculates `get_total_balance(unslashed_participating_indices(..))` for each flag in
    // the current and previous epoch.
    let current_epoch = state.current_epoch();
    let previous_epoch = state.previous_epoch();
    let mut previous_epoch_cache = EpochTotalBalances::new(spec);
    let mut current_epoch_cache = EpochTotalBalances::new(spec);
    for ((validator, current_epoch_flags), previous_epoch_flags) in state
        .validators()
        .iter()
        .zip(state.current_epoch_participation()?)
        .zip(state.previous_epoch_participation()?)
    {
        // Exclude slashed validators. We are calculating *unslashed* participating totals.
        if validator.slashed {
            continue;
        }

        // Update current epoch flag balances.
        if validator.is_active_at(current_epoch) {
            update_flag_total_balances(&mut current_epoch_cache, *current_epoch_flags, validator)?;
        }
        // Update previous epoch flag balances.
        if validator.is_active_at(previous_epoch) {
            update_flag_total_balances(
                &mut previous_epoch_cache,
                *previous_epoch_flags,
                validator,
            )?;
        }
    }

    state.progressive_balances_cache_mut().initialize(
        current_epoch,
        previous_epoch_cache,
        current_epoch_cache,
    );

    update_progressive_balances_metrics(state.progressive_balances_cache())?;

    Ok(())
}

/// During the initialization of the progressive balances for a single epoch, add
/// `validator.effective_balance` to the flag total, for each flag present in `participation_flags`.
///
/// Pre-conditions:
///
/// - `validator` must not be slashed
/// - the `participation_flags` must be for `validator` in the same epoch as the `total_balances`
fn update_flag_total_balances(
    total_balances: &mut EpochTotalBalances,
    participation_flags: ParticipationFlags,
    validator: &Validator,
) -> Result<(), BeaconStateError> {
    for (flag, balance) in total_balances.total_flag_balances.iter_mut().enumerate() {
        if participation_flags.has_flag(flag)? {
            balance.safe_add_assign(validator.effective_balance)?;
        }
    }
    Ok(())
}

/// Updates the `ProgressiveBalancesCache` when a new target attestation has been processed.
pub fn update_progressive_balances_on_attestation<E: EthSpec>(
    state: &mut BeaconState<E>,
    epoch: Epoch,
    flag_index: usize,
    validator_effective_balance: u64,
    validator_slashed: bool,
) -> Result<(), BlockProcessingError> {
    if is_progressive_balances_enabled(state) {
        state.progressive_balances_cache_mut().on_new_attestation(
            epoch,
            validator_slashed,
            flag_index,
            validator_effective_balance,
        )?;
    }
    Ok(())
}

/// Updates the `ProgressiveBalancesCache` when a target attester has been slashed.
pub fn update_progressive_balances_on_slashing<E: EthSpec>(
    state: &mut BeaconState<E>,
    validator_index: usize,
    validator_effective_balance: u64,
) -> Result<(), BlockProcessingError> {
    if is_progressive_balances_enabled(state) {
        let previous_epoch_participation = *state
            .previous_epoch_participation()?
            .get(validator_index)
            .ok_or(BeaconStateError::UnknownValidator(validator_index))?;

        let current_epoch_participation = *state
            .current_epoch_participation()?
            .get(validator_index)
            .ok_or(BeaconStateError::UnknownValidator(validator_index))?;

        state.progressive_balances_cache_mut().on_slashing(
            previous_epoch_participation,
            current_epoch_participation,
            validator_effective_balance,
        )?;
    }

    Ok(())
}

/// Updates the `ProgressiveBalancesCache` on epoch transition.
pub fn update_progressive_balances_on_epoch_transition<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    if is_progressive_balances_enabled(state) {
        state
            .progressive_balances_cache_mut()
            .on_epoch_transition(spec)?;

        update_progressive_balances_metrics(state.progressive_balances_cache())?;
    }

    Ok(())
}

pub fn update_progressive_balances_metrics(
    cache: &ProgressiveBalancesCache,
) -> Result<(), BeaconStateError> {
    set_gauge(
        &PARTICIPATION_PREV_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL,
        cache.previous_epoch_target_attesting_balance()? as i64,
    );

    set_gauge(
        &PARTICIPATION_CURR_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL,
        cache.current_epoch_target_attesting_balance()? as i64,
    );

    Ok(())
}
