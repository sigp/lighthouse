/// A collection of all functions that mutates the `ProgressiveBalancesCache`.
use crate::metrics::{
    PARTICIPATION_CURR_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL,
    PARTICIPATION_PREV_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL,
};
use crate::per_epoch_processing::altair::ParticipationCache;
use crate::{BlockProcessingError, EpochProcessingError};
use lighthouse_metrics::set_gauge;
use ssz_types::VariableList;
use std::borrow::Cow;
use types::consts::altair::TIMELY_TARGET_FLAG_INDEX;
use types::{
    is_progressive_balances_enabled, BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec,
    ParticipationFlags, ProgressiveBalancesCache,
};

/// Initializes the `ProgressiveBalancesCache` cache using balance values from the
/// `ParticipationCache`. If the optional `&ParticipationCache` is not supplied, it will be computed
/// from the `BeaconState`.
pub fn initialize_progressive_balances_cache<E: EthSpec>(
    state: &mut BeaconState<E>,
    maybe_participation_cache: Option<&ParticipationCache>,
    spec: &ChainSpec,
) -> Result<(), BeaconStateError> {
    if !is_progressive_balances_enabled(state)
        || state.progressive_balances_cache().is_initialized()
    {
        return Ok(());
    }

    let participation_cache = match maybe_participation_cache {
        Some(cache) => Cow::Borrowed(cache),
        None => Cow::Owned(ParticipationCache::new(state, spec)?),
    };

    let previous_epoch_target_attesting_balance = participation_cache
        .previous_epoch_target_attesting_balance_raw()
        .map_err(|e| BeaconStateError::ParticipationCacheError(format!("{e:?}")))?;

    let current_epoch_target_attesting_balance = participation_cache
        .current_epoch_target_attesting_balance_raw()
        .map_err(|e| BeaconStateError::ParticipationCacheError(format!("{e:?}")))?;

    let current_epoch = state.current_epoch();
    state.progressive_balances_cache_mut().initialize(
        current_epoch,
        previous_epoch_target_attesting_balance,
        current_epoch_target_attesting_balance,
    );

    update_progressive_balances_metrics(state.progressive_balances_cache())?;

    Ok(())
}

/// Updates the `ProgressiveBalancesCache` when a new target attestation has been processed.
pub fn update_progressive_balances_on_attestation<T: EthSpec>(
    state: &mut BeaconState<T>,
    epoch: Epoch,
    validator_index: usize,
) -> Result<(), BlockProcessingError> {
    if is_progressive_balances_enabled(state) {
        let validator = state.get_validator(validator_index)?;
        if !validator.slashed {
            let validator_effective_balance = validator.effective_balance;
            state
                .progressive_balances_cache_mut()
                .on_new_target_attestation(epoch, validator_effective_balance)?;
        }
    }
    Ok(())
}

/// Updates the `ProgressiveBalancesCache` when a target attester has been slashed.
pub fn update_progressive_balances_on_slashing<T: EthSpec>(
    state: &mut BeaconState<T>,
    validator_index: usize,
) -> Result<(), BlockProcessingError> {
    if is_progressive_balances_enabled(state) {
        let previous_epoch_participation = state.previous_epoch_participation()?;
        let is_previous_epoch_target_attester =
            is_target_attester_in_epoch::<T>(previous_epoch_participation, validator_index)?;

        let current_epoch_participation = state.current_epoch_participation()?;
        let is_current_epoch_target_attester =
            is_target_attester_in_epoch::<T>(current_epoch_participation, validator_index)?;

        let validator_effective_balance = state.get_effective_balance(validator_index)?;

        state.progressive_balances_cache_mut().on_slashing(
            is_previous_epoch_target_attester,
            is_current_epoch_target_attester,
            validator_effective_balance,
        )?;
    }

    Ok(())
}

/// Updates the `ProgressiveBalancesCache` on epoch transition.
pub fn update_progressive_balances_on_epoch_transition<T: EthSpec>(
    state: &mut BeaconState<T>,
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

fn is_target_attester_in_epoch<T: EthSpec>(
    epoch_participation: &VariableList<ParticipationFlags, T::ValidatorRegistryLimit>,
    validator_index: usize,
) -> Result<bool, BlockProcessingError> {
    let participation_flags = epoch_participation
        .get(validator_index)
        .ok_or(BeaconStateError::UnknownValidator(validator_index))?;
    participation_flags
        .has_flag(TIMELY_TARGET_FLAG_INDEX)
        .map_err(|e| e.into())
}
