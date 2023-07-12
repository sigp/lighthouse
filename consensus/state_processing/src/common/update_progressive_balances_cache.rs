/// A collection of all functions that mutates the `ProgressiveBalancesCache`.
use crate::metrics::{
    PARTICIPATION_CURR_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL,
    PARTICIPATION_PREV_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL,
};
use crate::per_epoch_processing::altair::ParticipationCache;
use crate::{BlockProcessingError, EpochProcessingError};
use lighthouse_metrics::set_gauge;
use std::borrow::Cow;
use types::{
    is_progressive_balances_enabled, BeaconState, BeaconStateError, ChainSpec, Epoch,
    EpochTotalBalances, EthSpec, ProgressiveBalancesCache,
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

    // FIXME(sproul): simplify the participation cache
    let participation_cache = match maybe_participation_cache {
        Some(cache) => Cow::Borrowed(cache),
        None => {
            state.build_total_active_balance_cache_at(state.current_epoch(), spec)?;
            Cow::Owned(
                ParticipationCache::new(state, spec)
                    .map_err(|e| BeaconStateError::ParticipationCacheError(format!("{e:?}")))?,
            )
        }
    };

    let current_epoch = state.current_epoch();
    let previous_epoch_cache = EpochTotalBalances {
        total_flag_balances: participation_cache
            .previous_epoch_participation
            .total_flag_balances,
    };
    let current_epoch_cache = EpochTotalBalances {
        total_flag_balances: participation_cache
            .current_epoch_participation
            .total_flag_balances,
    };

    state.progressive_balances_cache_mut().initialize(
        current_epoch,
        previous_epoch_cache,
        current_epoch_cache,
    );

    update_progressive_balances_metrics(state.progressive_balances_cache())?;

    Ok(())
}

/// Updates the `ProgressiveBalancesCache` when a new target attestation has been processed.
pub fn update_progressive_balances_on_attestation<T: EthSpec>(
    state: &mut BeaconState<T>,
    epoch: Epoch,
    flag_index: usize,
    validator_effective_balance: u64,
    validator_slashed: bool,
) -> Result<(), BlockProcessingError> {
    if is_progressive_balances_enabled(state) && !validator_slashed {
        state.progressive_balances_cache_mut().on_new_attestation(
            epoch,
            flag_index,
            validator_effective_balance,
        )?;
    }
    Ok(())
}

/// Updates the `ProgressiveBalancesCache` when a target attester has been slashed.
pub fn update_progressive_balances_on_slashing<T: EthSpec>(
    state: &mut BeaconState<T>,
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
