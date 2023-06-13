use crate::per_epoch_processing::altair::ParticipationCache;
use std::borrow::Cow;
use types::{is_progressive_balances_enabled, BeaconState, BeaconStateError, ChainSpec, EthSpec};

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
        .map_err(|e| BeaconStateError::ParticipationCacheError(format!("{:?}", e)))?;

    let current_epoch_target_attesting_balance = participation_cache
        .current_epoch_target_attesting_balance_raw()
        .map_err(|e| BeaconStateError::ParticipationCacheError(format!("{:?}", e)))?;

    let current_epoch = state.current_epoch();
    state.progressive_balances_cache_mut().initialize(
        current_epoch,
        previous_epoch_target_attesting_balance,
        current_epoch_target_attesting_balance,
    );

    Ok(())
}
