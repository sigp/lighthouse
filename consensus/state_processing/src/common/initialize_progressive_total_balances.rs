use crate::per_epoch_processing::altair::ParticipationCache;
use std::borrow::Cow;
use types::{BeaconState, BeaconStateError, ChainSpec, EthSpec};

/// Initializes the `ProgressiveTotalBalances` cache using balance values from the
/// `ParticipationCache`. If the optional `&ParticipationCache` is not supplied, it will be computed
/// from the `BeaconState`.
pub fn initialize_progressive_total_balances<E: EthSpec>(
    state: &mut BeaconState<E>,
    maybe_participation_cache: Option<&ParticipationCache>,
    spec: &ChainSpec,
) -> Result<(), BeaconStateError> {
    if !is_progressive_balances_enabled(state)
        || state.progressive_total_balances().is_initialized()
    {
        return Ok(());
    }

    let participation_cache = match maybe_participation_cache {
        Some(cache) => Cow::Borrowed(cache),
        None => Cow::Owned(ParticipationCache::new(state, spec)?),
    };

    // FIXME[JC]: Converts value to 0 if it is the same as `EFFECTIVE_BALANCE_INCREMENT`.
    // `ParticipationCache` methods return `EFFECTIVE_BALANCE_INCREMENT` (1,000,000,000)
    // when the balance is 0, and this breaks our calculation.
    let handle_zero_effective_balance = |val| {
        if val == spec.effective_balance_increment {
            0
        } else {
            val
        }
    };

    let previous_epoch_target_attesting_balance = participation_cache
        .previous_epoch_target_attesting_balance()
        .map(handle_zero_effective_balance)
        .map_err(|e| BeaconStateError::ParticipationCacheError(format!("{:?}", e)))?;

    let current_epoch_target_attesting_balance = participation_cache
        .current_epoch_target_attesting_balance()
        .map(handle_zero_effective_balance)
        .map_err(|e| BeaconStateError::ParticipationCacheError(format!("{:?}", e)))?;

    let current_epoch = state.current_epoch();
    state.progressive_total_balances_mut().initialize(
        current_epoch,
        previous_epoch_target_attesting_balance,
        current_epoch_target_attesting_balance,
    );

    Ok(())
}

/// `ProgressiveTotalBalances` is only enabled from `Altair` as it requires `ParticipationCache`.
fn is_progressive_balances_enabled<E: EthSpec>(state: &BeaconState<E>) -> bool {
    match state {
        BeaconState::Base(_) => false,
        BeaconState::Altair(_) | BeaconState::Merge(_) | BeaconState::Capella(_) => true,
    }
}
