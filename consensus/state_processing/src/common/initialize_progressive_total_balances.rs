use crate::per_epoch_processing::altair::participation_cache::Error as ParticipationCacheError;
use crate::per_epoch_processing::altair::ParticipationCache;
use types::{BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec};

pub fn initialize_progressive_total_balances<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
    epoch: Epoch,
) -> Result<(), BeaconStateError> {
    let participation_cache = ParticipationCache::new(state, spec)?;

    let to_beacon_state_error =
        |e: ParticipationCacheError| BeaconStateError::ParticipationCacheError(format!("{:?}", e));
    let (previous_epoch_target_attesting_balance, current_epoch_target_attesting_balance) = (
        participation_cache
            .previous_epoch_target_attesting_balance()
            .map_err(to_beacon_state_error)?,
        participation_cache
            .current_epoch_target_attesting_balance()
            .map_err(to_beacon_state_error)?,
    );

    state.progressive_total_balances_mut().initialize(
        epoch,
        previous_epoch_target_attesting_balance,
        current_epoch_target_attesting_balance,
    );

    Ok(())
}
