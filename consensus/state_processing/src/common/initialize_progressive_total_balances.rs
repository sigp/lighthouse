use crate::per_epoch_processing::altair::participation_cache::Error as ParticipationCacheError;
use crate::per_epoch_processing::altair::ParticipationCache;
use types::{BeaconState, BeaconStateError, EthSpec};

pub fn initialize_progressive_total_balances<E: EthSpec>(
    state: &mut BeaconState<E>,
    participation_cache: &ParticipationCache,
) -> Result<(), BeaconStateError> {
    let current_epoch = state.current_epoch();
    let progressive_total_balances = state.progressive_total_balances_mut();

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

    progressive_total_balances.initialize(
        current_epoch,
        previous_epoch_target_attesting_balance,
        current_epoch_target_attesting_balance,
    );

    Ok(())
}
