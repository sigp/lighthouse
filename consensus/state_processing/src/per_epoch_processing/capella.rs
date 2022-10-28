use super::{process_registry_updates, process_slashings, EpochProcessingSummary, Error};
use crate::per_epoch_processing::{
    altair,
    effective_balance_updates::process_effective_balance_updates,
    historical_roots_update::process_historical_roots_update,
    resets::{process_eth1_data_reset, process_randao_mixes_reset, process_slashings_reset},
};
pub use full_withdrawals::process_full_withdrawals;
pub use partial_withdrawals::process_partial_withdrawals;
use types::{BeaconState, ChainSpec, EthSpec, RelativeEpoch};

pub mod full_withdrawals;
pub mod partial_withdrawals;

pub fn process_epoch<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<EpochProcessingSummary<T>, Error> {
    // Ensure the committee caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;
    state.build_committee_cache(RelativeEpoch::Next, spec)?;

    // Pre-compute participating indices and total balances.
    let participation_cache = altair::ParticipationCache::new(state, spec)?;
    let sync_committee = state.current_sync_committee()?.clone();

    // Justification and finalization.
    let justification_and_finalization_state =
        altair::process_justification_and_finalization(state, &participation_cache)?;
    justification_and_finalization_state.apply_changes_to_state(state);

    altair::process_inactivity_updates(state, &participation_cache, spec)?;

    // Rewards and Penalties.
    altair::process_rewards_and_penalties(state, &participation_cache, spec)?;

    // Registry Updates.
    process_registry_updates(state, spec)?;

    // Slashings.
    process_slashings(
        state,
        participation_cache.current_epoch_total_active_balance(),
        spec,
    )?;

    // Reset eth1 data votes.
    process_eth1_data_reset(state)?;

    // Update effective balances with hysteresis (lag).
    process_effective_balance_updates(state, spec)?;

    // Reset slashings
    process_slashings_reset(state)?;

    // Set randao mix
    process_randao_mixes_reset(state)?;

    // Set historical root accumulator
    process_historical_roots_update(state)?;

    // Rotate current/previous epoch participation
    altair::process_participation_flag_updates(state)?;

    altair::process_sync_committee_updates(state, spec)?;

    // Withdrawals
    process_full_withdrawals(state, spec)?;

    process_partial_withdrawals(state, spec)?;

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches(spec)?;

    // FIXME: do we need a Capella variant for this?
    Ok(EpochProcessingSummary::Altair {
        participation_cache,
        sync_committee,
    })
}
