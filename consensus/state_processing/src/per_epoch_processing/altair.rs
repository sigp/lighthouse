use super::{EpochProcessingSummary, Error, process_registry_updates, process_slashings};
use crate::per_epoch_processing::{
    effective_balance_updates::process_effective_balance_updates,
    historical_roots_update::process_historical_roots_update,
    resets::{process_eth1_data_reset, process_randao_mixes_reset, process_slashings_reset},
};
pub use inactivity_updates::process_inactivity_updates;
pub use justification_and_finalization::process_justification_and_finalization;
pub use types::beacon_state::participation_cache::ParticipationCache;
pub use participation_flag_updates::process_participation_flag_updates;
pub use rewards_and_penalties::process_rewards_and_penalties;
pub use sync_committee_updates::process_sync_committee_updates;
use types::{BeaconState, ChainSpec, EthSpec, RelativeEpoch};
use types::beacon_state::participation_cache::CurrentEpochParticipationCache;

pub mod inactivity_updates;
pub mod justification_and_finalization;
pub mod participation_flag_updates;
pub mod rewards_and_penalties;
pub mod sync_committee_updates;

pub fn process_epoch<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<EpochProcessingSummary<T>, Error> {

    state.build_committee_cache(RelativeEpoch::Next, spec)?;

    let participation_cache = process_justifiable(state, spec)?;

    let sync_committee = state.current_sync_committee()?.clone();

    process_inactivity_updates(state, &participation_cache, spec)?;

    // Rewards and Penalties.
    process_rewards_and_penalties(state, &participation_cache, spec)?;

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
    process_participation_flag_updates(state)?;

    process_sync_committee_updates(state, spec)?;

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches(spec)?;

    Ok(EpochProcessingSummary::Altair {
        participation_cache,
        sync_committee,
    })
}

pub fn process_justifiable<T: EthSpec>(state: &mut BeaconState<T>, spec: &ChainSpec) -> Result<ParticipationCache, Error> {
// Ensure the committee caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;

    // Pre-compute participating indices and total balances.
    let prev_participation_cache = state.get_previous_epoch_participation_cache(spec)?;

    let current_participation_cache = CurrentEpochParticipationCache::new(state, spec)?;

    let participation_cache = ParticipationCache::new(prev_participation_cache, current_participation_cache);

    // Justification and finalization.
    process_justification_and_finalization(state, &participation_cache)?;

    Ok(participation_cache)
}
