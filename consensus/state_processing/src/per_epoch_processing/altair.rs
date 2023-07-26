use super::{process_registry_updates, process_slashings, EpochProcessingSummary, Error};
use crate::common::update_progressive_balances_cache::{
    initialize_progressive_balances_cache, update_progressive_balances_on_epoch_transition,
};
use crate::per_epoch_processing::{
    effective_balance_updates::process_effective_balance_updates,
    historical_roots_update::process_historical_roots_update,
    resets::{process_eth1_data_reset, process_randao_mixes_reset, process_slashings_reset},
};
pub use inactivity_updates::process_inactivity_updates;
pub use justification_and_finalization::process_justification_and_finalization;
pub use participation_cache::ParticipationCache;
pub use participation_flag_updates::process_participation_flag_updates;
pub use rewards_and_penalties::process_rewards_and_penalties;
pub use sync_committee_updates::process_sync_committee_updates;
use types::{BeaconState, ChainSpec, EthSpec, RelativeEpoch};

pub mod inactivity_updates;
pub mod justification_and_finalization;
pub mod participation_cache;
pub mod participation_flag_updates;
pub mod rewards_and_penalties;
pub mod sync_committee_updates;

pub fn process_epoch<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<EpochProcessingSummary<T>, Error> {
    // Ensure the committee caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;
    state.build_committee_cache(RelativeEpoch::Next, spec)?;

    // Pre-compute participating indices and total balances.
    let participation_cache = ParticipationCache::new(state, spec)?;
    let sync_committee = state.current_sync_committee()?.clone();
    initialize_progressive_balances_cache::<T>(state, Some(&participation_cache), spec)?;

    // Justification and finalization.
    let justification_and_finalization_state =
        process_justification_and_finalization(state, &participation_cache)?;
    justification_and_finalization_state.apply_changes_to_state(state);

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
    process_effective_balance_updates(state, Some(&participation_cache), spec)?;

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

    update_progressive_balances_on_epoch_transition(state, spec)?;

    Ok(EpochProcessingSummary::Altair {
        participation_cache,
        sync_committee,
    })
}
