use super::{process_registry_updates, process_slashings, EpochProcessingSummary, Error};
use crate::common::update_progressive_balances_cache::{
    initialize_progressive_balances_cache, update_progressive_balances_on_epoch_transition,
};
use crate::epoch_cache::initialize_epoch_cache;
use crate::per_epoch_processing::single_pass::process_epoch_single_pass;
use crate::per_epoch_processing::{
    capella::process_historical_summaries_update,
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
    // Ensure the required caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;
    state.build_committee_cache(RelativeEpoch::Next, spec)?;
    state.build_total_active_balance_cache_at(state.current_epoch(), spec)?;
    initialize_epoch_cache(state, state.current_epoch(), spec)?;

    // Pre-compute participating indices and total balances.
    let sync_committee = state.current_sync_committee()?.clone();
    initialize_progressive_balances_cache::<T>(state, spec)?;

    // Justification and finalization.
    let justification_and_finalization_state = process_justification_and_finalization(state)?;
    justification_and_finalization_state.apply_changes_to_state(state);

    // In a single pass:
    // - Inactivity updates
    // - Rewards and penalties
    // - Registry updates
    // - Slashings
    // - Effective balance updates
    //
    // The `process_eth1_data_reset` is not covered in the single pass, but happens afterwards
    // without loss of correctness.
    process_epoch_single_pass(state, spec)?;

    // Reset eth1 data votes.
    process_eth1_data_reset(state)?;

    // Reset slashings
    process_slashings_reset(state)?;

    // Set randao mix
    process_randao_mixes_reset(state)?;

    // Set historical summaries accumulator
    if state.historical_summaries().is_ok() {
        // Post-Capella.
        process_historical_summaries_update(state)?;
    } else {
        // Pre-Capella
        process_historical_roots_update(state)?;
    }

    // Rotate current/previous epoch participation
    process_participation_flag_updates(state)?;

    process_sync_committee_updates(state, spec)?;

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches(spec)?;
    update_progressive_balances_on_epoch_transition(state, spec)?;

    Ok(EpochProcessingSummary::Altair { sync_committee })
}
