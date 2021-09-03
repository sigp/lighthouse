use super::{process_registry_updates, process_slashings, EpochProcessingSummary, Error};
use crate::per_epoch_processing::{
    effective_balance_updates::process_effective_balance_updates,
    historical_roots_update::process_historical_roots_update,
    resets::{process_eth1_data_reset, process_randao_mixes_reset, process_slashings_reset},
};
pub use justification_and_finalization::process_justification_and_finalization;
pub use participation_record_updates::process_participation_record_updates;
pub use rewards_and_penalties::process_rewards_and_penalties;
use types::{BeaconState, ChainSpec, EthSpec, RelativeEpoch};
pub use validator_statuses::{TotalBalances, ValidatorStatus, ValidatorStatuses};

pub mod justification_and_finalization;
pub mod participation_record_updates;
pub mod rewards_and_penalties;
pub mod validator_statuses;

pub fn process_epoch<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<EpochProcessingSummary<T>, Error> {
    // Ensure the committee caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;
    state.build_committee_cache(RelativeEpoch::Next, spec)?;

    // Load the struct we use to assign validators into sets based on their participation.
    //
    // E.g., attestation in the previous epoch, attested to the head, etc.
    let mut validator_statuses = ValidatorStatuses::new(state, spec)?;
    validator_statuses.process_attestations(state)?;

    // Justification and finalization.
    process_justification_and_finalization(state, &validator_statuses.total_balances, spec)?;

    // Rewards and Penalties.
    process_rewards_and_penalties(state, &mut validator_statuses, spec)?;

    // Registry Updates.
    process_registry_updates(state, spec)?;

    // Slashings.
    process_slashings(
        state,
        validator_statuses.total_balances.current_epoch(),
        spec.proportional_slashing_multiplier,
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

    // Rotate current/previous epoch attestations
    process_participation_record_updates(state)?;

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches(spec)?;

    Ok(EpochProcessingSummary::Base {
        total_balances: validator_statuses.total_balances,
        statuses: validator_statuses.statuses,
    })
}
