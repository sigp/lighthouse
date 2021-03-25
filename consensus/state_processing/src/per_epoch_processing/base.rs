use super::{
    process_registry_updates, process_slashings, EpochProcessingSummary, Error,
};
use types::{BeaconState, ChainSpec, EthSpec, RelativeEpoch};

pub mod final_updates;
pub mod rewards_and_penalties;
pub mod validator_statuses;
pub mod justification_and_finalization;

pub use final_updates::process_final_updates;
pub use rewards_and_penalties::process_rewards_and_penalties;
pub use justification_and_finalization::process_justification_and_finalization;
pub use validator_statuses::{TotalBalances, ValidatorStatus, ValidatorStatuses};

pub fn process_epoch<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<EpochProcessingSummary, Error> {
    // Ensure the committee caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;
    state.build_committee_cache(RelativeEpoch::Next, spec)?;

    // Load the struct we use to assign validators into sets based on their participation.
    //
    // E.g., attestation in the previous epoch, attested to the head, etc.
    let mut validator_statuses = ValidatorStatuses::new(state, spec)?;
    validator_statuses.process_attestations(&state, spec)?;

    // Justification and finalization.
    process_justification_and_finalization(state, &validator_statuses.total_balances)?;

    // Rewards and Penalties.
    process_rewards_and_penalties(state, &mut validator_statuses, spec)?;

    // Registry Updates.
    process_registry_updates(state, spec)?;

    // Slashings.
    process_slashings(
        state,
        validator_statuses.total_balances.current_epoch(),
        spec,
    )?;

    // Final updates.
    process_final_updates(state, spec)?;

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches();

    Ok(EpochProcessingSummary {
        total_balances: validator_statuses.total_balances,
        statuses: validator_statuses.statuses,
    })
}
