use super::{process_registry_updates, process_slashings, EpochProcessingSummary, Error};
use crate::per_epoch_processing::{
    effective_balance_updates::process_effective_balance_updates,
    historical_roots_update::process_historical_roots_update,
    participation_record_updates::process_participation_record_updates,
    resets::{process_eth1_data_reset, process_randao_mixes_reset, process_slashings_reset},
    validator_statuses::ValidatorStatuses,
};
pub use inactivity_updates::process_inactivity_updates;
pub use justification_and_finalization::process_justification_and_finalization;
pub use participation_flag_updates::process_participation_flag_updates;
pub use rewards_and_penalties::process_rewards_and_penalties;
use safe_arith::SafeArith;
pub use sync_committee_udpates::process_sync_committee_udpates;
use tree_hash::TreeHash;
use types::consts::altair::{INACTIVITY_SCORE_BIAS, TIMELY_TARGET_FLAG_INDEX};
use types::{
    BeaconState, ChainSpec, EthSpec, ParticipationFlags, RelativeEpoch, Unsigned, VariableList,
};

pub mod inactivity_updates;
pub mod justification_and_finalization;
pub mod participation_flag_updates;
pub mod rewards_and_penalties;
pub mod sync_committee_udpates;

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
    //TODO: remove for altair?
    let mut validator_statuses = ValidatorStatuses::new(state, spec)?;
    validator_statuses.process_attestations(&state, spec)?;

    // Justification and finalization.
    process_justification_and_finalization(state, spec)?;

    process_inactivity_updates(state, spec)?;

    // Rewards and Penalties.
    process_rewards_and_penalties(state, spec)?;

    // Registry Updates.
    process_registry_updates(state, spec)?;

    // Slashings.
    process_slashings(
        state,
        state.get_total_active_balance(spec)?,
        spec.proportional_slashing_multiplier_altair,
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

    process_participation_flag_updates(state)?;

    process_sync_committee_udpates(state, spec)?;

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches();

    Ok(EpochProcessingSummary {
        total_balances: validator_statuses.total_balances,
        statuses: validator_statuses.statuses,
    })
}
