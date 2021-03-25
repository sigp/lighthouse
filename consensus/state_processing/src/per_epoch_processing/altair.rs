use super::{
    process_justification_and_finalization, process_registry_updates, process_slashings,
    EpochProcessingSummary, Error,
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
use crate::per_block_processing::process_eth1_data;

const TIMELY_HEAD_FLAG_INDEX: u64 = 0;
const TIMELY_SOURCE_FLAG_INDEX: u64 = 1;
const TIMELY_TARGET_FLAG_INDEX: u64 = 2;
const TIMELY_HEAD_WEIGHT: u64 = 12;
const TIMELY_SOURCE_WEIGHT: u64 = 12;
const TIMELY_TARGET_WEIGHT: u64 = 24;
const SYNC_REWARD_WEIGHT: u64 = 8;
const WEIGHT_DENOMINATOR: u64 = 64;

// FIXME(altair): implement
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
    //TODO: implement for altair
    let mut validator_statuses = ValidatorStatuses::new(state, spec)?;
    validator_statuses.process_attestations(&state, spec)?;

    // Justification and finalization.
    //TODO: modified
    process_justification_and_finalization(state, &validator_statuses.total_balances)?;

    //TODO: new
    process_inactivity_updates(state)?;

    // Rewards and Penalties.
    //TODO: modified
    process_rewards_and_penalties(state, &mut validator_statuses, spec)?;

    // Registry Updates.
    process_registry_updates(state, spec)?;

    // Slashings.
    //TODO: modified
    process_slashings(
        state,
        validator_statuses.total_balances.current_epoch(),
        spec,
    )?;

    // verify this includes:
    // - process_eth1_data_reset()
    // - process_effective_balances_updates()
    // - process_slashings_reset()
    // - process_randao_mixes_reset()
    // - process_historical_roots_update()
    // Final updates.
    process_final_updates(state, spec)?;

    //TODO: new
    process_participation_flag_updates();
    //TODO: new
    process_sync_committee_udpates();

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches();

    Ok(EpochProcessingSummary {
        total_balances: validator_statuses.total_balances,
        statuses: validator_statuses.statuses,
    })
}

fn process_participation_flag_updates(state: &mut BeaconState<T>){
    state.previous_epoch_participation = state.current_epoch_participation.clone();
    state.current_epoch_participation = state.current_epoch_participation.clone();
}

fn process_sync_committee_udpates(){

}
