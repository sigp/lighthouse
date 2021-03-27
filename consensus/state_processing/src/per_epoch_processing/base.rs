pub use justification_and_finalization::process_justification_and_finalization;
pub use rewards_and_penalties::process_rewards_and_penalties;

use safe_arith::SafeArith;
use tree_hash::TreeHash;
use types::{BeaconState, ChainSpec, EthSpec, RelativeEpoch, Unsigned, VariableList};

pub use crate::per_epoch_processing::validator_statuses::{
    TotalBalances, ValidatorStatus, ValidatorStatuses,
};
use crate::per_epoch_processing::weigh_justification_and_finalization;

use super::{process_registry_updates, process_slashings, EpochProcessingSummary, Error};

pub mod justification_and_finalization;
pub mod rewards_and_penalties;

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
    process_justification_and_finalization(state, &validator_statuses.total_balances, spec)?;

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
    state.advance_caches();

    Ok(EpochProcessingSummary {
        total_balances: validator_statuses.total_balances,
        statuses: validator_statuses.statuses,
    })
}

pub fn process_eth1_data_reset<T: EthSpec>(state: &mut BeaconState<T>) -> Result<(), Error> {
    if state
        .slot()
        .safe_add(1)?
        .safe_rem(T::SlotsPerEth1VotingPeriod::to_u64())?
        == 0
    {
        *state.eth1_data_votes_mut() = VariableList::empty();
    }
    Ok(())
}

pub fn process_effective_balance_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let hysteresis_increment = spec
        .effective_balance_increment
        .safe_div(spec.hysteresis_quotient)?;
    let downward_threshold = hysteresis_increment.safe_mul(spec.hysteresis_downward_multiplier)?;
    let upward_threshold = hysteresis_increment.safe_mul(spec.hysteresis_upward_multiplier)?;
    let (validators, balances) = state.validators_and_balances_mut();
    for (index, validator) in validators.iter_mut().enumerate() {
        let balance = balances[index];

        if balance.safe_add(downward_threshold)? < validator.effective_balance
            || validator.effective_balance.safe_add(upward_threshold)? < balance
        {
            validator.effective_balance = std::cmp::min(
                balance.safe_sub(balance.safe_rem(spec.effective_balance_increment)?)?,
                spec.max_effective_balance,
            );
        }
    }
    Ok(())
}

pub fn process_slashings_reset<T: EthSpec>(state: &mut BeaconState<T>) -> Result<(), Error> {
    let next_epoch = state.next_epoch()?;
    state.set_slashings(next_epoch, 0)?;
    Ok(())
}

pub fn process_randao_mixes_reset<T: EthSpec>(state: &mut BeaconState<T>) -> Result<(), Error> {
    let current_epoch = state.current_epoch();
    let next_epoch = state.next_epoch()?;
    state.set_randao_mix(next_epoch, *state.get_randao_mix(current_epoch)?)?;
    Ok(())
}

pub fn process_historical_roots_update<T: EthSpec>(
    state: &mut BeaconState<T>,
) -> Result<(), Error> {
    let next_epoch = state.next_epoch()?;
    if next_epoch
        .as_u64()
        .safe_rem(T::SlotsPerHistoricalRoot::to_u64().safe_div(T::slots_per_epoch())?)?
        == 0
    {
        let historical_batch = state.historical_batch();
        state
            .historical_roots_mut()
            .push(historical_batch.tree_hash_root())?;
    }
    Ok(())
}

pub fn process_participation_record_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
) -> Result<(), Error> {
    let base_state = state.as_base_mut()?;
    base_state.previous_epoch_attestations =
        std::mem::take(&mut base_state.current_epoch_attestations);
    Ok(())
}
