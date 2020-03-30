use errors::EpochProcessingError as Error;
use tree_hash::TreeHash;
use types::*;

pub mod apply_rewards;
pub mod errors;
pub mod process_slashings;
pub mod registry_updates;
pub mod tests;
pub mod validator_statuses;

pub use apply_rewards::process_rewards_and_penalties;
pub use process_slashings::process_slashings;
pub use registry_updates::process_registry_updates;
pub use validator_statuses::{TotalBalances, ValidatorStatus, ValidatorStatuses};

/// Performs per-epoch processing on some BeaconState.
///
/// Mutates the given `BeaconState`, returning early if an error is encountered. If an error is
/// returned, a state might be "half-processed" and therefore in an invalid state.
///
/// Spec v0.11.1
pub fn per_epoch_processing<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
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

    Ok(())
}

/// Update the following fields on the `BeaconState`:
///
/// - `justification_bitfield`.
/// - `previous_justified_epoch`
/// - `previous_justified_root`
/// - `current_justified_epoch`
/// - `current_justified_root`
/// - `finalized_epoch`
/// - `finalized_root`
///
/// Spec v0.11.1
#[allow(clippy::if_same_then_else)] // For readability and consistency with spec.
pub fn process_justification_and_finalization<T: EthSpec>(
    state: &mut BeaconState<T>,
    total_balances: &TotalBalances,
) -> Result<(), Error> {
    if state.current_epoch() <= T::genesis_epoch() + 1 {
        return Ok(());
    }

    let previous_epoch = state.previous_epoch();
    let current_epoch = state.current_epoch();

    let old_previous_justified_checkpoint = state.previous_justified_checkpoint.clone();
    let old_current_justified_checkpoint = state.current_justified_checkpoint.clone();

    // Process justifications
    state.previous_justified_checkpoint = state.current_justified_checkpoint.clone();
    state.justification_bits.shift_up(1)?;

    if total_balances.previous_epoch_target_attesters() * 3 >= total_balances.current_epoch() * 2 {
        state.current_justified_checkpoint = Checkpoint {
            epoch: previous_epoch,
            root: *state.get_block_root_at_epoch(previous_epoch)?,
        };
        state.justification_bits.set(1, true)?;
    }
    // If the current epoch gets justified, fill the last bit.
    if total_balances.current_epoch_target_attesters() * 3 >= total_balances.current_epoch() * 2 {
        state.current_justified_checkpoint = Checkpoint {
            epoch: current_epoch,
            root: *state.get_block_root_at_epoch(current_epoch)?,
        };
        state.justification_bits.set(0, true)?;
    }

    let bits = &state.justification_bits;

    // The 2nd/3rd/4th most recent epochs are all justified, the 2nd using the 4th as source.
    if (1..4).all(|i| bits.get(i).unwrap_or(false))
        && old_previous_justified_checkpoint.epoch + 3 == current_epoch
    {
        state.finalized_checkpoint = old_previous_justified_checkpoint;
    }
    // The 2nd/3rd most recent epochs are both justified, the 2nd using the 3rd as source.
    else if (1..3).all(|i| bits.get(i).unwrap_or(false))
        && old_previous_justified_checkpoint.epoch + 2 == current_epoch
    {
        state.finalized_checkpoint = old_previous_justified_checkpoint;
    }
    // The 1st/2nd/3rd most recent epochs are all justified, the 1st using the 3nd as source.
    if (0..3).all(|i| bits.get(i).unwrap_or(false))
        && old_current_justified_checkpoint.epoch + 2 == current_epoch
    {
        state.finalized_checkpoint = old_current_justified_checkpoint;
    }
    // The 1st/2nd most recent epochs are both justified, the 1st using the 2nd as source.
    else if (0..2).all(|i| bits.get(i).unwrap_or(false))
        && old_current_justified_checkpoint.epoch + 1 == current_epoch
    {
        state.finalized_checkpoint = old_current_justified_checkpoint;
    }

    Ok(())
}

/// Finish up an epoch update.
///
/// Spec v0.11.1
pub fn process_final_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state.current_epoch();
    let next_epoch = state.next_epoch();

    // Reset eth1 data votes.
    if (state.slot + 1) % T::SlotsPerEth1VotingPeriod::to_u64() == 0 {
        state.eth1_data_votes = VariableList::empty();
    }

    // Update effective balances with hysteresis (lag).
    let hysteresis_increment = spec.effective_balance_increment / spec.hysteresis_quotient;
    let downward_threshold = hysteresis_increment * spec.hysteresis_downward_multiplier;
    let upward_threshold = hysteresis_increment * spec.hysteresis_upward_multiplier;
    for (index, validator) in state.validators.iter_mut().enumerate() {
        let balance = state.balances[index];

        if balance + downward_threshold < validator.effective_balance
            || validator.effective_balance + upward_threshold < balance
        {
            validator.effective_balance = std::cmp::min(
                balance - balance % spec.effective_balance_increment,
                spec.max_effective_balance,
            );
        }
    }

    // Reset slashings
    state.set_slashings(next_epoch, 0)?;

    // Set randao mix
    state.set_randao_mix(next_epoch, *state.get_randao_mix(current_epoch)?)?;

    // Set historical root accumulator
    if next_epoch.as_u64() % (T::SlotsPerHistoricalRoot::to_u64() / T::slots_per_epoch()) == 0 {
        let historical_batch = state.historical_batch();
        state
            .historical_roots
            .push(historical_batch.tree_hash_root())?;
    }

    // Rotate current/previous epoch attestations
    state.previous_epoch_attestations =
        std::mem::replace(&mut state.current_epoch_attestations, VariableList::empty());

    Ok(())
}
