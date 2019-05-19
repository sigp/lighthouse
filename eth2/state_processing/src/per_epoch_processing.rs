use apply_rewards::process_rewards_and_penalties;
use errors::EpochProcessingError as Error;
use process_slashings::process_slashings;
use registry_updates::process_registry_updates;
use std::collections::HashMap;
use tree_hash::TreeHash;
use types::*;
use validator_statuses::{TotalBalances, ValidatorStatuses};
use winning_root::{winning_root, WinningRoot};

pub mod apply_rewards;
pub mod errors;
pub mod get_attesting_indices;
pub mod inclusion_distance;
pub mod process_slashings;
pub mod registry_updates;
pub mod tests;
pub mod validator_statuses;
pub mod winning_root;

/// Maps a shard to a winning root.
///
/// It is generated during crosslink processing and later used to reward/penalize validators.
pub type WinningRootHashSet = HashMap<u64, WinningRoot>;

/// Performs per-epoch processing on some BeaconState.
///
/// Mutates the given `BeaconState`, returning early if an error is encountered. If an error is
/// returned, a state might be "half-processed" and therefore in an invalid state.
///
/// Spec v0.6.1
pub fn per_epoch_processing<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Ensure the previous and next epoch caches are built.
    state.build_epoch_cache(RelativeEpoch::Previous, spec)?;
    state.build_epoch_cache(RelativeEpoch::Current, spec)?;

    // Load the struct we use to assign validators into sets based on their participation.
    //
    // E.g., attestation in the previous epoch, attested to the head, etc.
    let mut validator_statuses = ValidatorStatuses::new(state, spec)?;
    validator_statuses.process_attestations(&state, spec)?;

    // Justification and finalization.
    process_justification_and_finalization(state, &validator_statuses.total_balances, spec)?;

    // Crosslinks.
    let winning_root_for_shards = process_crosslinks(state, spec)?;

    // Rewards and Penalities.
    process_rewards_and_penalties(
        state,
        &mut validator_statuses,
        &winning_root_for_shards,
        spec,
    )?;

    // Registry Updates.
    process_registry_updates(state, spec)?;

    // Slashings.
    process_slashings(state, validator_statuses.total_balances.current_epoch, spec)?;

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
/// Spec v0.6.1
pub fn process_justification_and_finalization<T: EthSpec>(
    state: &mut BeaconState<T>,
    total_balances: &TotalBalances,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if state.current_epoch() == spec.genesis_epoch {
        return Ok(());
    }

    let previous_epoch = state.previous_epoch();
    let current_epoch = state.current_epoch();

    let old_previous_justified_epoch = state.previous_justified_epoch;
    let old_current_justified_epoch = state.current_justified_epoch;

    // Process justifications
    state.previous_justified_epoch = state.current_justified_epoch;
    state.previous_justified_root = state.current_justified_root;
    state.justification_bitfield <<= 1;

    if total_balances.previous_epoch_target_attesters * 3 >= total_balances.previous_epoch * 2 {
        state.current_justified_epoch = previous_epoch;
        state.current_justified_root =
            *state.get_block_root_at_epoch(state.current_justified_epoch, spec)?;
        state.justification_bitfield |= 2;
    }
    // If the current epoch gets justified, fill the last bit.
    if total_balances.current_epoch_target_attesters * 3 >= total_balances.current_epoch * 2 {
        state.current_justified_epoch = current_epoch;
        state.current_justified_root =
            *state.get_block_root_at_epoch(state.current_justified_epoch, spec)?;
        state.justification_bitfield |= 1;
    }

    let bitfield = state.justification_bitfield;

    // The 2nd/3rd/4th most recent epochs are all justified, the 2nd using the 4th as source.
    if (bitfield >> 1) % 8 == 0b111 && old_previous_justified_epoch == current_epoch - 3 {
        state.finalized_epoch = old_previous_justified_epoch;
        state.finalized_root = *state.get_block_root_at_epoch(state.finalized_epoch, spec)?;
    }
    // The 2nd/3rd most recent epochs are both justified, the 2nd using the 3rd as source.
    if (bitfield >> 1) % 4 == 0b11 && state.previous_justified_epoch == current_epoch - 2 {
        state.finalized_epoch = old_previous_justified_epoch;
        state.finalized_root = *state.get_block_root_at_epoch(state.finalized_epoch, spec)?;
    }
    // The 1st/2nd/3rd most recent epochs are all justified, the 1st using the 2nd as source.
    if bitfield % 8 == 0b111 && state.current_justified_epoch == current_epoch - 2 {
        state.finalized_epoch = old_current_justified_epoch;
        state.finalized_root = *state.get_block_root_at_epoch(state.finalized_epoch, spec)?;
    }
    // The 1st/2nd most recent epochs are both justified, the 1st using the 2nd as source.
    if bitfield % 4 == 0b11 && state.current_justified_epoch == current_epoch - 1 {
        state.finalized_epoch = old_current_justified_epoch;
        state.finalized_root = *state.get_block_root_at_epoch(state.finalized_epoch, spec)?;
    }

    Ok(())
}

/// Updates the following fields on the `BeaconState`:
///
/// - `previous_crosslinks`
/// - `current_crosslinks`
///
/// Also returns a `WinningRootHashSet` for later use during epoch processing.
///
/// Spec v0.6.1
pub fn process_crosslinks<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<WinningRootHashSet, Error> {
    let mut winning_root_for_shards: WinningRootHashSet = HashMap::new();

    state.previous_crosslinks = state.current_crosslinks.clone();

    for epoch in vec![state.previous_epoch(), state.current_epoch()] {
        for offset in 0..state.get_epoch_committee_count(epoch, spec) {
            let shard = (state.get_epoch_start_shard(epoch, spec) + offset) % spec.shard_count;
            let crosslink_committee = state.get_crosslink_committee(epoch, shard, spec)?;

            let winning_root = winning_root(state, shard, epoch, spec)?;

            if let Some(winning_root) = winning_root {
                let total_committee_balance =
                    state.get_total_balance(&crosslink_committee.committee, spec)?;

                if 3 * winning_root.total_attesting_balance >= 2 * total_committee_balance {
                    state.current_crosslinks[shard as usize] = winning_root.crosslink.clone();
                }
                winning_root_for_shards.insert(shard, winning_root);
            }
        }
    }

    Ok(winning_root_for_shards)
}

/// Finish up an epoch update.
///
/// Spec v0.6.1
pub fn process_final_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state.current_epoch();
    let next_epoch = state.next_epoch();

    // Reset eth1 data votes.
    if (state.slot + 1) % spec.slots_per_eth1_voting_period == 0 {
        state.eth1_data_votes = vec![];
    }

    // Update effective balances with hysteresis (lag).
    for (index, validator) in state.validator_registry.iter_mut().enumerate() {
        let balance = state.balances[index];
        let half_increment = spec.effective_balance_increment / 2;
        if balance < validator.effective_balance
            || validator.effective_balance + 3 * half_increment < balance
        {
            validator.effective_balance = std::cmp::min(
                balance - balance % spec.effective_balance_increment,
                spec.max_effective_balance,
            );
        }
    }

    // Update start shard.
    state.latest_start_shard = (state.latest_start_shard
        + state.get_shard_delta(current_epoch, spec))
        % T::ShardCount::to_u64();

    // This is a hack to allow us to update index roots and slashed balances for the next epoch.
    //
    // The indentation here is to make it obvious where the weird stuff happens.
    {
        state.slot += 1;

        // Set active index root
        let active_index_root = Hash256::from_slice(
            &state
                .get_active_validator_indices(next_epoch + spec.activation_exit_delay)
                .tree_hash_root()[..],
        );
        state.set_active_index_root(next_epoch, active_index_root, spec)?;

        // Set total slashed balances
        state.set_slashed_balance(next_epoch, state.get_slashed_balance(current_epoch)?)?;

        // Set randao mix
        state.set_randao_mix(next_epoch, *state.get_randao_mix(current_epoch)?)?;

        state.slot -= 1;
    }

    if next_epoch.as_u64() % (T::SlotsPerHistoricalRoot::to_u64() / spec.slots_per_epoch) == 0 {
        let historical_batch = state.historical_batch();
        state
            .historical_roots
            .push(Hash256::from_slice(&historical_batch.tree_hash_root()[..]));
    }

    // Rotate current/previous epoch attestations
    state.previous_epoch_attestations =
        std::mem::replace(&mut state.current_epoch_attestations, vec![]);

    Ok(())
}
