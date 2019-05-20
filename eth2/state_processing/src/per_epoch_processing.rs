use apply_rewards::apply_rewards;
use errors::EpochProcessingError as Error;
use process_ejections::process_ejections;
use process_exit_queue::process_exit_queue;
use process_slashings::process_slashings;
use std::collections::HashMap;
use tree_hash::TreeHash;
use types::*;
use update_registry_and_shuffling_data::update_registry_and_shuffling_data;
use validator_statuses::{TotalBalances, ValidatorStatuses};
use winning_root::{winning_root, WinningRoot};

pub mod apply_rewards;
pub mod errors;
pub mod get_attestation_participants;
pub mod inclusion_distance;
pub mod process_ejections;
pub mod process_exit_queue;
pub mod process_slashings;
pub mod tests;
pub mod update_registry_and_shuffling_data;
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
/// Spec v0.5.1
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

    // Justification.
    update_justification_and_finalization(state, &validator_statuses.total_balances, spec)?;

    // Crosslinks.
    let winning_root_for_shards = process_crosslinks(state, spec)?;

    // Eth1 data.
    maybe_reset_eth1_period(state, spec);

    // Rewards and Penalities.
    apply_rewards(
        state,
        &mut validator_statuses,
        &winning_root_for_shards,
        spec,
    )?;

    // Ejections.
    process_ejections(state, spec)?;

    // Validator Registry.
    update_registry_and_shuffling_data(
        state,
        validator_statuses.total_balances.current_epoch,
        spec,
    )?;

    // Slashings and exit queue.
    process_slashings(state, validator_statuses.total_balances.current_epoch, spec)?;
    process_exit_queue(state, spec);

    // Final updates.
    finish_epoch_update(state, spec)?;

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches();

    Ok(())
}

/// Maybe resets the eth1 period.
///
/// Spec v0.5.1
pub fn maybe_reset_eth1_period<T: EthSpec>(state: &mut BeaconState<T>, spec: &ChainSpec) {
    let next_epoch = state.next_epoch(spec);
    let voting_period = spec.epochs_per_eth1_voting_period;

    if next_epoch % voting_period == 0 {
        for eth1_data_vote in &state.eth1_data_votes {
            if eth1_data_vote.vote_count * 2 > voting_period * spec.slots_per_epoch {
                state.latest_eth1_data = eth1_data_vote.eth1_data.clone();
            }
        }
        state.eth1_data_votes = vec![];
    }
}

/// Update the following fields on the `BeaconState`:
///
/// - `justification_bitfield`.
/// - `finalized_epoch`
/// - `justified_epoch`
/// - `previous_justified_epoch`
///
/// Spec v0.5.1
pub fn update_justification_and_finalization<T: EthSpec>(
    state: &mut BeaconState<T>,
    total_balances: &TotalBalances,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let previous_epoch = state.previous_epoch(spec);
    let current_epoch = state.current_epoch(spec);

    let mut new_justified_epoch = state.current_justified_epoch;
    let mut new_finalized_epoch = state.finalized_epoch;

    // Rotate the justification bitfield up one epoch to make room for the current epoch.
    state.justification_bitfield <<= 1;

    // If the previous epoch gets justified, full the second last bit.
    if (total_balances.previous_epoch_boundary_attesters * 3) >= (total_balances.previous_epoch * 2)
    {
        new_justified_epoch = previous_epoch;
        state.justification_bitfield |= 2;
    }
    // If the current epoch gets justified, fill the last bit.
    if (total_balances.current_epoch_boundary_attesters * 3) >= (total_balances.current_epoch * 2) {
        new_justified_epoch = current_epoch;
        state.justification_bitfield |= 1;
    }

    let bitfield = state.justification_bitfield;

    // The 2nd/3rd/4th most recent epochs are all justified, the 2nd using the 4th as source.
    if ((bitfield >> 1) % 8 == 0b111) & (state.previous_justified_epoch == current_epoch - 3) {
        new_finalized_epoch = state.previous_justified_epoch;
    }
    // The 2nd/3rd most recent epochs are both justified, the 2nd using the 3rd as source.
    if ((bitfield >> 1) % 4 == 0b11) & (state.previous_justified_epoch == current_epoch - 2) {
        new_finalized_epoch = state.previous_justified_epoch;
    }
    // The 1st/2nd/3rd most recent epochs are all justified, the 1st using the 2nd as source.
    if (bitfield % 8 == 0b111) & (state.current_justified_epoch == current_epoch - 2) {
        new_finalized_epoch = state.current_justified_epoch;
    }
    // The 1st/2nd most recent epochs are both justified, the 1st using the 2nd as source.
    if (bitfield % 4 == 0b11) & (state.current_justified_epoch == current_epoch - 1) {
        new_finalized_epoch = state.current_justified_epoch;
    }

    state.previous_justified_epoch = state.current_justified_epoch;
    state.previous_justified_root = state.current_justified_root;

    if new_justified_epoch != state.current_justified_epoch {
        state.current_justified_epoch = new_justified_epoch;
        state.current_justified_root =
            *state.get_block_root(new_justified_epoch.start_slot(spec.slots_per_epoch))?;
    }

    if new_finalized_epoch != state.finalized_epoch {
        state.finalized_epoch = new_finalized_epoch;
        state.finalized_root =
            *state.get_block_root(new_finalized_epoch.start_slot(spec.slots_per_epoch))?;
    }

    Ok(())
}

/// Updates the following fields on the `BeaconState`:
///
/// - `latest_crosslinks`
///
/// Also returns a `WinningRootHashSet` for later use during epoch processing.
///
/// Spec v0.5.1
pub fn process_crosslinks<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<WinningRootHashSet, Error> {
    let mut winning_root_for_shards: WinningRootHashSet = HashMap::new();

    let previous_and_current_epoch_slots: Vec<Slot> = state
        .previous_epoch(spec)
        .slot_iter(spec.slots_per_epoch)
        .chain(state.current_epoch(spec).slot_iter(spec.slots_per_epoch))
        .collect();

    for slot in previous_and_current_epoch_slots {
        // Clone removes the borrow which becomes an issue when mutating `state.balances`.
        let crosslink_committees_at_slot =
            state.get_crosslink_committees_at_slot(slot, spec)?.clone();

        for c in crosslink_committees_at_slot {
            let shard = c.shard as u64;

            let winning_root = winning_root(state, shard, spec)?;

            if let Some(winning_root) = winning_root {
                let total_committee_balance = state.get_total_balance(&c.committee, spec)?;

                // TODO: I think this has a bug.
                if (3 * winning_root.total_attesting_balance) >= (2 * total_committee_balance) {
                    state.latest_crosslinks[shard as usize] = Crosslink {
                        epoch: slot.epoch(spec.slots_per_epoch),
                        crosslink_data_root: winning_root.crosslink_data_root,
                    }
                }
                winning_root_for_shards.insert(shard, winning_root);
            }
        }
    }

    Ok(winning_root_for_shards)
}

/// Finish up an epoch update.
///
/// Spec v0.5.1
pub fn finish_epoch_update<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);
    let next_epoch = state.next_epoch(spec);

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
        state.set_randao_mix(
            next_epoch,
            *state.get_randao_mix(current_epoch, spec)?,
            spec,
        )?;

        state.slot -= 1;
    }

    if next_epoch.as_u64() % (T::SlotsPerHistoricalRoot::to_u64() / spec.slots_per_epoch) == 0 {
        let historical_batch = state.historical_batch();
        state
            .historical_roots
            .push(Hash256::from_slice(&historical_batch.tree_hash_root()[..]));
    }

    state.previous_epoch_attestations = state.current_epoch_attestations.clone();
    state.current_epoch_attestations = vec![];

    Ok(())
}
