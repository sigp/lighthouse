use errors::EpochProcessingError as Error;
use integer_sqrt::IntegerSquareRoot;
use rayon::prelude::*;
use ssz::TreeHash;
use std::collections::HashMap;
use types::{validator_registry::get_active_validator_indices, *};
use validator_statuses::{TotalBalances, ValidatorStatuses};
use winning_root::{winning_root, WinningRoot};

pub mod errors;
pub mod inclusion_distance;
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
/// Spec v0.4.0
pub fn per_epoch_processing(state: &mut BeaconState, spec: &ChainSpec) -> Result<(), Error> {
    // Ensure all of the caches are built.
    state.build_epoch_cache(RelativeEpoch::Previous, spec)?;
    state.build_epoch_cache(RelativeEpoch::Current, spec)?;
    state.build_epoch_cache(RelativeEpoch::Next, spec)?;

    let mut statuses = initialize_validator_statuses(&state, spec)?;

    process_eth1_data(state, spec);

    process_justification(state, &statuses.total_balances, spec);

    // Crosslinks
    let winning_root_for_shards = process_crosslinks(state, spec)?;

    // Rewards and Penalities
    process_rewards_and_penalities(state, &mut statuses, &winning_root_for_shards, spec)?;

    // Ejections
    state.process_ejections(spec);

    // Validator Registry
    process_validator_registry(state, spec)?;

    // Final updates
    update_active_tree_index_roots(state, spec)?;
    update_latest_slashed_balances(state, spec);
    clean_attestations(state, spec);

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches();

    Ok(())
}

/// Returns a list of active validator indices for the state's current epoch.
///
/// Spec v0.4.0
pub fn calculate_active_validator_indices(state: &BeaconState, spec: &ChainSpec) -> Vec<usize> {
    get_active_validator_indices(
        &state.validator_registry,
        state.slot.epoch(spec.slots_per_epoch),
    )
}

/// Calculates various sets of attesters, including:
///
/// - current epoch attesters
/// - current epoch boundary attesters
/// - previous epoch attesters
/// - etc.
///
/// Spec v0.4.0
pub fn initialize_validator_statuses(
    state: &BeaconState,
    spec: &ChainSpec,
) -> Result<ValidatorStatuses, BeaconStateError> {
    let mut statuses = ValidatorStatuses::new(state, spec);

    statuses.process_attestations(&state, &state.latest_attestations, spec)?;

    Ok(statuses)
}

/// Spec v0.4.0
pub fn process_eth1_data(state: &mut BeaconState, spec: &ChainSpec) {
    let next_epoch = state.next_epoch(spec);
    let voting_period = spec.epochs_per_eth1_voting_period;

    if next_epoch % voting_period == 0 {
        for eth1_data_vote in &state.eth1_data_votes {
            if eth1_data_vote.vote_count * 2 > voting_period {
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
/// Spec v0.4.0
pub fn process_justification(
    state: &mut BeaconState,
    total_balances: &TotalBalances,
    spec: &ChainSpec,
) {
    let previous_epoch = state.previous_epoch(spec);
    let current_epoch = state.current_epoch(spec);

    let mut new_justified_epoch = state.justified_epoch;
    state.justification_bitfield <<= 1;

    // If > 2/3 of the total balance attested to the previous epoch boundary
    //
    // - Set the 2nd bit of the bitfield.
    // - Set the previous epoch to be justified.
    if (3 * total_balances.previous_epoch_boundary_attesters) >= (2 * total_balances.previous_epoch)
    {
        state.justification_bitfield |= 2;
        new_justified_epoch = previous_epoch;
    }
    // If > 2/3 of the total balance attested to the previous epoch boundary
    //
    // - Set the 1st bit of the bitfield.
    // - Set the current epoch to be justified.
    if (3 * total_balances.current_epoch_boundary_attesters) >= (2 * total_balances.current_epoch) {
        state.justification_bitfield |= 1;
        new_justified_epoch = current_epoch;
    }

    // If:
    //
    // - All three epochs prior to this epoch have been justified.
    // - The previous justified justified epoch was three epochs ago.
    //
    // Then, set the finalized epoch to be three epochs ago.
    if ((state.justification_bitfield >> 1) % 8 == 0b111)
        & (state.previous_justified_epoch == previous_epoch - 2)
    {
        state.finalized_epoch = state.previous_justified_epoch;
    }
    // If:
    //
    // - Both two epochs prior to this epoch have been justified.
    // - The previous justified epoch was two epochs ago.
    //
    // Then, set the finalized epoch to two epochs ago.
    if ((state.justification_bitfield >> 1) % 4 == 0b11)
        & (state.previous_justified_epoch == previous_epoch - 1)
    {
        state.finalized_epoch = state.previous_justified_epoch;
    }
    // If:
    //
    // - This epoch and the two prior have been justified.
    // - The presently justified epoch was two epochs ago.
    //
    // Then, set the finalized epoch to two epochs ago.
    if (state.justification_bitfield % 8 == 0b111) & (state.justified_epoch == previous_epoch - 1) {
        state.finalized_epoch = state.justified_epoch;
    }
    // If:
    //
    // - This epoch and the epoch prior to it have been justified.
    // - Set the previous epoch to be justified.
    //
    // Then, set the finalized epoch to be the previous epoch.
    if (state.justification_bitfield % 4 == 0b11) & (state.justified_epoch == previous_epoch) {
        state.finalized_epoch = state.justified_epoch;
    }

    state.previous_justified_epoch = state.justified_epoch;
    state.justified_epoch = new_justified_epoch;
}

/// Updates the following fields on the `BeaconState`:
///
/// - `latest_crosslinks`
///
/// Also returns a `WinningRootHashSet` for later use during epoch processing.
///
/// Spec v0.4.0
pub fn process_crosslinks(
    state: &mut BeaconState,
    spec: &ChainSpec,
) -> Result<WinningRootHashSet, Error> {
    let current_epoch_attestations: Vec<&PendingAttestation> = state
        .latest_attestations
        .par_iter()
        .filter(|a| a.data.slot.epoch(spec.slots_per_epoch) == state.current_epoch(spec))
        .collect();

    let previous_epoch_attestations: Vec<&PendingAttestation> = state
        .latest_attestations
        .par_iter()
        .filter(|a| a.data.slot.epoch(spec.slots_per_epoch) == state.previous_epoch(spec))
        .collect();

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

        for (crosslink_committee, shard) in crosslink_committees_at_slot {
            let shard = shard as u64;

            let winning_root = winning_root(
                state,
                shard,
                &current_epoch_attestations[..],
                &previous_epoch_attestations[..],
                spec,
            )?;

            if let Some(winning_root) = winning_root {
                let total_committee_balance = state.get_total_balance(&crosslink_committee, spec);

                // TODO: I think this has a bug.
                if (3 * winning_root.total_attesting_balance) >= (2 * total_committee_balance) {
                    state.latest_crosslinks[shard as usize] = Crosslink {
                        epoch: state.current_epoch(spec),
                        crosslink_data_root: winning_root.crosslink_data_root,
                    }
                }
                winning_root_for_shards.insert(shard, winning_root);
            }
        }
    }

    Ok(winning_root_for_shards)
}

/// Updates the following fields on the BeaconState:
///
/// - `validator_balances`
///
/// Spec v0.4.0
pub fn process_rewards_and_penalities(
    state: &mut BeaconState,
    statuses: &mut ValidatorStatuses,
    winning_root_for_shards: &WinningRootHashSet,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let next_epoch = state.next_epoch(spec);

    statuses.process_winning_roots(state, winning_root_for_shards, spec)?;

    let total_balances = &statuses.total_balances;

    let base_reward_quotient =
        total_balances.previous_epoch.integer_sqrt() / spec.base_reward_quotient;

    // Guard against a divide-by-zero during the validator balance update.
    if base_reward_quotient == 0 {
        return Err(Error::BaseRewardQuotientIsZero);
    }
    // Guard against a divide-by-zero during the validator balance update.
    if total_balances.previous_epoch == 0 {
        return Err(Error::PreviousTotalBalanceIsZero);
    }
    // Guard against an out-of-bounds during the validator balance update.
    if statuses.statuses.len() != state.validator_balances.len() {
        return Err(Error::ValidatorStatusesInconsistent);
    }

    // Justification and finalization

    let epochs_since_finality = next_epoch - state.finalized_epoch;

    state.validator_balances = state
        .validator_balances
        .par_iter()
        .enumerate()
        .map(|(index, &balance)| {
            let mut balance = balance;
            let status = &statuses.statuses[index];
            let base_reward = state.base_reward(index, base_reward_quotient, spec);

            if epochs_since_finality <= 4 {
                // Expected FFG source
                if status.is_previous_epoch_attester {
                    safe_add_assign!(
                        balance,
                        base_reward * total_balances.previous_epoch_attesters
                            / total_balances.previous_epoch
                    );
                } else if status.is_active_in_previous_epoch {
                    safe_sub_assign!(balance, base_reward);
                }

                // Expected FFG target
                if status.is_previous_epoch_boundary_attester {
                    safe_add_assign!(
                        balance,
                        base_reward * total_balances.previous_epoch_boundary_attesters
                            / total_balances.previous_epoch
                    );
                } else if status.is_active_in_previous_epoch {
                    safe_sub_assign!(balance, base_reward);
                }

                // Expected beacon chain head
                if status.is_previous_epoch_head_attester {
                    safe_add_assign!(
                        balance,
                        base_reward * total_balances.previous_epoch_head_attesters
                            / total_balances.previous_epoch
                    );
                } else if status.is_active_in_previous_epoch {
                    safe_sub_assign!(balance, base_reward);
                };
            } else {
                let inactivity_penalty = state.inactivity_penalty(
                    index,
                    epochs_since_finality,
                    base_reward_quotient,
                    spec,
                );

                if status.is_active_in_previous_epoch {
                    if !status.is_previous_epoch_attester {
                        safe_sub_assign!(balance, inactivity_penalty);
                    }
                    if !status.is_previous_epoch_boundary_attester {
                        safe_sub_assign!(balance, inactivity_penalty);
                    }
                    if !status.is_previous_epoch_head_attester {
                        safe_sub_assign!(balance, inactivity_penalty);
                    }

                    if state.validator_registry[index].slashed {
                        let base_reward = state.base_reward(index, base_reward_quotient, spec);
                        safe_sub_assign!(balance, 2 * inactivity_penalty + base_reward);
                    }
                }
            }

            // Crosslinks

            if let Some(ref info) = status.winning_root_info {
                safe_add_assign!(
                    balance,
                    base_reward * info.total_attesting_balance / info.total_committee_balance
                );
            } else {
                safe_sub_assign!(balance, base_reward);
            }

            balance
        })
        .collect();

    // Attestation inclusion

    // Guard against an out-of-bounds during the attester inclusion balance update.
    if statuses.statuses.len() != state.validator_registry.len() {
        return Err(Error::ValidatorStatusesInconsistent);
    }

    for (index, _validator) in state.validator_registry.iter().enumerate() {
        let status = &statuses.statuses[index];

        if status.is_previous_epoch_attester {
            let proposer_index = status.inclusion_info.proposer_index;
            let inclusion_distance = status.inclusion_info.distance;

            let base_reward = state.base_reward(proposer_index, base_reward_quotient, spec);

            if inclusion_distance > 0 && inclusion_distance < Slot::max_value() {
                safe_add_assign!(
                    state.validator_balances[proposer_index],
                    base_reward * spec.min_attestation_inclusion_delay
                        / inclusion_distance.as_u64()
                )
            }
        }
    }

    Ok(())
}

/// Peforms a validator registry update, if required.
///
/// Spec v0.4.0
pub fn process_validator_registry(state: &mut BeaconState, spec: &ChainSpec) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);
    let next_epoch = state.next_epoch(spec);

    state.previous_shuffling_epoch = state.current_shuffling_epoch;
    state.previous_shuffling_start_shard = state.current_shuffling_start_shard;

    state.previous_shuffling_seed = state.current_shuffling_seed;

    let should_update_validator_registy = if state.finalized_epoch
        > state.validator_registry_update_epoch
    {
        (0..state.get_current_epoch_committee_count(spec)).all(|i| {
            let shard = (state.current_shuffling_start_shard + i as u64) % spec.shard_count;
            state.latest_crosslinks[shard as usize].epoch > state.validator_registry_update_epoch
        })
    } else {
        false
    };

    if should_update_validator_registy {
        state.update_validator_registry(spec);

        state.current_shuffling_epoch = next_epoch;
        state.current_shuffling_start_shard = (state.current_shuffling_start_shard
            + state.get_current_epoch_committee_count(spec) as u64)
            % spec.shard_count;
        state.current_shuffling_seed = state.generate_seed(state.current_shuffling_epoch, spec)?
    } else {
        let epochs_since_last_registry_update =
            current_epoch - state.validator_registry_update_epoch;
        if (epochs_since_last_registry_update > 1)
            & epochs_since_last_registry_update.is_power_of_two()
        {
            state.current_shuffling_epoch = next_epoch;
            state.current_shuffling_seed =
                state.generate_seed(state.current_shuffling_epoch, spec)?
        }
    }

    state.process_slashings(spec);
    state.process_exit_queue(spec);

    Ok(())
}

/// Updates the state's `latest_active_index_roots` field with a tree hash the active validator
/// indices for the next epoch.
///
/// Spec v0.4.0
pub fn update_active_tree_index_roots(
    state: &mut BeaconState,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let next_epoch = state.next_epoch(spec);

    let active_tree_root = get_active_validator_indices(
        &state.validator_registry,
        next_epoch + Epoch::from(spec.activation_exit_delay),
    )
    .hash_tree_root();

    state.latest_active_index_roots[(next_epoch.as_usize()
        + spec.activation_exit_delay as usize)
        % spec.latest_active_index_roots_length] = Hash256::from_slice(&active_tree_root[..]);

    Ok(())
}

/// Advances the state's `latest_slashed_balances` field.
///
/// Spec v0.4.0
pub fn update_latest_slashed_balances(state: &mut BeaconState, spec: &ChainSpec) {
    let current_epoch = state.current_epoch(spec);
    let next_epoch = state.next_epoch(spec);

    state.latest_slashed_balances[next_epoch.as_usize() % spec.latest_slashed_exit_length] =
        state.latest_slashed_balances[current_epoch.as_usize() % spec.latest_slashed_exit_length];
}

/// Removes all pending attestations from the previous epoch.
///
/// Spec v0.4.0
pub fn clean_attestations(state: &mut BeaconState, spec: &ChainSpec) {
    let current_epoch = state.current_epoch(spec);

    state.latest_attestations = state
        .latest_attestations
        .iter()
        .filter(|a| a.data.slot.epoch(spec.slots_per_epoch) >= current_epoch)
        .cloned()
        .collect();
}
