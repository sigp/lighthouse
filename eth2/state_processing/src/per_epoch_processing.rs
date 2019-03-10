use attester_sets::AttesterSets;
use errors::EpochProcessingError as Error;
use fnv::FnvHashMap;
use fnv::FnvHashSet;
use integer_sqrt::IntegerSquareRoot;
use log::debug;
use rayon::prelude::*;
use ssz::TreeHash;
use std::collections::HashMap;
use std::iter::FromIterator;
use types::{validator_registry::get_active_validator_indices, *};
use winning_root::{winning_root, WinningRoot};

pub mod attester_sets;
pub mod errors;
pub mod inclusion_distance;
pub mod tests;
pub mod winning_root;

pub fn per_epoch_processing(state: &mut BeaconState, spec: &ChainSpec) -> Result<(), Error> {
    let previous_epoch = state.previous_epoch(spec);

    debug!(
        "Starting per-epoch processing on epoch {}...",
        state.current_epoch(spec)
    );

    // Ensure all of the caches are built.
    state.build_epoch_cache(RelativeEpoch::Previous, spec)?;
    state.build_epoch_cache(RelativeEpoch::Current, spec)?;
    state.build_epoch_cache(RelativeEpoch::Next, spec)?;

    let attesters = calculate_attester_sets(&state, spec)?;

    let active_validator_indices = calculate_active_validator_indices(&state, spec);

    let current_total_balance = state.get_total_balance(&active_validator_indices[..], spec);

    let previous_total_balance = state.get_total_balance(
        &get_active_validator_indices(&state.validator_registry, previous_epoch)[..],
        spec,
    );

    process_eth1_data(state, spec);

    process_justification(
        state,
        current_total_balance,
        previous_total_balance,
        attesters.previous_epoch_boundary.balance,
        attesters.current_epoch_boundary.balance,
        spec,
    );

    // Crosslinks
    let winning_root_for_shards = process_crosslinks(state, spec)?;

    // Rewards and Penalities
    process_rewards_and_penalities(
        state,
        &active_validator_indices,
        &attesters,
        previous_total_balance,
        &winning_root_for_shards,
        spec,
    )?;

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

    debug!("Epoch transition complete.");

    Ok(())
}

pub fn calculate_active_validator_indices(state: &BeaconState, spec: &ChainSpec) -> Vec<usize> {
    get_active_validator_indices(
        &state.validator_registry,
        state.slot.epoch(spec.slots_per_epoch),
    )
}

pub fn calculate_attester_sets(
    state: &BeaconState,
    spec: &ChainSpec,
) -> Result<AttesterSets, BeaconStateError> {
    AttesterSets::new(&state, spec)
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

/// Spec v0.4.0
pub fn process_justification(
    state: &mut BeaconState,
    current_total_balance: u64,
    previous_total_balance: u64,
    previous_epoch_boundary_attesting_balance: u64,
    current_epoch_boundary_attesting_balance: u64,
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
    if (3 * previous_epoch_boundary_attesting_balance) >= (2 * previous_total_balance) {
        state.justification_bitfield |= 2;
        new_justified_epoch = previous_epoch;
    }
    // If > 2/3 of the total balance attested to the previous epoch boundary
    //
    // - Set the 1st bit of the bitfield.
    // - Set the current epoch to be justified.
    if (3 * current_epoch_boundary_attesting_balance) >= (2 * current_total_balance) {
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

pub type WinningRootHashSet = HashMap<u64, WinningRoot>;

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

/// Spec v0.4.0
pub fn process_rewards_and_penalities(
    state: &mut BeaconState,
    active_validator_indices: &[usize],
    attesters: &AttesterSets,
    previous_total_balance: u64,
    winning_root_for_shards: &WinningRootHashSet,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let next_epoch = state.next_epoch(spec);

    let active_validator_indices: FnvHashSet<usize> =
        FnvHashSet::from_iter(active_validator_indices.iter().cloned());

    let previous_epoch_attestations: Vec<&PendingAttestation> = state
        .latest_attestations
        .par_iter()
        .filter(|a| a.data.slot.epoch(spec.slots_per_epoch) == state.previous_epoch(spec))
        .collect();

    let base_reward_quotient = previous_total_balance.integer_sqrt() / spec.base_reward_quotient;

    if base_reward_quotient == 0 {
        return Err(Error::BaseRewardQuotientIsZero);
    }
    if previous_total_balance == 0 {
        return Err(Error::PreviousTotalBalanceIsZero);
    }

    // Map is ValidatorIndex -> ProposerIndex
    let mut inclusion_slots: FnvHashMap<usize, (Slot, usize)> = FnvHashMap::default();
    for a in &previous_epoch_attestations {
        let participants =
            state.get_attestation_participants(&a.data, &a.aggregation_bitfield, spec)?;
        let inclusion_distance = (a.inclusion_slot - a.data.slot).as_u64();
        for participant in participants {
            if let Some((existing_distance, _)) = inclusion_slots.get(&participant) {
                if *existing_distance <= inclusion_distance {
                    continue;
                }
            }
            let proposer_index = state
                .get_beacon_proposer_index(a.data.slot, spec)
                .map_err(|_| Error::UnableToDetermineProducer)?;
            inclusion_slots.insert(
                participant,
                (Slot::from(inclusion_distance), proposer_index),
            );
        }
    }

    // Justification and finalization

    let epochs_since_finality = next_epoch - state.finalized_epoch;

    if epochs_since_finality <= 4 {
        state.validator_balances = state
            .validator_balances
            .par_iter()
            .enumerate()
            .map(|(index, &balance)| {
                let mut balance = balance;
                let base_reward = state.base_reward(index, base_reward_quotient, spec);

                // Expected FFG source
                if attesters.previous_epoch.indices.contains(&index) {
                    safe_add_assign!(
                        balance,
                        base_reward * attesters.previous_epoch.balance / previous_total_balance
                    );
                } else if active_validator_indices.contains(&index) {
                    safe_sub_assign!(balance, base_reward);
                }

                // Expected FFG target
                if attesters.previous_epoch_boundary.indices.contains(&index) {
                    safe_add_assign!(
                        balance,
                        base_reward * attesters.previous_epoch_boundary.balance
                            / previous_total_balance
                    );
                } else if active_validator_indices.contains(&index) {
                    safe_sub_assign!(balance, base_reward);
                }

                // Expected beacon chain head
                if attesters.previous_epoch_head.indices.contains(&index) {
                    safe_add_assign!(
                        balance,
                        base_reward * attesters.previous_epoch_head.balance
                            / previous_total_balance
                    );
                } else if active_validator_indices.contains(&index) {
                    safe_sub_assign!(balance, base_reward);
                };

                if attesters.previous_epoch.indices.contains(&index) {
                    let base_reward = state.base_reward(index, base_reward_quotient, spec);

                    let (inclusion_distance, _) = inclusion_slots
                        .get(&index)
                        .expect("Inconsistent inclusion_slots.");

                    if *inclusion_distance > 0 {
                        safe_add_assign!(
                            balance,
                            base_reward * spec.min_attestation_inclusion_delay
                                / inclusion_distance.as_u64()
                        )
                    }
                }

                balance
            })
            .collect();
    } else {
        state.validator_balances = state
            .validator_balances
            .par_iter()
            .enumerate()
            .map(|(index, &balance)| {
                let mut balance = balance;

                let inactivity_penalty = state.inactivity_penalty(
                    index,
                    epochs_since_finality,
                    base_reward_quotient,
                    spec,
                );

                if active_validator_indices.contains(&index) {
                    if !attesters.previous_epoch.indices.contains(&index) {
                        safe_sub_assign!(balance, inactivity_penalty);
                    }
                    if !attesters.previous_epoch_boundary.indices.contains(&index) {
                        safe_sub_assign!(balance, inactivity_penalty);
                    }
                    if !attesters.previous_epoch_head.indices.contains(&index) {
                        safe_sub_assign!(balance, inactivity_penalty);
                    }

                    if state.validator_registry[index].slashed {
                        let base_reward = state.base_reward(index, base_reward_quotient, spec);
                        safe_sub_assign!(balance, 2 * inactivity_penalty + base_reward);
                    }
                }

                if attesters.previous_epoch.indices.contains(&index) {
                    let base_reward = state.base_reward(index, base_reward_quotient, spec);

                    let (inclusion_distance, _) = inclusion_slots
                        .get(&index)
                        .expect("Inconsistent inclusion_slots.");

                    if *inclusion_distance > 0 {
                        safe_add_assign!(
                            balance,
                            base_reward * spec.min_attestation_inclusion_delay
                                / inclusion_distance.as_u64()
                        )
                    }
                }

                balance
            })
            .collect();
    }

    // Attestation inclusion
    //

    for &index in &attesters.previous_epoch.indices {
        let (_, proposer_index) = inclusion_slots
            .get(&index)
            .ok_or_else(|| Error::InclusionSlotsInconsistent(index))?;

        let base_reward = state.base_reward(*proposer_index, base_reward_quotient, spec);

        safe_add_assign!(
            state.validator_balances[*proposer_index],
            base_reward / spec.attestation_inclusion_reward_quotient
        );
    }

    //Crosslinks

    for slot in state.previous_epoch(spec).slot_iter(spec.slots_per_epoch) {
        // Clone removes the borrow which becomes an issue when mutating `state.balances`.
        let crosslink_committees_at_slot =
            state.get_crosslink_committees_at_slot(slot, spec)?.clone();

        for (crosslink_committee, shard) in crosslink_committees_at_slot {
            let shard = shard as u64;

            // Note: I'm a little uncertain of the logic here -- I am waiting for spec v0.5.0 to
            // clear it up.
            //
            // What happens here is:
            //
            // - If there was some crosslink root elected by the super-majority of this committee,
            // then we reward all who voted for that root and penalize all that did not.
            // - However, if there _was not_ some super-majority-voted crosslink root, then penalize
            // all the validators.
            //
            // I'm not quite sure that the second case (no super-majority crosslink) is correct.
            if let Some(winning_root) = winning_root_for_shards.get(&shard) {
                // Hash set de-dedups and (hopefully) offers a speed improvement from faster
                // lookups.
                let attesting_validator_indices: FnvHashSet<usize> =
                    FnvHashSet::from_iter(winning_root.attesting_validator_indices.iter().cloned());

                for &index in &crosslink_committee {
                    let base_reward = state.base_reward(index, base_reward_quotient, spec);

                    let total_balance = state.get_total_balance(&crosslink_committee, spec);

                    if attesting_validator_indices.contains(&index) {
                        safe_add_assign!(
                            state.validator_balances[index],
                            base_reward * winning_root.total_attesting_balance / total_balance
                        );
                    } else {
                        safe_sub_assign!(state.validator_balances[index], base_reward);
                    }
                }
            } else {
                for &index in &crosslink_committee {
                    let base_reward = state.base_reward(index, base_reward_quotient, spec);

                    safe_sub_assign!(state.validator_balances[index], base_reward);
                }
            }
        }
    }

    Ok(())
}

// Spec v0.4.0
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

// Spec v0.4.0
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

// Spec v0.4.0
pub fn update_latest_slashed_balances(state: &mut BeaconState, spec: &ChainSpec) {
    let current_epoch = state.current_epoch(spec);
    let next_epoch = state.next_epoch(spec);

    state.latest_slashed_balances[next_epoch.as_usize() % spec.latest_slashed_exit_length] =
        state.latest_slashed_balances[current_epoch.as_usize() % spec.latest_slashed_exit_length];
}

// Spec v0.4.0
pub fn clean_attestations(state: &mut BeaconState, spec: &ChainSpec) {
    let current_epoch = state.current_epoch(spec);

    state.latest_attestations = state
        .latest_attestations
        .iter()
        .filter(|a| a.data.slot.epoch(spec.slots_per_epoch) >= current_epoch)
        .cloned()
        .collect();
}
