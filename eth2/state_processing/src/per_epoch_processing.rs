use errors::{EpochProcessingError as Error, WinningRootError};
use grouped_attesters::GroupedAttesters;
use integer_sqrt::IntegerSquareRoot;
use log::{debug, trace};
use rayon::prelude::*;
use ssz::TreeHash;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use types::{validator_registry::get_active_validator_indices, *};
use winning_root::{winning_root, WinningRoot};

pub mod errors;
mod grouped_attesters;
mod tests;
mod winning_root;

macro_rules! safe_add_assign {
    ($a: expr, $b: expr) => {
        $a = $a.saturating_add($b);
    };
}
macro_rules! safe_sub_assign {
    ($a: expr, $b: expr) => {
        $a = $a.saturating_sub($b);
    };
}

pub fn per_epoch_processing(state: &mut BeaconState, spec: &ChainSpec) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);
    let previous_epoch = state.previous_epoch(spec);
    let next_epoch = state.next_epoch(spec);

    debug!(
        "Starting per-epoch processing on epoch {}...",
        state.current_epoch(spec)
    );

    // Ensure all of the caches are built.
    state.build_epoch_cache(RelativeEpoch::Previous, spec)?;
    state.build_epoch_cache(RelativeEpoch::Current, spec)?;
    state.build_epoch_cache(RelativeEpoch::Next, spec)?;

    let attesters = GroupedAttesters::new(&state, spec)?;

    let active_validator_indices = get_active_validator_indices(
        &state.validator_registry,
        state.slot.epoch(spec.slots_per_epoch),
    );

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
    let active_validator_indices_hashset: HashSet<usize> =
        HashSet::from_iter(active_validator_indices.iter().cloned());
    process_rewards_and_penalities(
        state,
        active_validator_indices_hashset,
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
    state.latest_active_index_roots[(next_epoch.as_usize()
        + spec.activation_exit_delay as usize)
        % spec.latest_active_index_roots_length] = hash_tree_root(get_active_validator_indices(
        &state.validator_registry,
        next_epoch + Epoch::from(spec.activation_exit_delay),
    ));

    state.latest_slashed_balances[next_epoch.as_usize() % spec.latest_slashed_exit_length] =
        state.latest_slashed_balances[current_epoch.as_usize() % spec.latest_slashed_exit_length];
    state.latest_randao_mixes[next_epoch.as_usize() % spec.latest_randao_mixes_length] = state
        .get_randao_mix(current_epoch, spec)
        .and_then(|x| Some(*x))
        .ok_or_else(|| Error::NoRandaoSeed)?;
    state.latest_attestations = state
        .latest_attestations
        .iter()
        .filter(|a| a.data.slot.epoch(spec.slots_per_epoch) >= current_epoch)
        .cloned()
        .collect();

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches();

    debug!("Epoch transition complete.");

    Ok(())
}

fn hash_tree_root<T: TreeHash>(input: Vec<T>) -> Hash256 {
    Hash256::from(&input.hash_tree_root()[..])
}

/// Spec v0.4.0
fn process_eth1_data(state: &mut BeaconState, spec: &ChainSpec) {
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
fn process_justification(
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

pub type WinningRootHashSet = HashMap<u64, Result<WinningRoot, WinningRootError>>;

fn process_crosslinks(
    state: &mut BeaconState,
    spec: &ChainSpec,
) -> Result<WinningRootHashSet, Error> {
    let current_epoch_attestations: Vec<&PendingAttestation> = state
        .latest_attestations
        .par_iter()
        .filter(|a| {
            (a.data.slot / spec.slots_per_epoch).epoch(spec.slots_per_epoch)
                == state.current_epoch(spec)
        })
        .collect();

    let previous_epoch_attestations: Vec<&PendingAttestation> = state
        .latest_attestations
        .par_iter()
        .filter(|a| {
            (a.data.slot / spec.slots_per_epoch).epoch(spec.slots_per_epoch)
                == state.previous_epoch(spec)
        })
        .collect();

    let mut winning_root_for_shards: HashMap<u64, Result<WinningRoot, WinningRootError>> =
        HashMap::new();
    // for slot in state.slot.saturating_sub(2 * spec.slots_per_epoch)..state.slot {
    for slot in state.previous_epoch(spec).slot_iter(spec.slots_per_epoch) {
        trace!(
            "Finding winning root for slot: {} (epoch: {})",
            slot,
            slot.epoch(spec.slots_per_epoch)
        );

        // Clone is used to remove the borrow. It becomes an issue later when trying to mutate
        // `state.balances`.
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
            );

            if let Ok(winning_root) = &winning_root {
                let total_committee_balance = state.get_total_balance(&crosslink_committee, spec);

                if (3 * winning_root.total_attesting_balance) >= (2 * total_committee_balance) {
                    state.latest_crosslinks[shard as usize] = Crosslink {
                        epoch: state.current_epoch(spec),
                        crosslink_data_root: winning_root.crosslink_data_root,
                    }
                }
            }
            winning_root_for_shards.insert(shard, winning_root);
        }
    }

    Ok(winning_root_for_shards)
}

fn process_rewards_and_penalities(
    state: &mut BeaconState,
    active_validator_indices: HashSet<usize>,
    attesters: &GroupedAttesters,
    previous_total_balance: u64,
    winning_root_for_shards: &HashMap<u64, Result<WinningRoot, WinningRootError>>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let next_epoch = state.next_epoch(spec);

    let previous_epoch_attestations: Vec<&PendingAttestation> = state
        .latest_attestations
        .par_iter()
        .filter(|a| {
            (a.data.slot / spec.slots_per_epoch).epoch(spec.slots_per_epoch)
                == state.previous_epoch(spec)
        })
        .collect();

    let base_reward_quotient = previous_total_balance.integer_sqrt() / spec.base_reward_quotient;
    if base_reward_quotient == 0 {
        return Err(Error::BaseRewardQuotientIsZero);
    }

    /*
     * Justification and finalization
     */
    let epochs_since_finality = next_epoch - state.finalized_epoch;

    let active_validator_indices_hashset: HashSet<usize> =
        HashSet::from_iter(active_validator_indices.iter().cloned());

    if epochs_since_finality <= 4 {
        for index in 0..state.validator_balances.len() {
            let base_reward = state.base_reward(index, base_reward_quotient, spec);

            if attesters.previous_epoch.indices.contains(&index) {
                safe_add_assign!(
                    state.validator_balances[index],
                    base_reward * attesters.previous_epoch.balance / previous_total_balance
                );
            } else if active_validator_indices_hashset.contains(&index) {
                safe_sub_assign!(state.validator_balances[index], base_reward);
            }

            if attesters.previous_epoch_boundary.indices.contains(&index) {
                safe_add_assign!(
                    state.validator_balances[index],
                    base_reward * attesters.previous_epoch_boundary.balance
                        / previous_total_balance
                );
            } else if active_validator_indices_hashset.contains(&index) {
                safe_sub_assign!(state.validator_balances[index], base_reward);
            }

            if attesters.previous_epoch_head.indices.contains(&index) {
                safe_add_assign!(
                    state.validator_balances[index],
                    base_reward * attesters.previous_epoch_head.balance / previous_total_balance
                );
            } else if active_validator_indices_hashset.contains(&index) {
                safe_sub_assign!(state.validator_balances[index], base_reward);
            }
        }

        for &index in &attesters.previous_epoch.indices {
            let base_reward = state.base_reward(index, base_reward_quotient, spec);
            let inclusion_distance =
                state.inclusion_distance(&previous_epoch_attestations, index, spec)?;

            safe_add_assign!(
                state.validator_balances[index],
                base_reward * spec.min_attestation_inclusion_delay / inclusion_distance
            )
        }
    } else {
        for index in 0..state.validator_balances.len() {
            let inactivity_penalty =
                state.inactivity_penalty(index, epochs_since_finality, base_reward_quotient, spec);
            if active_validator_indices_hashset.contains(&index) {
                if !attesters.previous_epoch.indices.contains(&index) {
                    safe_sub_assign!(state.validator_balances[index], inactivity_penalty);
                }
                if !attesters.previous_epoch_boundary.indices.contains(&index) {
                    safe_sub_assign!(state.validator_balances[index], inactivity_penalty);
                }
                if !attesters.previous_epoch_head.indices.contains(&index) {
                    safe_sub_assign!(state.validator_balances[index], inactivity_penalty);
                }

                if state.validator_registry[index].slashed {
                    let base_reward = state.base_reward(index, base_reward_quotient, spec);
                    safe_sub_assign!(
                        state.validator_balances[index],
                        2 * inactivity_penalty + base_reward
                    );
                }
            }
        }

        for &index in &attesters.previous_epoch.indices {
            let base_reward = state.base_reward(index, base_reward_quotient, spec);
            let inclusion_distance =
                state.inclusion_distance(&previous_epoch_attestations, index, spec)?;

            safe_sub_assign!(
                state.validator_balances[index],
                base_reward
                    - base_reward * spec.min_attestation_inclusion_delay / inclusion_distance
            );
        }
    }

    trace!("Processed validator justification and finalization rewards/penalities.");

    /*
     * Attestation inclusion
     */
    for &index in &attesters.previous_epoch.indices {
        let inclusion_slot = state.inclusion_slot(&previous_epoch_attestations[..], index, spec)?;
        let proposer_index = state
            .get_beacon_proposer_index(inclusion_slot, spec)
            .map_err(|_| Error::UnableToDetermineProducer)?;
        let base_reward = state.base_reward(proposer_index, base_reward_quotient, spec);
        safe_add_assign!(
            state.validator_balances[proposer_index],
            base_reward / spec.attestation_inclusion_reward_quotient
        );
    }

    /*
     * Crosslinks
     */
    for slot in state.previous_epoch(spec).slot_iter(spec.slots_per_epoch) {
        // Clone is used to remove the borrow. It becomes an issue later when trying to mutate
        // `state.balances`.
        let crosslink_committees_at_slot =
            state.get_crosslink_committees_at_slot(slot, spec)?.clone();

        for (_crosslink_committee, shard) in crosslink_committees_at_slot {
            let shard = shard as u64;

            if let Some(Ok(winning_root)) = winning_root_for_shards.get(&shard) {
                // TODO: remove the map.
                let attesting_validator_indices: HashSet<usize> =
                    HashSet::from_iter(winning_root.attesting_validator_indices.iter().cloned());

                for index in 0..state.validator_balances.len() {
                    let base_reward = state.base_reward(index, base_reward_quotient, spec);

                    if attesting_validator_indices.contains(&index) {
                        safe_add_assign!(
                            state.validator_balances[index],
                            base_reward * winning_root.total_attesting_balance
                                / winning_root.total_balance
                        );
                    } else {
                        safe_sub_assign!(state.validator_balances[index], base_reward);
                    }
                }

                for index in &winning_root.attesting_validator_indices {
                    let base_reward = state.base_reward(*index, base_reward_quotient, spec);
                    safe_add_assign!(
                        state.validator_balances[*index],
                        base_reward * winning_root.total_attesting_balance
                            / winning_root.total_balance
                    );
                }
            }
        }
    }

    Ok(())
}

fn process_validator_registry(state: &mut BeaconState, spec: &ChainSpec) -> Result<(), Error> {
    let current_epoch = state.current_epoch(spec);
    let next_epoch = state.next_epoch(spec);

    state.previous_shuffling_epoch = state.current_shuffling_epoch;
    state.previous_shuffling_start_shard = state.current_shuffling_start_shard;

    debug!(
        "setting previous_shuffling_seed to : {}",
        state.current_shuffling_seed
    );

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
        trace!("updating validator registry.");
        state.update_validator_registry(spec);

        state.current_shuffling_epoch = next_epoch;
        state.current_shuffling_start_shard = (state.current_shuffling_start_shard
            + state.get_current_epoch_committee_count(spec) as u64)
            % spec.shard_count;
        state.current_shuffling_seed = state.generate_seed(state.current_shuffling_epoch, spec)?
    } else {
        trace!("not updating validator registry.");
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
