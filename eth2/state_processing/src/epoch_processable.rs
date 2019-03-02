use integer_sqrt::IntegerSquareRoot;
use log::{debug, trace};
use rayon::prelude::*;
use ssz::TreeHash;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use types::{
    validator_registry::get_active_validator_indices, BeaconState, BeaconStateError, ChainSpec,
    Crosslink, Epoch, Hash256, InclusionError, PendingAttestation, RelativeEpoch,
};

mod tests;

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

#[derive(Debug, PartialEq)]
pub enum Error {
    UnableToDetermineProducer,
    NoBlockRoots,
    BaseRewardQuotientIsZero,
    NoRandaoSeed,
    BeaconStateError(BeaconStateError),
    InclusionError(InclusionError),
    WinningRootError(WinningRootError),
}

#[derive(Debug, PartialEq)]
pub enum WinningRootError {
    NoWinningRoot,
    BeaconStateError(BeaconStateError),
}

#[derive(Clone)]
pub struct WinningRoot {
    pub shard_block_root: Hash256,
    pub attesting_validator_indices: Vec<usize>,
    pub total_balance: u64,
    pub total_attesting_balance: u64,
}

pub trait EpochProcessable {
    fn per_epoch_processing(&mut self, spec: &ChainSpec) -> Result<(), Error>;
}

impl EpochProcessable for BeaconState {
    // Cyclomatic complexity is ignored. It would be ideal to split this function apart, however it
    // remains monolithic to allow for easier spec updates. Once the spec is more stable we can
    // optimise.
    #[allow(clippy::cyclomatic_complexity)]
    fn per_epoch_processing(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        let current_epoch = self.current_epoch(spec);
        let previous_epoch = self.previous_epoch(spec);
        let next_epoch = self.next_epoch(spec);

        debug!(
            "Starting per-epoch processing on epoch {}...",
            self.current_epoch(spec)
        );

        // Ensure all of the caches are built.
        self.build_epoch_cache(RelativeEpoch::Previous, spec)?;
        self.build_epoch_cache(RelativeEpoch::Current, spec)?;
        self.build_epoch_cache(RelativeEpoch::Next, spec)?;

        /*
         * Validators attesting during the current epoch.
         */
        let active_validator_indices = get_active_validator_indices(
            &self.validator_registry,
            self.slot.epoch(spec.epoch_length),
        );
        let current_total_balance = self.get_total_balance(&active_validator_indices[..], spec);

        trace!(
            "{} validators with a total balance of {} wei.",
            active_validator_indices.len(),
            current_total_balance
        );

        let current_epoch_attestations: Vec<&PendingAttestation> = self
            .latest_attestations
            .par_iter()
            .filter(|a| {
                (a.data.slot / spec.epoch_length).epoch(spec.epoch_length)
                    == self.current_epoch(spec)
            })
            .collect();

        trace!(
            "Current epoch attestations: {}",
            current_epoch_attestations.len()
        );

        let current_epoch_boundary_attestations: Vec<&PendingAttestation> =
            current_epoch_attestations
                .par_iter()
                .filter(
                    |a| match self.get_block_root(self.current_epoch_start_slot(spec), spec) {
                        Some(block_root) => {
                            (a.data.epoch_boundary_root == *block_root)
                                && (a.data.justified_epoch == self.justified_epoch)
                        }
                        None => unreachable!(),
                    },
                )
                .cloned()
                .collect();

        let current_epoch_boundary_attester_indices = self
            .get_attestation_participants_union(&current_epoch_boundary_attestations[..], spec)?;
        let current_epoch_boundary_attesting_balance =
            self.get_total_balance(&current_epoch_boundary_attester_indices[..], spec);

        trace!(
            "Current epoch boundary attesters: {}",
            current_epoch_boundary_attester_indices.len()
        );

        /*
         * Validators attesting during the previous epoch
         */

        /*
         * Validators that made an attestation during the previous epoch
         */
        let previous_epoch_attestations: Vec<&PendingAttestation> = self
            .latest_attestations
            .par_iter()
            .filter(|a| {
                //TODO: ensure these saturating subs are correct.
                (a.data.slot / spec.epoch_length).epoch(spec.epoch_length)
                    == self.previous_epoch(spec)
            })
            .collect();

        debug!(
            "previous epoch attestations: {}",
            previous_epoch_attestations.len()
        );

        let previous_epoch_attester_indices =
            self.get_attestation_participants_union(&previous_epoch_attestations[..], spec)?;
        let previous_total_balance = self.get_total_balance(
            &get_active_validator_indices(&self.validator_registry, previous_epoch),
            spec,
        );

        /*
         * Validators targetting the previous justified slot
         */
        let previous_epoch_justified_attestations: Vec<&PendingAttestation> = {
            let mut a: Vec<&PendingAttestation> = current_epoch_attestations
                .iter()
                .filter(|a| a.data.justified_epoch == self.previous_justified_epoch)
                .cloned()
                .collect();
            let mut b: Vec<&PendingAttestation> = previous_epoch_attestations
                .iter()
                .filter(|a| a.data.justified_epoch == self.previous_justified_epoch)
                .cloned()
                .collect();
            a.append(&mut b);
            a
        };

        let previous_epoch_justified_attester_indices = self
            .get_attestation_participants_union(&previous_epoch_justified_attestations[..], spec)?;
        let previous_epoch_justified_attesting_balance =
            self.get_total_balance(&previous_epoch_justified_attester_indices[..], spec);

        /*
         * Validators justifying the epoch boundary block at the start of the previous epoch
         */
        let previous_epoch_boundary_attestations: Vec<&PendingAttestation> =
            previous_epoch_justified_attestations
                .iter()
                .filter(
                    |a| match self.get_block_root(self.previous_epoch_start_slot(spec), spec) {
                        Some(block_root) => a.data.epoch_boundary_root == *block_root,
                        None => unreachable!(),
                    },
                )
                .cloned()
                .collect();

        let previous_epoch_boundary_attester_indices = self
            .get_attestation_participants_union(&previous_epoch_boundary_attestations[..], spec)?;
        let previous_epoch_boundary_attesting_balance =
            self.get_total_balance(&previous_epoch_boundary_attester_indices[..], spec);

        /*
         * Validators attesting to the expected beacon chain head during the previous epoch.
         */
        let previous_epoch_head_attestations: Vec<&PendingAttestation> =
            previous_epoch_attestations
                .iter()
                .filter(|a| match self.get_block_root(a.data.slot, spec) {
                    Some(block_root) => a.data.beacon_block_root == *block_root,
                    None => unreachable!(),
                })
                .cloned()
                .collect();

        let previous_epoch_head_attester_indices =
            self.get_attestation_participants_union(&previous_epoch_head_attestations[..], spec)?;
        let previous_epoch_head_attesting_balance =
            self.get_total_balance(&previous_epoch_head_attester_indices[..], spec);

        debug!(
            "previous_epoch_head_attester_balance of {} wei.",
            previous_epoch_head_attesting_balance
        );

        /*
         * Eth1 Data
         */
        if self.next_epoch(spec) % spec.eth1_data_voting_period == 0 {
            for eth1_data_vote in &self.eth1_data_votes {
                if eth1_data_vote.vote_count * 2 > spec.eth1_data_voting_period {
                    self.latest_eth1_data = eth1_data_vote.eth1_data.clone();
                }
            }
            self.eth1_data_votes = vec![];
        }

        /*
         * Justification
         */

        let mut new_justified_epoch = self.justified_epoch;
        self.justification_bitfield <<= 1;

        // If > 2/3 of the total balance attested to the previous epoch boundary
        //
        // - Set the 2nd bit of the bitfield.
        // - Set the previous epoch to be justified.
        if (3 * previous_epoch_boundary_attesting_balance) >= (2 * current_total_balance) {
            self.justification_bitfield |= 2;
            new_justified_epoch = previous_epoch;
            trace!(">= 2/3 voted for previous epoch boundary");
        }
        // If > 2/3 of the total balance attested to the previous epoch boundary
        //
        // - Set the 1st bit of the bitfield.
        // - Set the current epoch to be justified.
        if (3 * current_epoch_boundary_attesting_balance) >= (2 * current_total_balance) {
            self.justification_bitfield |= 1;
            new_justified_epoch = current_epoch;
            trace!(">= 2/3 voted for current epoch boundary");
        }

        // If:
        //
        // - All three epochs prior to this epoch have been justified.
        // - The previous justified justified epoch was three epochs ago.
        //
        // Then, set the finalized epoch to be three epochs ago.
        if ((self.justification_bitfield >> 1) % 8 == 0b111)
            & (self.previous_justified_epoch == previous_epoch - 2)
        {
            self.finalized_epoch = self.previous_justified_epoch;
            trace!("epoch - 3 was finalized (1st condition).");
        }
        // If:
        //
        // - Both two epochs prior to this epoch have been justified.
        // - The previous justified epoch was two epochs ago.
        //
        // Then, set the finalized epoch to two epochs ago.
        if ((self.justification_bitfield >> 1) % 4 == 0b11)
            & (self.previous_justified_epoch == previous_epoch - 1)
        {
            self.finalized_epoch = self.previous_justified_epoch;
            trace!("epoch - 2 was finalized (2nd condition).");
        }
        // If:
        //
        // - This epoch and the two prior have been justified.
        // - The presently justified epoch was two epochs ago.
        //
        // Then, set the finalized epoch to two epochs ago.
        if (self.justification_bitfield % 8 == 0b111) & (self.justified_epoch == previous_epoch - 1)
        {
            self.finalized_epoch = self.justified_epoch;
            trace!("epoch - 2 was finalized (3rd condition).");
        }
        // If:
        //
        // - This epoch and the epoch prior to it have been justified.
        // - Set the previous epoch to be justified.
        //
        // Then, set the finalized epoch to be the previous epoch.
        if (self.justification_bitfield % 4 == 0b11) & (self.justified_epoch == previous_epoch) {
            self.finalized_epoch = self.justified_epoch;
            trace!("epoch - 1 was finalized (4th condition).");
        }

        self.previous_justified_epoch = self.justified_epoch;
        self.justified_epoch = new_justified_epoch;

        debug!(
            "Finalized epoch {}, justified epoch {}.",
            self.finalized_epoch, self.justified_epoch
        );

        /*
         * Crosslinks
         */

        // Cached for later lookups.
        let mut winning_root_for_shards: HashMap<u64, Result<WinningRoot, WinningRootError>> =
            HashMap::new();

        // for slot in self.slot.saturating_sub(2 * spec.epoch_length)..self.slot {
        for slot in self.previous_epoch(spec).slot_iter(spec.epoch_length) {
            trace!(
                "Finding winning root for slot: {} (epoch: {})",
                slot,
                slot.epoch(spec.epoch_length)
            );

            // Clone is used to remove the borrow. It becomes an issue later when trying to mutate
            // `self.balances`.
            let crosslink_committees_at_slot =
                self.get_crosslink_committees_at_slot(slot, spec)?.clone();

            for (crosslink_committee, shard) in crosslink_committees_at_slot {
                let shard = shard as u64;

                let winning_root = winning_root(
                    self,
                    shard,
                    &current_epoch_attestations,
                    &previous_epoch_attestations,
                    spec,
                );

                if let Ok(winning_root) = &winning_root {
                    let total_committee_balance =
                        self.get_total_balance(&crosslink_committee[..], spec);

                    if (3 * winning_root.total_attesting_balance) >= (2 * total_committee_balance) {
                        self.latest_crosslinks[shard as usize] = Crosslink {
                            epoch: current_epoch,
                            shard_block_root: winning_root.shard_block_root,
                        }
                    }
                }
                winning_root_for_shards.insert(shard, winning_root);
            }
        }

        trace!(
            "Found {} winning shard roots.",
            winning_root_for_shards.len()
        );

        /*
         * Rewards and Penalities
         */
        let base_reward_quotient =
            previous_total_balance.integer_sqrt() / spec.base_reward_quotient;
        if base_reward_quotient == 0 {
            return Err(Error::BaseRewardQuotientIsZero);
        }

        /*
         * Justification and finalization
         */
        let epochs_since_finality = next_epoch - self.finalized_epoch;

        let previous_epoch_justified_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_justified_attester_indices.iter().cloned());
        let previous_epoch_boundary_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_boundary_attester_indices.iter().cloned());
        let previous_epoch_head_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_head_attester_indices.iter().cloned());
        let previous_epoch_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_attester_indices.iter().cloned());
        let active_validator_indices_hashset: HashSet<usize> =
            HashSet::from_iter(active_validator_indices.iter().cloned());

        debug!("previous epoch justified attesters: {}, previous epoch boundary attesters: {}, previous epoch head attesters: {}, previous epoch attesters: {}", previous_epoch_justified_attester_indices.len(), previous_epoch_boundary_attester_indices.len(), previous_epoch_head_attester_indices.len(), previous_epoch_attester_indices.len());

        debug!("{} epochs since finality.", epochs_since_finality);

        if epochs_since_finality <= 4 {
            for index in 0..self.validator_balances.len() {
                let base_reward = self.base_reward(index, base_reward_quotient, spec);

                if previous_epoch_justified_attester_indices_hashset.contains(&index) {
                    safe_add_assign!(
                        self.validator_balances[index],
                        base_reward * previous_epoch_justified_attesting_balance
                            / previous_total_balance
                    );
                } else if active_validator_indices_hashset.contains(&index) {
                    safe_sub_assign!(self.validator_balances[index], base_reward);
                }

                if previous_epoch_boundary_attester_indices_hashset.contains(&index) {
                    safe_add_assign!(
                        self.validator_balances[index],
                        base_reward * previous_epoch_boundary_attesting_balance
                            / previous_total_balance
                    );
                } else if active_validator_indices_hashset.contains(&index) {
                    safe_sub_assign!(self.validator_balances[index], base_reward);
                }

                if previous_epoch_head_attester_indices_hashset.contains(&index) {
                    safe_add_assign!(
                        self.validator_balances[index],
                        base_reward * previous_epoch_head_attesting_balance
                            / previous_total_balance
                    );
                } else if active_validator_indices_hashset.contains(&index) {
                    safe_sub_assign!(self.validator_balances[index], base_reward);
                }
            }

            for index in previous_epoch_attester_indices {
                let base_reward = self.base_reward(index, base_reward_quotient, spec);
                let inclusion_distance =
                    self.inclusion_distance(&previous_epoch_attestations, index, spec)?;

                safe_add_assign!(
                    self.validator_balances[index],
                    base_reward * spec.min_attestation_inclusion_delay / inclusion_distance
                )
            }
        } else {
            for index in 0..self.validator_balances.len() {
                let inactivity_penalty = self.inactivity_penalty(
                    index,
                    epochs_since_finality,
                    base_reward_quotient,
                    spec,
                );
                if active_validator_indices_hashset.contains(&index) {
                    if !previous_epoch_justified_attester_indices_hashset.contains(&index) {
                        safe_sub_assign!(self.validator_balances[index], inactivity_penalty);
                    }
                    if !previous_epoch_boundary_attester_indices_hashset.contains(&index) {
                        safe_sub_assign!(self.validator_balances[index], inactivity_penalty);
                    }
                    if !previous_epoch_head_attester_indices_hashset.contains(&index) {
                        safe_sub_assign!(self.validator_balances[index], inactivity_penalty);
                    }

                    if self.validator_registry[index].penalized_epoch <= current_epoch {
                        let base_reward = self.base_reward(index, base_reward_quotient, spec);
                        safe_sub_assign!(
                            self.validator_balances[index],
                            2 * inactivity_penalty + base_reward
                        );
                    }
                }
            }

            for index in previous_epoch_attester_indices {
                let base_reward = self.base_reward(index, base_reward_quotient, spec);
                let inclusion_distance =
                    self.inclusion_distance(&previous_epoch_attestations, index, spec)?;

                safe_sub_assign!(
                    self.validator_balances[index],
                    base_reward
                        - base_reward * spec.min_attestation_inclusion_delay / inclusion_distance
                );
            }
        }

        trace!("Processed validator justification and finalization rewards/penalities.");

        /*
         * Attestation inclusion
         */
        for &index in &previous_epoch_attester_indices_hashset {
            let inclusion_slot =
                self.inclusion_slot(&previous_epoch_attestations[..], index, spec)?;
            let proposer_index = self
                .get_beacon_proposer_index(inclusion_slot, spec)
                .map_err(|_| Error::UnableToDetermineProducer)?;
            let base_reward = self.base_reward(proposer_index, base_reward_quotient, spec);
            safe_add_assign!(
                self.validator_balances[proposer_index],
                base_reward / spec.includer_reward_quotient
            );
        }

        trace!(
            "Previous epoch attesters: {}.",
            previous_epoch_attester_indices_hashset.len()
        );

        /*
         * Crosslinks
         */
        for slot in self.previous_epoch(spec).slot_iter(spec.epoch_length) {
            // Clone is used to remove the borrow. It becomes an issue later when trying to mutate
            // `self.balances`.
            let crosslink_committees_at_slot =
                self.get_crosslink_committees_at_slot(slot, spec)?.clone();

            for (_crosslink_committee, shard) in crosslink_committees_at_slot {
                let shard = shard as u64;

                if let Some(Ok(winning_root)) = winning_root_for_shards.get(&shard) {
                    // TODO: remove the map.
                    let attesting_validator_indices: HashSet<usize> = HashSet::from_iter(
                        winning_root.attesting_validator_indices.iter().cloned(),
                    );

                    for index in 0..self.validator_balances.len() {
                        let base_reward = self.base_reward(index, base_reward_quotient, spec);

                        if attesting_validator_indices.contains(&index) {
                            safe_add_assign!(
                                self.validator_balances[index],
                                base_reward * winning_root.total_attesting_balance
                                    / winning_root.total_balance
                            );
                        } else {
                            safe_sub_assign!(self.validator_balances[index], base_reward);
                        }
                    }

                    for index in &winning_root.attesting_validator_indices {
                        let base_reward = self.base_reward(*index, base_reward_quotient, spec);
                        safe_add_assign!(
                            self.validator_balances[*index],
                            base_reward * winning_root.total_attesting_balance
                                / winning_root.total_balance
                        );
                    }
                }
            }
        }

        /*
         * Ejections
         */
        self.process_ejections(spec);

        /*
         * Validator Registry
         */
        self.previous_calculation_epoch = self.current_calculation_epoch;
        self.previous_epoch_start_shard = self.current_epoch_start_shard;

        debug!(
            "setting previous_epoch_seed to : {}",
            self.current_epoch_seed
        );

        self.previous_epoch_seed = self.current_epoch_seed;

        let should_update_validator_registy = if self.finalized_epoch
            > self.validator_registry_update_epoch
        {
            (0..self.get_current_epoch_committee_count(spec)).all(|i| {
                let shard = (self.current_epoch_start_shard + i as u64) % spec.shard_count;
                self.latest_crosslinks[shard as usize].epoch > self.validator_registry_update_epoch
            })
        } else {
            false
        };

        if should_update_validator_registy {
            trace!("updating validator registry.");
            self.update_validator_registry(spec);

            self.current_calculation_epoch = next_epoch;
            self.current_epoch_start_shard = (self.current_epoch_start_shard
                + self.get_current_epoch_committee_count(spec) as u64)
                % spec.shard_count;
            self.current_epoch_seed = self.generate_seed(self.current_calculation_epoch, spec)?
        } else {
            trace!("not updating validator registry.");
            let epochs_since_last_registry_update =
                current_epoch - self.validator_registry_update_epoch;
            if (epochs_since_last_registry_update > 1)
                & epochs_since_last_registry_update.is_power_of_two()
            {
                self.current_calculation_epoch = next_epoch;
                self.current_epoch_seed =
                    self.generate_seed(self.current_calculation_epoch, spec)?
            }
        }

        self.process_penalties_and_exits(spec);

        self.latest_index_roots[(next_epoch.as_usize() + spec.entry_exit_delay as usize)
            % spec.latest_index_roots_length] = hash_tree_root(get_active_validator_indices(
            &self.validator_registry,
            next_epoch + Epoch::from(spec.entry_exit_delay),
        ));
        self.latest_penalized_balances[next_epoch.as_usize() % spec.latest_penalized_exit_length] =
            self.latest_penalized_balances
                [current_epoch.as_usize() % spec.latest_penalized_exit_length];
        self.latest_randao_mixes[next_epoch.as_usize() % spec.latest_randao_mixes_length] = self
            .get_randao_mix(current_epoch, spec)
            .and_then(|x| Some(*x))
            .ok_or_else(|| Error::NoRandaoSeed)?;
        self.latest_attestations = self
            .latest_attestations
            .iter()
            .filter(|a| a.data.slot.epoch(spec.epoch_length) >= current_epoch)
            .cloned()
            .collect();

        debug!("Epoch transition complete.");

        Ok(())
    }
}

fn hash_tree_root<T: TreeHash>(input: Vec<T>) -> Hash256 {
    Hash256::from(&input.hash_tree_root()[..])
}

fn winning_root(
    state: &BeaconState,
    shard: u64,
    current_epoch_attestations: &[&PendingAttestation],
    previous_epoch_attestations: &[&PendingAttestation],
    spec: &ChainSpec,
) -> Result<WinningRoot, WinningRootError> {
    let mut attestations = current_epoch_attestations.to_vec();
    attestations.append(&mut previous_epoch_attestations.to_vec());

    let mut candidates: HashMap<Hash256, WinningRoot> = HashMap::new();

    let mut highest_seen_balance = 0;

    for a in &attestations {
        if a.data.shard != shard {
            continue;
        }

        let shard_block_root = &a.data.shard_block_root;

        if candidates.contains_key(shard_block_root) {
            continue;
        }

        let attesting_validator_indices = attestations
            .iter()
            .try_fold::<_, _, Result<_, BeaconStateError>>(vec![], |mut acc, a| {
                if (a.data.shard == shard) && (a.data.shard_block_root == *shard_block_root) {
                    acc.append(&mut state.get_attestation_participants(
                        &a.data,
                        &a.aggregation_bitfield,
                        spec,
                    )?);
                }
                Ok(acc)
            })?;

        let total_balance: u64 = attesting_validator_indices
            .iter()
            .fold(0, |acc, i| acc + state.get_effective_balance(*i, spec));

        let total_attesting_balance: u64 = attesting_validator_indices
            .iter()
            .fold(0, |acc, i| acc + state.get_effective_balance(*i, spec));

        if total_attesting_balance > highest_seen_balance {
            highest_seen_balance = total_attesting_balance;
        }

        let candidate_root = WinningRoot {
            shard_block_root: *shard_block_root,
            attesting_validator_indices,
            total_attesting_balance,
            total_balance,
        };

        candidates.insert(*shard_block_root, candidate_root);
    }

    Ok(candidates
        .iter()
        .filter_map(|(_hash, candidate)| {
            if candidate.total_attesting_balance == highest_seen_balance {
                Some(candidate)
            } else {
                None
            }
        })
        .min_by_key(|candidate| candidate.shard_block_root)
        .ok_or_else(|| WinningRootError::NoWinningRoot)?
        // TODO: avoid clone.
        .clone())
}

impl From<InclusionError> for Error {
    fn from(e: InclusionError) -> Error {
        Error::InclusionError(e)
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<BeaconStateError> for WinningRootError {
    fn from(e: BeaconStateError) -> WinningRootError {
        WinningRootError::BeaconStateError(e)
    }
}
