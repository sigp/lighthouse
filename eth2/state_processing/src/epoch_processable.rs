use log::debug;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use types::{
    beacon_state::{AttestationParticipantsError, CommitteesError, InclusionError},
    validator_registry::get_active_validator_indices,
    BeaconState, ChainSpec, Crosslink, Hash256, PendingAttestation,
};

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
    CommitteesError(CommitteesError),
    AttestationParticipantsError(AttestationParticipantsError),
    InclusionError(InclusionError),
    WinningRootError(WinningRootError),
}

#[derive(Debug, PartialEq)]
pub enum WinningRootError {
    NoWinningRoot,
    AttestationParticipantsError(AttestationParticipantsError),
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
    fn per_epoch_processing(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        let current_epoch = self.current_epoch(spec);
        let previous_epoch = self.previous_epoch(spec);
        let next_epoch = self.next_epoch(spec);

        debug!(
            "Starting per-epoch processing on epoch {}...",
            self.current_epoch(spec)
        );

        /*
         * All Validators
         */
        let active_validator_indices = get_active_validator_indices(
            &self.validator_registry,
            self.slot.epoch(spec.epoch_length),
        );
        let total_balance = self.get_total_balance(&active_validator_indices[..], spec);

        debug!(
            "{} validators with a total balance of {} wei.",
            active_validator_indices.len(),
            total_balance
        );

        let current_epoch_attestations: Vec<&PendingAttestation> = self
            .latest_attestations
            .par_iter()
            .filter(|a| {
                (a.data.slot / spec.epoch_length).epoch(spec.epoch_length)
                    == self.current_epoch(spec)
            })
            .collect();

        debug!(
            "Current epoch attestations: {}",
            current_epoch_attestations.len()
        );

        /*
         * Validators attesting during the current epoch.
         */
        if self.latest_block_roots.is_empty() {
            return Err(Error::NoBlockRoots);
        }

        let current_epoch_boundary_attestations: Vec<&PendingAttestation> =
            current_epoch_attestations
                .par_iter()
                .filter(|a| {
                    match self.get_block_root(self.current_epoch_start_slot(spec), spec) {
                        Some(block_root) => {
                            (a.data.epoch_boundary_root == *block_root)
                                && (a.data.justified_epoch == self.justified_epoch)
                        }
                        // Protected by a check that latest_block_roots isn't empty.
                        //
                        // TODO: provide detailed reasoning.
                        None => unreachable!(),
                    }
                })
                .cloned()
                .collect();

        let current_epoch_boundary_attester_indices = self
            .get_attestation_participants_union(&current_epoch_boundary_attestations[..], spec)?;
        let current_epoch_boundary_attesting_balance =
            self.get_total_balance(&current_epoch_boundary_attester_indices[..], spec);

        debug!(
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
                .filter(|a| {
                    match self.get_block_root(self.previous_epoch_start_slot(spec), spec) {
                        Some(block_root) => a.data.epoch_boundary_root == *block_root,
                        // Protected by a check that latest_block_roots isn't empty.
                        //
                        // TODO: provide detailed reasoning.
                        None => unreachable!(),
                    }
                })
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
                .filter(|a| {
                    match self.get_block_root(a.data.slot, spec) {
                        Some(block_root) => a.data.beacon_block_root == *block_root,
                        // Protected by a check that latest_block_roots isn't empty.
                        //
                        // TODO: provide detailed reasoning.
                        None => unreachable!(),
                    }
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
        let new_justified_epoch = self.justified_epoch;
        self.previous_justified_epoch = self.justified_epoch;
        let (new_bitfield, _) = self.justification_bitfield.overflowing_mul(2);
        self.justification_bitfield = new_bitfield;

        // If >= 2/3 of validators voted for the previous epoch boundary
        if (3 * previous_epoch_boundary_attesting_balance) >= (2 * total_balance) {
            // TODO: check saturating_sub is correct.
            self.justification_bitfield |= 2;
            self.justified_epoch = self.slot.saturating_sub(2 * spec.epoch_length);
            debug!(">= 2/3 voted for previous epoch boundary");
        }

        // If >= 2/3 of validators voted for the current epoch boundary
        if (3 * current_epoch_boundary_attesting_balance) >= (2 * total_balance) {
            // TODO: check saturating_sub is correct.
            self.justification_bitfield |= 1;
            self.justified_epoch = self.slot.saturating_sub(1 * spec.epoch_length);
            debug!(">= 2/3 voted for current epoch boundary");
        }

        if (self.previous_justified_epoch == self.slot.saturating_sub(2 * spec.epoch_length))
            && (self.justification_bitfield % 4 == 3)
        {
            self.finalized_slot = self.previous_justified_epoch;
        }
        if (self.previous_justified_epoch == self.slot.saturating_sub(3 * spec.epoch_length))
            && (self.justification_bitfield % 8 == 7)
        {
            self.finalized_slot = self.previous_justified_epoch;
        }
        if (self.previous_justified_epoch == self.slot.saturating_sub(4 * spec.epoch_length))
            && (self.justification_bitfield % 16 == 14)
        {
            self.finalized_slot = self.previous_justified_epoch;
        }
        if (self.previous_justified_epoch == self.slot.saturating_sub(4 * spec.epoch_length))
            && (self.justification_bitfield % 16 == 15)
        {
            self.finalized_slot = self.previous_justified_epoch;
        }

        debug!(
            "Finalized slot {}, justified slot {}.",
            self.finalized_slot, self.justified_epoch
        );

        /*
         * Crosslinks
         */

        // Cached for later lookups.
        let mut winning_root_for_shards: HashMap<u64, Result<WinningRoot, WinningRootError>> =
            HashMap::new();

        // for slot in self.slot.saturating_sub(2 * spec.epoch_length)..self.slot {
        for slot in self.previous_epoch(spec).slot_iter(spec.epoch_length) {
            let crosslink_committees_at_slot =
                self.get_crosslink_committees_at_slot(slot, false, spec)?;

            for (crosslink_committee, shard) in crosslink_committees_at_slot {
                let shard = shard as u64;

                let winning_root = self.winning_root(
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
                            slot: self.slot,
                            shard_block_root: winning_root.shard_block_root,
                        }
                    }
                }
                winning_root_for_shards.insert(shard, winning_root);
            }
        }

        debug!(
            "Found {} winning shard roots.",
            winning_root_for_shards.len()
        );

        /*
         * Rewards and Penalities
         */
        let base_reward_quotient = total_balance.integer_sqrt();
        if base_reward_quotient == 0 {
            return Err(Error::BaseRewardQuotientIsZero);
        }

        /*
         * Justification and finalization
         */
        let epochs_since_finality =
            (self.slot.saturating_sub(self.finalized_slot) / spec.epoch_length).as_u64();

        // TODO: fix this extra map
        let previous_epoch_justified_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_justified_attester_indices.iter().map(|i| *i));
        let previous_epoch_boundary_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_boundary_attester_indices.iter().map(|i| *i));
        let previous_epoch_head_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_head_attester_indices.iter().map(|i| *i));
        let previous_epoch_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_attester_indices.iter().map(|i| *i));

        debug!("previous epoch justified attesters: {}, previous epoch boundary attesters: {}, previous epoch head attesters: {}, previous epoch attesters: {}", previous_epoch_justified_attester_indices.len(), previous_epoch_boundary_attester_indices.len(), previous_epoch_head_attester_indices.len(), previous_epoch_attester_indices.len());

        debug!("{} epochs since finality.", epochs_since_finality);

        if epochs_since_finality <= 4 {
            for index in 0..self.validator_balances.len() {
                let base_reward = self.base_reward(index, base_reward_quotient, spec);

                if previous_epoch_justified_attester_indices_hashset.contains(&index) {
                    safe_add_assign!(
                        self.validator_balances[index],
                        base_reward * previous_epoch_justified_attesting_balance / total_balance
                    );
                } else {
                    safe_sub_assign!(self.validator_balances[index], base_reward);
                }

                if previous_epoch_boundary_attester_indices_hashset.contains(&index) {
                    safe_add_assign!(
                        self.validator_balances[index],
                        base_reward * previous_epoch_boundary_attesting_balance / total_balance
                    );
                } else {
                    safe_sub_assign!(self.validator_balances[index], base_reward);
                }

                if previous_epoch_head_attester_indices_hashset.contains(&index) {
                    safe_add_assign!(
                        self.validator_balances[index],
                        base_reward * previous_epoch_head_attesting_balance / total_balance
                    );
                } else {
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

                if !previous_epoch_justified_attester_indices_hashset.contains(&index) {
                    safe_sub_assign!(self.validator_balances[index], inactivity_penalty);
                }

                if !previous_epoch_boundary_attester_indices_hashset.contains(&index) {
                    safe_sub_assign!(self.validator_balances[index], inactivity_penalty);
                }

                if !previous_epoch_head_attester_indices_hashset.contains(&index) {
                    safe_sub_assign!(self.validator_balances[index], inactivity_penalty);
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

        debug!("Processed validator justification and finalization rewards/penalities.");

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

        debug!(
            "Previous epoch attesters: {}.",
            previous_epoch_attester_indices_hashset.len()
        );

        /*
         * Crosslinks
         */
        for slot in self.previous_epoch(spec).slot_iter(spec.epoch_length) {
            let crosslink_committees_at_slot = self.get_crosslink_committees_at_slot(slot, spec)?;

            for (_crosslink_committee, shard) in crosslink_committees_at_slot {
                let shard = shard as u64;

                if let Some(Ok(winning_root)) = winning_root_for_shards.get(&shard) {
                    // TODO: remove the map.
                    let attesting_validator_indices: HashSet<usize> = HashSet::from_iter(
                        winning_root.attesting_validator_indices.iter().map(|i| *i),
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
        self.process_ejections();

        /*
         * Validator Registry
         */
        self.previous_calculation_epoch = self.current_calculation_epoch;
        self.previous_epoch_start_shard = self.current_epoch_start_shard;
        self.previous_epoch_seed = self.current_epoch_seed;

        let should_update_validator_registy = if self.finalized_slot
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
            self.update_validator_registry(spec);

            self.current_calculation_epoch = self.slot;
            self.current_epoch_start_shard = (self.current_epoch_start_shard
                + self.get_current_epoch_committee_count(spec) as u64 * spec.epoch_length)
                % spec.shard_count;
            self.current_epoch_seed =
                self.get_randao_mix(self.current_calculation_epoch - spec.seed_lookahead, spec);
        } else {
            let epochs_since_last_registry_change =
                (self.slot - self.validator_registry_update_epoch) / spec.epoch_length;
            if epochs_since_last_registry_change.is_power_of_two() {
                self.current_calculation_epoch = self.slot;
                self.current_epoch_seed =
                    self.get_randao_mix(self.current_calculation_epoch - spec.seed_lookahead, spec);
            }
        }

        self.process_penalties_and_exits(spec);

        let e = self.slot / spec.epoch_length;
        self.latest_penalized_balances[((e + 1) % spec.latest_penalized_exit_length).as_usize()] =
            self.latest_penalized_balances[(e % spec.latest_penalized_exit_length).as_usize()];

        self.latest_attestations = self
            .latest_attestations
            .iter()
            .filter(|a| {
                (a.data.slot / spec.epoch_length).epoch(spec.epoch_length)
                    >= self.current_epoch(spec)
            })
            .cloned()
            .collect();

        debug!("Epoch transition complete.");

        Ok(())
    }
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

        // TODO: `cargo fmt` makes this rather ugly; tidy up.
        let attesting_validator_indices = attestations.iter().try_fold::<_, _, Result<
            _,
            AttestationParticipantsError,
        >>(vec![], |mut acc, a| {
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
            shard_block_root: shard_block_root.clone(),
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

impl From<CommitteesError> for Error {
    fn from(e: CommitteesError) -> Error {
        Error::CommitteesError(e)
    }
}

impl From<AttestationParticipantsError> for Error {
    fn from(e: AttestationParticipantsError) -> Error {
        Error::AttestationParticipantsError(e)
    }
}

impl From<AttestationParticipantsError> for WinningRootError {
    fn from(e: AttestationParticipantsError) -> WinningRootError {
        WinningRootError::AttestationParticipantsError(e)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
