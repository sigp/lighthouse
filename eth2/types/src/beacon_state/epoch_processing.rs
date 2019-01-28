use super::winning_root::WinningRoot;
use crate::{
    validator::StatusFlags, validator_registry::get_active_validator_indices, AttestationData,
    BeaconState, Bitfield, ChainSpec, Crosslink, Hash256, PendingAttestation,
};
use integer_sqrt::IntegerSquareRoot;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;

pub enum Error {
    UnableToDetermineProducer,
    NoBlockRoots,
    UnableToGetCrosslinkCommittees,
    BaseRewardQuotientIsZero,
}

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

impl BeaconState {
    pub fn per_epoch_processing(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        /*
         * All Validators
         */
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, self.slot);
        let total_balance: u64 = active_validator_indices
            .iter()
            .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

        let current_epoch_attestations: Vec<&PendingAttestation> = self
            .latest_attestations
            .iter()
            .filter(|a| (self.slot - spec.epoch_length <= a.data.slot) && (a.data.slot < self.slot))
            .collect();

        /*
         * Validators attesting during the current epoch.
         */
        if self.latest_block_roots.is_empty() {
            return Err(Error::NoBlockRoots);
        }

        let current_epoch_boundary_attestations: Vec<&PendingAttestation> =
            current_epoch_attestations
                .iter()
                // `filter_map` is used to avoid a double borrow (`&&..`).
                .filter_map(|a| {
                    // TODO: ensure this saturating sub is correct.
                    let block_root = match self
                        .get_block_root(self.slot.saturating_sub(spec.epoch_length), spec)
                    {
                        Some(root) => root,
                        // Protected by a check that latest_block_roots isn't empty.
                        //
                        // TODO: provide detailed reasoning.
                        None => unreachable!(),
                    };

                    if (a.data.epoch_boundary_root == *block_root)
                        && (a.data.justified_slot == self.justified_slot)
                    {
                        Some(*a)
                    } else {
                        None
                    }
                })
                .collect();

        let current_epoch_boundary_attester_indices: Vec<usize> =
            current_epoch_boundary_attestations
                .iter()
                .fold(vec![], |mut acc, a| {
                    acc.append(
                        &mut self.get_attestation_participants(&a.data, &a.aggregation_bitfield),
                    );
                    acc
                });

        let current_epoch_boundary_attesting_balance = current_epoch_boundary_attester_indices
            .iter()
            .fold(0_u64, |acc, i| acc + self.get_effective_balance(*i, spec));

        /*
         * Validators attesting during the previous epoch
         */

        /*
         * Validators that made an attestation during the previous epoch
         */
        let previous_epoch_attestations: Vec<&PendingAttestation> = self
            .latest_attestations
            .iter()
            .filter(|a| {
                //TODO: ensure these saturating subs are correct.
                (self.slot.saturating_sub(2 * spec.epoch_length) <= a.data.slot)
                    && (a.data.slot < self.slot.saturating_sub(spec.epoch_length))
            })
            .collect();

        let previous_epoch_attester_indices: Vec<usize> =
            previous_epoch_attestations
                .iter()
                .fold(vec![], |mut acc, a| {
                    acc.append(
                        &mut self.get_attestation_participants(&a.data, &a.aggregation_bitfield),
                    );
                    acc
                });

        /*
         * Validators targetting the previous justified slot
         */
        let previous_epoch_justified_attestations: Vec<&PendingAttestation> = {
            let mut a: Vec<&PendingAttestation> = current_epoch_attestations
                .iter()
                // `filter_map` is used to avoid a double borrow (`&&..`).
                .filter_map(|a| {
                    if a.data.justified_slot == self.previous_justified_slot {
                        Some(*a)
                    } else {
                        None
                    }
                })
                .collect();
            let mut b: Vec<&PendingAttestation> = previous_epoch_attestations
                .iter()
                // `filter_map` is used to avoid a double borrow (`&&..`).
                .filter_map(|a| {
                    if a.data.justified_slot == self.previous_justified_slot {
                        Some(*a)
                    } else {
                        None
                    }
                })
                .collect();
            a.append(&mut b);
            a
        };

        let previous_epoch_justified_attester_indices: Vec<usize> =
            previous_epoch_justified_attestations
                .iter()
                .fold(vec![], |mut acc, a| {
                    acc.append(
                        &mut self.get_attestation_participants(&a.data, &a.aggregation_bitfield),
                    );
                    acc
                });

        let previous_epoch_justified_attesting_balance = previous_epoch_justified_attester_indices
            .iter()
            .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

        /*
         * Validators justifying the epoch boundary block at the start of the previous epoch
         */
        let previous_epoch_boundary_attestations: Vec<&PendingAttestation> =
            previous_epoch_justified_attestations
                .iter()
                // `filter_map` is used to avoid a double borrow (`&&..`).
                .filter_map(|a| {
                    // TODO: ensure this saturating sub is correct.
                    let block_root = match self
                        .get_block_root(self.slot.saturating_sub(2 * spec.epoch_length), spec)
                    {
                        Some(root) => root,
                        // Protected by a check that latest_block_roots isn't empty.
                        //
                        // TODO: provide detailed reasoning.
                        None => unreachable!(),
                    };

                    if a.data.epoch_boundary_root == *block_root {
                        Some(*a)
                    } else {
                        None
                    }
                })
                .collect();

        let previous_epoch_boundary_attester_indices: Vec<usize> =
            previous_epoch_boundary_attestations
                .iter()
                .fold(vec![], |mut acc, a| {
                    acc.append(
                        &mut self.get_attestation_participants(&a.data, &a.aggregation_bitfield),
                    );
                    acc
                });

        let previous_epoch_boundary_attesting_balance: u64 =
            previous_epoch_boundary_attester_indices
                .iter()
                .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

        /*
         * Validators attesting to the expected beacon chain head during the previous epoch.
         */
        let previous_epoch_head_attestations: Vec<&PendingAttestation> =
            previous_epoch_attestations
                .iter()
                .filter_map(|a| {
                    let block_root = match self
                        .get_block_root(self.slot.saturating_sub(2 * spec.epoch_length), spec)
                    {
                        Some(root) => root,
                        // Protected by a check that latest_block_roots isn't empty.
                        //
                        // TODO: provide detailed reasoning.
                        None => unreachable!(),
                    };

                    if a.data.beacon_block_root == *block_root {
                        Some(*a)
                    } else {
                        None
                    }
                })
                .collect();

        let previous_epoch_head_attester_indices: Vec<usize> = previous_epoch_head_attestations
            .iter()
            .fold(vec![], |mut acc, a| {
                acc.append(
                    &mut self.get_attestation_participants(&a.data, &a.aggregation_bitfield),
                );
                acc
            });

        let previous_epoch_head_attesting_balance: u64 = previous_epoch_head_attester_indices
            .iter()
            .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

        /*
         * Eth1 Data
         */
        if self.slot % spec.eth1_data_voting_period == 0 {
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
        self.previous_justified_slot = self.justified_slot;
        let (new_bitfield, _) = self.justification_bitfield.overflowing_mul(2);
        self.justification_bitfield = new_bitfield;

        // If >= 2/3 of validators voted for the previous epoch boundary
        if (3 * previous_epoch_boundary_attesting_balance) >= (2 * total_balance) {
            // TODO: check saturating_sub is correct.
            self.justification_bitfield |= 2;
            self.justified_slot = self.slot.saturating_sub(2 * spec.epoch_length);
        }

        // If >= 2/3 of validators voted for the current epoch boundary
        if (3 * current_epoch_boundary_attesting_balance) >= (2 * total_balance) {
            // TODO: check saturating_sub is correct.
            self.justification_bitfield |= 1;
            self.justified_slot = self.slot.saturating_sub(1 * spec.epoch_length);
        }

        if (self.previous_justified_slot == self.slot.saturating_sub(2 * spec.epoch_length))
            && (self.justification_bitfield % 4 == 3)
        {
            self.finalized_slot = self.previous_justified_slot;
        }
        if (self.previous_justified_slot == self.slot.saturating_sub(3 * spec.epoch_length))
            && (self.justification_bitfield % 8 == 7)
        {
            self.finalized_slot = self.previous_justified_slot;
        }
        if (self.previous_justified_slot == self.slot.saturating_sub(4 * spec.epoch_length))
            && (self.justification_bitfield % 16 == 14)
        {
            self.finalized_slot = self.previous_justified_slot;
        }
        if (self.previous_justified_slot == self.slot.saturating_sub(4 * spec.epoch_length))
            && (self.justification_bitfield % 16 == 15)
        {
            self.finalized_slot = self.previous_justified_slot;
        }

        /*
         * Crosslinks
         */

        // Cached for later lookups.
        let mut winning_root_for_shards: HashMap<u64, WinningRoot> = HashMap::new();

        for slot in self.slot.saturating_sub(2 * spec.epoch_length)..self.slot {
            let crosslink_committees_at_slot = self
                .get_crosslink_committees_at_slot(slot)
                .ok_or_else(|| Error::UnableToGetCrosslinkCommittees)?;

            for (crosslink_committee, shard) in crosslink_committees_at_slot {
                let shard = shard as u64;

                let winning_root = self.winning_root(
                    shard,
                    &current_epoch_attestations,
                    &previous_epoch_attestations,
                    spec,
                );

                if let Some(winning_root) = winning_root {
                    let total_committee_balance: u64 = crosslink_committee
                        .iter()
                        .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

                    winning_root_for_shards.insert(shard, winning_root.clone());

                    if (3 * winning_root.total_attesting_balance) >= (2 * total_committee_balance) {
                        self.latest_crosslinks[shard as usize] = Crosslink {
                            slot: self.slot,
                            shard_block_root: winning_root.shard_block_root,
                        }
                    }
                }
            }
        }

        /*
         * Rewards and Penalities
         */
        let base_reward_quotient = total_balance.integer_sqrt();
        if base_reward_quotient == 0 {
            return Err(Error::BaseRewardQuotientIsZero);
        }

        /*
        let base_reward = |i| match self.get_effective_balance(i, spec) {
            Some(effective_balance) => effective_balance / base_reward_quotient / 5,
            None => unreachable!(),
        };
        */

        /*
         * Justification and finalization
         */
        let epochs_since_finality = (self.slot - self.finalized_slot) / spec.epoch_length;

        // TODO: fix this extra map
        let previous_epoch_justified_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_justified_attester_indices.iter().map(|i| *i));
        let previous_epoch_boundary_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_boundary_attester_indices.iter().map(|i| *i));
        let previous_epoch_head_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_head_attester_indices.iter().map(|i| *i));
        let previous_epoch_attester_indices_hashset: HashSet<usize> =
            HashSet::from_iter(previous_epoch_attester_indices.iter().map(|i| *i));

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
                let inclusion_distance = match self.inclusion_distance(index) {
                    Some(distance) => distance,
                    None => unreachable!(),
                };

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
                let inclusion_distance = match self.inclusion_distance(index) {
                    Some(distance) => distance,
                    None => unreachable!(),
                };

                safe_sub_assign!(
                    self.validator_balances[index],
                    base_reward
                        - base_reward * spec.min_attestation_inclusion_delay / inclusion_distance
                );
            }
        }

        /*
         * Attestation inclusion
         */
        for index in previous_epoch_attester_indices_hashset {
            let inclusion_slot = match self.inclusion_slot(index) {
                Some(slot) => slot,
                None => unreachable!(),
            };
            let proposer_index = self
                .get_beacon_proposer_index(inclusion_slot, spec)
                .ok_or_else(|| Error::UnableToDetermineProducer)?;
            let base_reward = self.base_reward(proposer_index, base_reward_quotient, spec);
            safe_add_assign!(
                self.validator_balances[proposer_index],
                base_reward / spec.includer_reward_quotient
            );
        }

        /*
         * Crosslinks
         */
        for slot in self.slot.saturating_sub(2 * spec.epoch_length)..self.slot {
            let crosslink_committees_at_slot = self
                .get_crosslink_committees_at_slot(slot)
                .ok_or_else(|| Error::UnableToGetCrosslinkCommittees)?;

            for (_crosslink_committee, shard) in crosslink_committees_at_slot {
                let shard = shard as u64;

                let winning_root = winning_root_for_shards.get(&shard).expect("unreachable");

                // TODO: remove the map.
                let attesting_validator_indices: HashSet<usize> =
                    HashSet::from_iter(winning_root.attesting_validator_indices.iter().map(|i| *i));

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

        /*
         * Ejections
         */
        self.process_ejections();

        /*
         * Validator Registry
         */
        self.previous_epoch_calculation_slot = self.current_epoch_calculation_slot;
        self.previous_epoch_start_shard = self.current_epoch_start_shard;
        self.previous_epoch_randao_mix = self.current_epoch_randao_mix;

        let should_update_validator_registy = if self.finalized_slot
            > self.validator_registry_update_slot
        {
            (0..self.get_current_epoch_committee_count_per_slot(spec)).all(|i| {
                let shard = (self.current_epoch_start_shard + i as u64) % spec.shard_count;
                self.latest_crosslinks[shard as usize].slot > self.validator_registry_update_slot
            })
        } else {
            false
        };

        if should_update_validator_registy {
            self.update_validator_registry(spec);

            self.current_epoch_calculation_slot = self.slot;
            self.current_epoch_start_shard = (self.current_epoch_start_shard
                + self.get_current_epoch_committee_count_per_slot(spec) as u64 * spec.epoch_length)
                % spec.shard_count;
            self.current_epoch_randao_mix = self.get_randao_mix(
                self.current_epoch_calculation_slot
                    .saturating_sub(spec.seed_lookahead),
                spec,
            );
        } else {
            let epochs_since_last_registry_change =
                (self.slot - self.validator_registry_update_slot) / spec.epoch_length;
            if epochs_since_last_registry_change.is_power_of_two() {
                self.current_epoch_calculation_slot = self.slot;
                self.current_epoch_randao_mix = self.get_randao_mix(
                    self.current_epoch_calculation_slot
                        .saturating_sub(spec.seed_lookahead),
                    spec,
                );
            }
        }

        self.process_penalties_and_exits(spec);

        let e = self.slot / spec.epoch_length;
        self.latest_penalized_balances[((e + 1) % spec.latest_penalized_exit_length) as usize] =
            self.latest_penalized_balances[(e % spec.latest_penalized_exit_length) as usize];

        self.latest_attestations = self
            .latest_attestations
            .iter()
            .filter_map(|a| {
                if a.data.slot < self.slot - spec.epoch_length {
                    Some(a.clone())
                } else {
                    None
                }
            })
            .collect();

        Ok(())
    }

    fn process_penalties_and_exits(&mut self, spec: &ChainSpec) {
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, self.slot);
        let total_balance = active_validator_indices
            .iter()
            .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

        for index in 0..self.validator_balances.len() {
            let validator = &self.validator_registry[index];

            if (self.slot / spec.epoch_length)
                == (validator.penalized_slot / spec.epoch_length)
                    + spec.latest_penalized_exit_length / 2
            {
                let e = (self.slot / spec.epoch_length) % spec.latest_penalized_exit_length;
                let total_at_start = self.latest_penalized_balances
                    [((e + 1) % spec.latest_penalized_exit_length) as usize];
                let total_at_end = self.latest_penalized_balances[e as usize];
                let total_penalities = total_at_end.saturating_sub(total_at_start);
                let penalty = self.get_effective_balance(index, spec)
                    * std::cmp::min(total_penalities * 3, total_balance)
                    / total_balance;
                safe_sub_assign!(self.validator_balances[index], penalty);
            }
        }

        let eligible = |index: usize| {
            let validator = &self.validator_registry[index];

            if validator.penalized_slot <= self.slot {
                let penalized_withdrawal_time =
                    spec.latest_penalized_exit_length * spec.epoch_length / 2;
                self.slot >= validator.penalized_slot + penalized_withdrawal_time
            } else {
                self.slot >= validator.exit_slot + spec.min_validator_withdrawal_time
            }
        };

        let mut eligable_indices: Vec<usize> = (0..self.validator_registry.len())
            .filter(|i| eligible(*i))
            .collect();
        eligable_indices.sort_by_key(|i| self.validator_registry[*i].exit_count);
        let mut withdrawn_so_far = 0;
        for index in eligable_indices {
            self.prepare_validator_for_withdrawal(index);
            withdrawn_so_far += 1;
            if withdrawn_so_far >= spec.max_withdrawals_per_epoch {
                break;
            }
        }
    }

    fn prepare_validator_for_withdrawal(&mut self, index: usize) {
        //TODO: we're not ANDing here, we're setting. Potentially wrong.
        self.validator_registry[index].status_flags = Some(StatusFlags::Withdrawable);
    }

    fn get_randao_mix(&mut self, slot: u64, spec: &ChainSpec) -> Hash256 {
        assert!(self.slot < slot + spec.latest_randao_mixes_length);
        assert!(slot <= self.slot);
        self.latest_randao_mixes[(slot & spec.latest_randao_mixes_length) as usize]
    }

    fn update_validator_registry(&mut self, spec: &ChainSpec) {
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, self.slot);
        let total_balance = active_validator_indices
            .iter()
            .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

        let max_balance_churn = std::cmp::max(
            spec.max_deposit,
            total_balance / (2 * spec.max_balance_churn_quotient),
        );

        let mut balance_churn = 0;
        for index in 0..self.validator_registry.len() {
            let validator = &self.validator_registry[index];

            if (validator.activation_slot > self.slot + spec.entry_exit_delay)
                && self.validator_balances[index] >= spec.max_deposit
            {
                balance_churn += self.get_effective_balance(index, spec);
                if balance_churn > max_balance_churn {
                    break;
                }

                self.activate_validator(index, false, spec);
            }
        }

        let mut balance_churn = 0;
        for index in 0..self.validator_registry.len() {
            let validator = &self.validator_registry[index];

            if (validator.exit_slot > self.slot + spec.entry_exit_delay)
                && validator.status_flags == Some(StatusFlags::InitiatedExit)
            {
                balance_churn += self.get_effective_balance(index, spec);
                if balance_churn > max_balance_churn {
                    break;
                }

                self.exit_validator(index, spec);
            }
        }

        self.validator_registry_update_slot = self.slot;
    }

    fn exit_validator(&mut self, validator_index: usize, spec: &ChainSpec) {
        if self.validator_registry[validator_index].exit_slot
            <= self.entry_exit_effect_slot(self.slot, spec)
        {
            return;
        }

        self.validator_registry[validator_index].exit_slot =
            self.entry_exit_effect_slot(self.slot, spec);

        self.validator_registry_exit_count += 1;
        self.validator_registry[validator_index].exit_count = self.validator_registry_exit_count;
    }

    fn activate_validator(&mut self, validator_index: usize, is_genesis: bool, spec: &ChainSpec) {
        self.validator_registry[validator_index].activation_slot = if is_genesis {
            spec.genesis_slot
        } else {
            self.entry_exit_effect_slot(self.slot, spec)
        }
    }

    fn entry_exit_effect_slot(&self, slot: u64, spec: &ChainSpec) -> u64 {
        (slot - slot % spec.epoch_length) + spec.epoch_length + spec.entry_exit_delay
    }

    fn get_current_epoch_committee_count_per_slot(&self, spec: &ChainSpec) -> usize {
        let current_active_validators = get_active_validator_indices(
            &self.validator_registry,
            self.current_epoch_calculation_slot,
        );
        self.get_committee_count_per_slot(current_active_validators.len(), spec)
    }

    fn process_ejections(&self) {
        //TODO: stubbed out.
    }

    fn inactivity_penalty(
        &self,
        validator_index: usize,
        epochs_since_finality: u64,
        base_reward_quotient: u64,
        spec: &ChainSpec,
    ) -> u64 {
        let effective_balance = self.get_effective_balance(validator_index, spec);
        self.base_reward(validator_index, base_reward_quotient, spec)
            + effective_balance * epochs_since_finality / spec.inactivity_penalty_quotient / 2
    }

    fn inclusion_distance(&self, validator_index: usize) -> Option<u64> {
        let attestation = self.earliest_included_attestation(validator_index)?;
        Some(
            attestation
                .slot_included
                .saturating_sub(attestation.data.slot),
        )
    }

    fn inclusion_slot(&self, validator_index: usize) -> Option<u64> {
        let attestation = self.earliest_included_attestation(validator_index)?;
        Some(attestation.slot_included)
    }

    fn earliest_included_attestation(&self, validator_index: usize) -> Option<&PendingAttestation> {
        self.latest_attestations
            .iter()
            .filter(|a| {
                self.get_attestation_participants(&a.data, &a.aggregation_bitfield)
                    .iter()
                    .find(|i| **i == validator_index)
                    .is_some()
            })
            .min_by_key(|a| a.slot_included)
    }

    fn base_reward(
        &self,
        validator_index: usize,
        base_reward_quotient: u64,
        spec: &ChainSpec,
    ) -> u64 {
        self.get_effective_balance(validator_index, spec) / base_reward_quotient / 5
    }

    pub fn get_effective_balance(&self, validator_index: usize, spec: &ChainSpec) -> u64 {
        std::cmp::min(self.validator_balances[validator_index], spec.max_deposit)
    }

    pub fn get_block_root(&self, slot: u64, spec: &ChainSpec) -> Option<&Hash256> {
        if self.slot <= slot + spec.latest_block_roots_length && slot <= self.slot {
            self.latest_block_roots
                .get((slot % spec.latest_block_roots_length) as usize)
        } else {
            None
        }
    }

    pub fn get_attestation_participants(
        &self,
        _attestation_data: &AttestationData,
        _aggregation_bitfield: &Bitfield,
    ) -> Vec<usize> {
        // TODO: stubbed out.
        vec![0, 1]
    }
}
