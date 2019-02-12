use crate::test_utils::TestRandom;
use crate::{
    validator::StatusFlags, validator_registry::get_active_validator_indices, AttestationData,
    Bitfield, ChainSpec, Crosslink, Deposit, Epoch, Eth1Data, Eth1DataVote, Fork, Hash256,
    PendingAttestation, PublicKey, Signature, Slot, Validator,
};
use bls::verify_proof_of_possession;
use honey_badger_split::SplitExt;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use std::ops::Range;
use vec_shuffle::shuffle;

pub enum Error {
    InsufficientValidators,
    BadBlockSignature,
    InvalidEpoch(Slot, Range<Epoch>),
    CommitteesError(CommitteesError),
}

#[derive(Debug, PartialEq)]
pub enum CommitteesError {
    InvalidEpoch,
    InsufficientNumberOfValidators,
    BadRandao,
}

#[derive(Debug, PartialEq)]
pub enum InclusionError {
    NoIncludedAttestations,
    AttestationParticipantsError(AttestationParticipantsError),
}

#[derive(Debug, PartialEq)]
pub enum AttestationParticipantsError {
    NoCommitteeForShard,
    NoCommittees,
    BadBitfieldLength,
    CommitteesError(CommitteesError),
}

#[derive(Debug, PartialEq)]
pub enum AttestationValidationError {
    IncludedTooEarly,
    IncludedTooLate,
    WrongJustifiedSlot,
    WrongJustifiedRoot,
    BadLatestCrosslinkRoot,
    BadSignature,
    ShardBlockRootNotZero,
    NoBlockRoot,
    AttestationParticipantsError(AttestationParticipantsError),
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

#[derive(Debug, PartialEq, Clone, Default, Serialize)]
pub struct BeaconState {
    // Misc
    pub slot: Slot,
    pub genesis_time: u64,
    pub fork: Fork,

    // Validator registry
    pub validator_registry: Vec<Validator>,
    pub validator_balances: Vec<u64>,
    pub validator_registry_update_epoch: Epoch,

    // Randomness and committees
    pub latest_randao_mixes: Vec<Hash256>,
    pub previous_epoch_start_shard: u64,
    pub current_epoch_start_shard: u64,
    pub previous_calculation_epoch: Epoch,
    pub current_calculation_epoch: Epoch,
    pub previous_epoch_seed: Hash256,
    pub current_epoch_seed: Hash256,

    // Finality
    pub previous_justified_epoch: Epoch,
    pub justified_epoch: Epoch,
    pub justification_bitfield: u64,
    pub finalized_epoch: Epoch,

    // Recent state
    pub latest_crosslinks: Vec<Crosslink>,
    pub latest_block_roots: Vec<Hash256>,
    pub latest_index_roots: Vec<Hash256>,
    pub latest_penalized_balances: Vec<u64>,
    pub latest_attestations: Vec<PendingAttestation>,
    pub batched_block_roots: Vec<Hash256>,

    // Ethereum 1.0 chain data
    pub latest_eth1_data: Eth1Data,
    pub eth1_data_votes: Vec<Eth1DataVote>,
}

impl BeaconState {
    /// Produce the first state of the Beacon Chain.
    pub fn genesis(
        genesis_time: u64,
        initial_validator_deposits: Vec<Deposit>,
        latest_eth1_data: Eth1Data,
        spec: &ChainSpec,
    ) -> BeaconState {
        let initial_crosslink = Crosslink {
            epoch: spec.genesis_epoch,
            shard_block_root: spec.zero_hash,
        };

        let mut genesis_state = BeaconState {
            /*
             * Misc
             */
            slot: spec.genesis_slot,
            genesis_time,
            fork: Fork {
                previous_version: spec.genesis_fork_version,
                current_version: spec.genesis_fork_version,
                epoch: spec.genesis_epoch,
            },

            /*
             * Validator registry
             */
            validator_registry: vec![], // Set later in the function.
            validator_balances: vec![], // Set later in the function.
            validator_registry_update_epoch: spec.genesis_epoch,

            /*
             * Randomness and committees
             */
            latest_randao_mixes: vec![spec.zero_hash; spec.latest_randao_mixes_length as usize],
            previous_epoch_start_shard: spec.genesis_start_shard,
            current_epoch_start_shard: spec.genesis_start_shard,
            previous_calculation_epoch: spec.genesis_epoch,
            current_calculation_epoch: spec.genesis_epoch,
            previous_epoch_seed: spec.zero_hash,
            current_epoch_seed: spec.zero_hash,

            /*
             * Finality
             */
            previous_justified_epoch: spec.genesis_epoch,
            justified_epoch: spec.genesis_epoch,
            justification_bitfield: 0,
            finalized_epoch: spec.genesis_epoch,

            /*
             * Recent state
             */
            latest_crosslinks: vec![initial_crosslink; spec.shard_count as usize],
            latest_block_roots: vec![spec.zero_hash; spec.latest_block_roots_length as usize],
            latest_index_roots: vec![spec.zero_hash; spec.latest_index_roots_length as usize],
            latest_penalized_balances: vec![0; spec.latest_penalized_exit_length as usize],
            latest_attestations: vec![],
            batched_block_roots: vec![],

            /*
             * PoW receipt root
             */
            latest_eth1_data,
            eth1_data_votes: vec![],
        };

        for deposit in initial_validator_deposits {
            let _index = genesis_state.process_deposit(
                deposit.deposit_data.deposit_input.pubkey,
                deposit.deposit_data.amount,
                deposit.deposit_data.deposit_input.proof_of_possession,
                deposit.deposit_data.deposit_input.withdrawal_credentials,
                spec,
            );
        }

        for validator_index in 0..genesis_state.validator_registry.len() {
            if genesis_state.get_effective_balance(validator_index, spec) >= spec.max_deposit_amount
            {
                genesis_state.activate_validator(validator_index, true, spec);
            }
        }

        let genesis_active_index_root = hash_tree_root(get_active_validator_indices(
            &genesis_state.validator_registry,
            spec.genesis_epoch,
        ));
        genesis_state.latest_index_roots =
            vec![genesis_active_index_root; spec.latest_index_roots_length];
        genesis_state.current_epoch_seed = genesis_state
            .generate_seed(spec.genesis_epoch, spec)
            .expect("Unable to generate seed.");

        genesis_state
    }

    /// Return the tree hash root for this `BeaconState`.
    ///
    /// Spec v0.2.0
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from(&self.hash_tree_root()[..])
    }

    /// The epoch corresponding to `self.slot`.
    ///
    /// Spec v0.2.0
    pub fn current_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.slot.epoch(spec.epoch_length)
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// Spec v0.2.0
    pub fn previous_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.current_epoch(spec).saturating_sub(1_u64)
    }

    /// The epoch following `self.current_epoch()`.
    ///
    /// Spec v0.2.0
    pub fn next_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.current_epoch(spec).saturating_add(1_u64)
    }

    /// The first slot of the epoch corresponding to `self.slot`.
    ///
    /// Spec v0.2.0
    pub fn current_epoch_start_slot(&self, spec: &ChainSpec) -> Slot {
        self.current_epoch(spec).start_slot(spec.epoch_length)
    }

    /// The first slot of the epoch preceeding the one corresponding to `self.slot`.
    ///
    /// Spec v0.2.0
    pub fn previous_epoch_start_slot(&self, spec: &ChainSpec) -> Slot {
        self.previous_epoch(spec).start_slot(spec.epoch_length)
    }

    /// Return the number of committees in one epoch.
    ///
    /// TODO: this should probably be a method on `ChainSpec`.
    ///
    /// Spec v0.2.0
    pub fn get_epoch_committee_count(
        &self,
        active_validator_count: usize,
        spec: &ChainSpec,
    ) -> u64 {
        std::cmp::max(
            1,
            std::cmp::min(
                spec.shard_count / spec.epoch_length,
                active_validator_count as u64 / spec.epoch_length / spec.target_committee_size,
            ),
        ) * spec.epoch_length
    }

    /// Shuffle ``validators`` into crosslink committees seeded by ``seed`` and ``epoch``.
    /// Return a list of ``committees_per_epoch`` committees where each
    /// committee is itself a list of validator indices.
    ///
    /// Spec v0.1
    pub fn get_shuffling(&self, seed: Hash256, epoch: Epoch, spec: &ChainSpec) -> Vec<Vec<usize>> {
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, epoch);

        let committees_per_epoch =
            self.get_epoch_committee_count(active_validator_indices.len(), spec);

        // TODO: check that Hash256::from(u64) matches 'int_to_bytes32'.
        let seed = seed ^ Hash256::from(epoch.as_u64());
        // TODO: fix `expect` assert.
        let shuffled_active_validator_indices =
            shuffle(&seed, active_validator_indices).expect("Max validator count exceed!");

        shuffled_active_validator_indices
            .honey_badger_split(committees_per_epoch as usize)
            .map(|slice: &[usize]| slice.to_vec())
            .collect()
    }

    /// Return the number of committees in the previous epoch.
    ///
    /// Spec v0.2.0
    fn get_previous_epoch_committee_count(&self, spec: &ChainSpec) -> u64 {
        let previous_active_validators =
            get_active_validator_indices(&self.validator_registry, self.previous_calculation_epoch);
        self.get_epoch_committee_count(previous_active_validators.len(), spec)
    }

    /// Return the number of committees in the current epoch.
    ///
    /// Spec v0.2.0
    pub fn get_current_epoch_committee_count(&self, spec: &ChainSpec) -> u64 {
        let current_active_validators =
            get_active_validator_indices(&self.validator_registry, self.current_calculation_epoch);
        self.get_epoch_committee_count(current_active_validators.len(), spec)
    }

    /// Return the number of committees in the next epoch.
    ///
    /// Spec v0.2.0
    pub fn get_next_epoch_committee_count(&self, spec: &ChainSpec) -> u64 {
        let current_active_validators =
            get_active_validator_indices(&self.validator_registry, self.next_epoch(spec));
        self.get_epoch_committee_count(current_active_validators.len(), spec)
    }

    pub fn get_active_index_root(&self, epoch: Epoch, spec: &ChainSpec) -> Option<Hash256> {
        let current_epoch = self.current_epoch(spec);

        let earliest_index_root = current_epoch - Epoch::from(spec.latest_index_roots_length)
            + Epoch::from(spec.entry_exit_delay)
            + 1;
        let latest_index_root = current_epoch + spec.entry_exit_delay;

        if (epoch <= earliest_index_root) & (epoch >= latest_index_root) {
            Some(self.latest_index_roots[epoch.as_usize() % spec.latest_index_roots_length])
        } else {
            None
        }
    }

    /// Generate a seed for the given ``epoch``.
    ///
    /// Spec v0.2.0
    pub fn generate_seed(&self, epoch: Epoch, spec: &ChainSpec) -> Option<Hash256> {
        let mut input = self.get_randao_mix(epoch, spec)?.to_vec();
        input.append(&mut self.get_active_index_root(epoch, spec)?.to_vec());
        // TODO: ensure `Hash256::from(u64)` == `int_to_bytes32`.
        input.append(&mut Hash256::from(epoch.as_u64()).to_vec());
        Some(Hash256::from(&hash(&input[..])[..]))
    }

    /// Return the list of ``(committee, shard)`` tuples for the ``slot``.
    ///
    /// Note: There are two possible shufflings for crosslink committees for a
    /// `slot` in the next epoch: with and without a `registry_change`
    ///
    /// Spec v0.2.0
    pub fn get_crosslink_committees_at_slot(
        &self,
        slot: Slot,
        registry_change: bool,
        spec: &ChainSpec,
    ) -> Result<Vec<(Vec<usize>, u64)>, CommitteesError> {
        let epoch = slot.epoch(spec.epoch_length);
        let current_epoch = self.current_epoch(spec);
        let previous_epoch = if current_epoch == spec.genesis_epoch {
            current_epoch
        } else {
            current_epoch.saturating_sub(1_u64)
        };
        let next_epoch = self.next_epoch(spec);

        let (committees_per_epoch, seed, shuffling_epoch, shuffling_start_shard) =
            if epoch == previous_epoch {
                (
                    self.get_previous_epoch_committee_count(spec),
                    self.previous_epoch_seed,
                    self.previous_calculation_epoch,
                    self.previous_epoch_start_shard,
                )
            } else if epoch == current_epoch {
                (
                    self.get_current_epoch_committee_count(spec),
                    self.current_epoch_seed,
                    self.current_calculation_epoch,
                    self.current_epoch_start_shard,
                )
            } else if epoch == next_epoch {
                let current_committees_per_epoch = self.get_current_epoch_committee_count(spec);
                let epochs_since_last_registry_update =
                    current_epoch - self.validator_registry_update_epoch;
                let (seed, shuffling_start_shard) = if registry_change {
                    let next_seed = self
                        .generate_seed(next_epoch, spec)
                        .ok_or_else(|| CommitteesError::BadRandao)?;
                    (
                        next_seed,
                        (self.current_epoch_start_shard + current_committees_per_epoch)
                            % spec.shard_count,
                    )
                } else if (epochs_since_last_registry_update > 1)
                    & epochs_since_last_registry_update.is_power_of_two()
                {
                    let next_seed = self
                        .generate_seed(next_epoch, spec)
                        .ok_or_else(|| CommitteesError::BadRandao)?;
                    (next_seed, self.current_epoch_start_shard)
                } else {
                    (self.current_epoch_seed, self.current_epoch_start_shard)
                };
                (
                    self.get_next_epoch_committee_count(spec),
                    seed,
                    next_epoch,
                    shuffling_start_shard,
                )
            } else {
                panic!("Epoch out-of-bounds.")
            };

        let shuffling = self.get_shuffling(seed, shuffling_epoch, spec);
        let offset = slot.as_u64() % spec.epoch_length;
        let committees_per_slot = committees_per_epoch / spec.epoch_length;
        let slot_start_shard =
            (shuffling_start_shard + committees_per_slot * offset) % spec.shard_count;

        let mut crosslinks_at_slot = vec![];
        for i in 0..committees_per_slot {
            let tuple = (
                shuffling[(committees_per_slot * offset + i) as usize].clone(),
                (slot_start_shard + i) % spec.shard_count,
            );
            crosslinks_at_slot.push(tuple)
        }
        Ok(crosslinks_at_slot)
    }

    /// Returns the `slot`, `shard` and `committee_index` for which a validator must produce an
    /// attestation.
    ///
    /// Spec v0.2.0
    pub fn attestation_slot_and_shard_for_validator(
        &self,
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<Option<(Slot, u64, u64)>, CommitteesError> {
        let mut result = None;
        for slot in self.current_epoch(spec).slot_iter(spec.epoch_length) {
            for (committee, shard) in self.get_crosslink_committees_at_slot(slot, false, spec)? {
                if let Some(committee_index) = committee.iter().position(|&i| i == validator_index)
                {
                    result = Some((slot, shard, committee_index as u64));
                }
            }
        }
        Ok(result)
    }

    /// An entry or exit triggered in the ``epoch`` given by the input takes effect at
    /// the epoch given by the output.
    ///
    /// Spec v0.2.0
    pub fn get_entry_exit_effect_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> Epoch {
        epoch + 1 + spec.entry_exit_delay
    }

    /// Returns the beacon proposer index for the `slot`.
    ///
    /// If the state does not contain an index for a beacon proposer at the requested `slot`, then `None` is returned.
    ///
    /// Spec v0.2.0
    pub fn get_beacon_proposer_index(
        &self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<usize, CommitteesError> {
        let committees = self.get_crosslink_committees_at_slot(slot, false, spec)?;
        committees
            .first()
            .ok_or(CommitteesError::InsufficientNumberOfValidators)
            .and_then(|(first_committee, _)| {
                let index = (slot.as_usize())
                    .checked_rem(first_committee.len())
                    .ok_or(CommitteesError::InsufficientNumberOfValidators)?;
                // NOTE: next index will not panic as we have already returned if this is the case.
                Ok(first_committee[index])
            })
    }

    /// Process the penalties and prepare the validators who are eligible to withdrawal.
    ///
    /// Spec v0.2.0
    pub fn process_penalties_and_exits(&mut self, spec: &ChainSpec) {
        let current_epoch = self.current_epoch(spec);
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, current_epoch);
        let total_balance = self.get_total_balance(&active_validator_indices[..], spec);

        for index in 0..self.validator_balances.len() {
            let validator = &self.validator_registry[index];

            if current_epoch
                == validator.penalized_epoch + Epoch::from(spec.latest_penalized_exit_length / 2)
            {
                let epoch_index: usize =
                    current_epoch.as_usize() % spec.latest_penalized_exit_length;

                let total_at_start = self.latest_penalized_balances
                    [(epoch_index + 1) % spec.latest_penalized_exit_length];
                let total_at_end = self.latest_penalized_balances[epoch_index];
                let total_penalities = total_at_end.saturating_sub(total_at_start);
                let penalty = self.get_effective_balance(index, spec)
                    * std::cmp::min(total_penalities * 3, total_balance)
                    / total_balance;
                safe_sub_assign!(self.validator_balances[index], penalty);
            }
        }

        let eligible = |index: usize| {
            let validator = &self.validator_registry[index];

            if validator.penalized_epoch <= current_epoch {
                let penalized_withdrawal_epochs = spec.latest_penalized_exit_length / 2;
                current_epoch >= validator.penalized_epoch + penalized_withdrawal_epochs as u64
            } else {
                current_epoch >= validator.exit_epoch + spec.min_validator_withdrawal_epochs
            }
        };

        let mut eligable_indices: Vec<usize> = (0..self.validator_registry.len())
            .filter(|i| eligible(*i))
            .collect();
        eligable_indices.sort_by_key(|i| self.validator_registry[*i].exit_epoch);
        for (withdrawn_so_far, index) in eligable_indices.iter().enumerate() {
            self.prepare_validator_for_withdrawal(*index);
            if withdrawn_so_far as u64 >= spec.max_withdrawals_per_epoch {
                break;
            }
        }
    }

    /// Return the randao mix at a recent ``epoch``.
    ///
    /// Returns `None` if the epoch is out-of-bounds of `self.latest_randao_mixes`.
    ///
    /// Spec v0.2.0
    pub fn get_randao_mix(&self, epoch: Epoch, spec: &ChainSpec) -> Option<&Hash256> {
        self.latest_randao_mixes
            .get(epoch.as_usize() % spec.latest_randao_mixes_length)
    }

    /// Update validator registry, activating/exiting validators if possible.
    ///
    /// Spec v0.2.0
    pub fn update_validator_registry(&mut self, spec: &ChainSpec) {
        let current_epoch = self.current_epoch(spec);
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, current_epoch);
        let total_balance = self.get_total_balance(&active_validator_indices[..], spec);

        let max_balance_churn = std::cmp::max(
            spec.max_deposit_amount,
            total_balance / (2 * spec.max_balance_churn_quotient),
        );

        let mut balance_churn = 0;
        for index in 0..self.validator_registry.len() {
            let validator = &self.validator_registry[index];

            if (validator.activation_epoch > self.get_entry_exit_effect_epoch(current_epoch, spec))
                && self.validator_balances[index] >= spec.max_deposit_amount
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

            if (validator.exit_epoch > self.get_entry_exit_effect_epoch(current_epoch, spec))
                && validator.status_flags == Some(StatusFlags::InitiatedExit)
            {
                balance_churn += self.get_effective_balance(index, spec);
                if balance_churn > max_balance_churn {
                    break;
                }

                self.exit_validator(index, spec);
            }
        }

        self.validator_registry_update_epoch = current_epoch;
    }
    /// Process a validator deposit, returning the validator index if the deposit is valid.
    ///
    /// Spec v0.2.0
    pub fn process_deposit(
        &mut self,
        pubkey: PublicKey,
        amount: u64,
        proof_of_possession: Signature,
        withdrawal_credentials: Hash256,
        spec: &ChainSpec,
    ) -> Result<usize, ()> {
        // TODO: ensure verify proof-of-possession represents the spec accurately.
        if !verify_proof_of_possession(&proof_of_possession, &pubkey) {
            return Err(());
        }

        if let Some(index) = self
            .validator_registry
            .iter()
            .position(|v| v.pubkey == pubkey)
        {
            if self.validator_registry[index].withdrawal_credentials == withdrawal_credentials {
                safe_add_assign!(self.validator_balances[index], amount);
                Ok(index)
            } else {
                Err(())
            }
        } else {
            let validator = Validator {
                pubkey,
                withdrawal_credentials,
                activation_epoch: spec.far_future_epoch,
                exit_epoch: spec.far_future_epoch,
                withdrawal_epoch: spec.far_future_epoch,
                penalized_epoch: spec.far_future_epoch,
                status_flags: None,
            };
            self.validator_registry.push(validator);
            self.validator_balances.push(amount);
            Ok(self.validator_registry.len() - 1)
        }
    }

    /// Activate the validator of the given ``index``.
    ///
    /// Spec v0.2.0
    pub fn activate_validator(
        &mut self,
        validator_index: usize,
        is_genesis: bool,
        spec: &ChainSpec,
    ) {
        let current_epoch = self.current_epoch(spec);

        self.validator_registry[validator_index].activation_epoch = if is_genesis {
            spec.genesis_epoch
        } else {
            self.get_entry_exit_effect_epoch(current_epoch, spec)
        }
    }

    /// Initiate an exit for the validator of the given `index`.
    ///
    /// Spec v0.2.0
    pub fn initiate_validator_exit(&mut self, validator_index: usize) {
        // TODO: the spec does an `|=` here, ensure this isn't buggy.
        self.validator_registry[validator_index].status_flags = Some(StatusFlags::InitiatedExit);
    }

    /// Exit the validator of the given `index`.
    ///
    /// Spec v0.2.0
    fn exit_validator(&mut self, validator_index: usize, spec: &ChainSpec) {
        let current_epoch = self.current_epoch(spec);

        if self.validator_registry[validator_index].exit_epoch
            <= self.get_entry_exit_effect_epoch(current_epoch, spec)
        {
            return;
        }

        self.validator_registry[validator_index].exit_epoch =
            self.get_entry_exit_effect_epoch(current_epoch, spec);
    }

    ///  Penalize the validator of the given ``index``.
    ///
    ///  Exits the validator and assigns its effective balance to the block producer for this
    ///  state.
    ///
    /// Spec v0.2.0
    pub fn penalize_validator(
        &mut self,
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<(), CommitteesError> {
        self.exit_validator(validator_index, spec);
        let current_epoch = self.current_epoch(spec);

        self.latest_penalized_balances
            [current_epoch.as_usize() % spec.latest_penalized_exit_length] +=
            self.get_effective_balance(validator_index, spec);

        let whistleblower_index = self.get_beacon_proposer_index(self.slot, spec)?;
        let whistleblower_reward = self.get_effective_balance(validator_index, spec);
        safe_add_assign!(
            self.validator_balances[whistleblower_index as usize],
            whistleblower_reward
        );
        safe_sub_assign!(
            self.validator_balances[validator_index],
            whistleblower_reward
        );
        self.validator_registry[validator_index].penalized_epoch = current_epoch;
        Ok(())
    }

    /// Initiate an exit for the validator of the given `index`.
    ///
    /// Spec v0.2.0
    pub fn prepare_validator_for_withdrawal(&mut self, validator_index: usize) {
        //TODO: we're not ANDing here, we're setting. Potentially wrong.
        self.validator_registry[validator_index].status_flags = Some(StatusFlags::Withdrawable);
    }

    /// Iterate through the validator registry and eject active validators with balance below
    /// ``EJECTION_BALANCE``.
    ///
    /// Spec v0.2.0
    pub fn process_ejections(&mut self, spec: &ChainSpec) {
        for validator_index in
            get_active_validator_indices(&self.validator_registry, self.current_epoch(spec))
        {
            if self.validator_balances[validator_index] < spec.ejection_balance {
                self.exit_validator(validator_index, spec)
            }
        }
    }

    /// Returns the penality that should be applied to some validator for inactivity.
    ///
    /// Note: this is defined "inline" in the spec, not as a helper function.
    ///
    /// Spec v0.2.0
    pub fn inactivity_penalty(
        &self,
        validator_index: usize,
        epochs_since_finality: Epoch,
        base_reward_quotient: u64,
        spec: &ChainSpec,
    ) -> u64 {
        let effective_balance = self.get_effective_balance(validator_index, spec);
        self.base_reward(validator_index, base_reward_quotient, spec)
            + effective_balance * epochs_since_finality.as_u64()
                / spec.inactivity_penalty_quotient
                / 2
    }

    /// Returns the distance between the first included attestation for some validator and this
    /// slot.
    ///
    /// Note: In the spec this is defined "inline", not as a helper function.
    ///
    /// Spec v0.2.0
    pub fn inclusion_distance(
        &self,
        attestations: &[&PendingAttestation],
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<u64, InclusionError> {
        let attestation =
            self.earliest_included_attestation(attestations, validator_index, spec)?;
        Ok((attestation.inclusion_slot - attestation.data.slot).as_u64())
    }

    /// Returns the slot of the earliest included attestation for some validator.
    ///
    /// Note: In the spec this is defined "inline", not as a helper function.
    ///
    /// Spec v0.2.0
    pub fn inclusion_slot(
        &self,
        attestations: &[&PendingAttestation],
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<Slot, InclusionError> {
        let attestation =
            self.earliest_included_attestation(attestations, validator_index, spec)?;
        Ok(attestation.inclusion_slot)
    }

    /// Finds the earliest included attestation for some validator.
    ///
    /// Note: In the spec this is defined "inline", not as a helper function.
    ///
    /// Spec v0.2.0
    fn earliest_included_attestation(
        &self,
        attestations: &[&PendingAttestation],
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<PendingAttestation, InclusionError> {
        let mut included_attestations = vec![];

        for (i, a) in attestations.iter().enumerate() {
            let participants =
                self.get_attestation_participants(&a.data, &a.aggregation_bitfield, spec)?;
            if participants.iter().any(|i| *i == validator_index) {
                included_attestations.push(i);
            }
        }

        let earliest_attestation_index = included_attestations
            .iter()
            .min_by_key(|i| attestations[**i].inclusion_slot)
            .ok_or_else(|| InclusionError::NoIncludedAttestations)?;
        Ok(attestations[*earliest_attestation_index].clone())
    }

    /// Returns the base reward for some validator.
    ///
    /// Note: In the spec this is defined "inline", not as a helper function.
    ///
    /// Spec v0.2.0
    pub fn base_reward(
        &self,
        validator_index: usize,
        base_reward_quotient: u64,
        spec: &ChainSpec,
    ) -> u64 {
        self.get_effective_balance(validator_index, spec) / base_reward_quotient / 5
    }

    /// Return the combined effective balance of an array of validators.
    ///
    /// Spec v0.2.0
    pub fn get_total_balance(&self, validator_indices: &[usize], spec: &ChainSpec) -> u64 {
        validator_indices
            .iter()
            .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec))
    }

    /// Return the effective balance (also known as "balance at stake") for a validator with the given ``index``.
    ///
    /// Spec v0.2.0
    pub fn get_effective_balance(&self, validator_index: usize, spec: &ChainSpec) -> u64 {
        std::cmp::min(
            self.validator_balances[validator_index],
            spec.max_deposit_amount,
        )
    }

    /// Return the block root at a recent `slot`.
    ///
    /// Spec v0.2.0
    pub fn get_block_root(&self, slot: Slot, spec: &ChainSpec) -> Option<&Hash256> {
        self.latest_block_roots
            .get(slot.as_usize() % spec.latest_block_roots_length)
    }

    pub fn get_attestation_participants_union(
        &self,
        attestations: &[&PendingAttestation],
        spec: &ChainSpec,
    ) -> Result<Vec<usize>, AttestationParticipantsError> {
        let mut all_participants = attestations.iter().try_fold::<_, _, Result<
            Vec<usize>,
            AttestationParticipantsError,
        >>(vec![], |mut acc, a| {
            acc.append(&mut self.get_attestation_participants(
                &a.data,
                &a.aggregation_bitfield,
                spec,
            )?);
            Ok(acc)
        })?;
        all_participants.sort_unstable();
        all_participants.dedup();
        Ok(all_participants)
    }

    /// Return the participant indices at for the ``attestation_data`` and ``bitfield``.
    ///
    /// In effect, this converts the "committee indices" on the bitfield into "validator indices"
    /// for self.validator_registy.
    ///
    /// Spec v0.2.0
    pub fn get_attestation_participants(
        &self,
        attestation_data: &AttestationData,
        bitfield: &Bitfield,
        spec: &ChainSpec,
    ) -> Result<Vec<usize>, AttestationParticipantsError> {
        let crosslink_committees =
            self.get_crosslink_committees_at_slot(attestation_data.slot, false, spec)?;

        let committee_index: usize = crosslink_committees
            .iter()
            .position(|(_committee, shard)| *shard == attestation_data.shard)
            .ok_or_else(|| AttestationParticipantsError::NoCommitteeForShard)?;
        let (crosslink_committee, _shard) = &crosslink_committees[committee_index];

        /*
         * TODO: verify bitfield length is valid.
         */

        let mut participants = vec![];
        for (i, validator_index) in crosslink_committee.iter().enumerate() {
            if bitfield.get(i).unwrap() {
                participants.push(*validator_index);
            }
        }
        Ok(participants)
    }
}

fn hash_tree_root<T: TreeHash>(input: Vec<T>) -> Hash256 {
    Hash256::from(&input.hash_tree_root()[..])
}

impl From<AttestationParticipantsError> for AttestationValidationError {
    fn from(e: AttestationParticipantsError) -> AttestationValidationError {
        AttestationValidationError::AttestationParticipantsError(e)
    }
}

impl From<CommitteesError> for AttestationParticipantsError {
    fn from(e: CommitteesError) -> AttestationParticipantsError {
        AttestationParticipantsError::CommitteesError(e)
    }
}

/*

*/

impl From<AttestationParticipantsError> for InclusionError {
    fn from(e: AttestationParticipantsError) -> InclusionError {
        InclusionError::AttestationParticipantsError(e)
    }
}

impl From<CommitteesError> for Error {
    fn from(e: CommitteesError) -> Error {
        Error::CommitteesError(e)
    }
}

impl Encodable for BeaconState {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.genesis_time);
        s.append(&self.fork);
        s.append(&self.validator_registry);
        s.append(&self.validator_balances);
        s.append(&self.validator_registry_update_epoch);
        s.append(&self.latest_randao_mixes);
        s.append(&self.previous_epoch_start_shard);
        s.append(&self.current_epoch_start_shard);
        s.append(&self.previous_calculation_epoch);
        s.append(&self.current_calculation_epoch);
        s.append(&self.previous_epoch_seed);
        s.append(&self.current_epoch_seed);
        s.append(&self.previous_justified_epoch);
        s.append(&self.justified_epoch);
        s.append(&self.justification_bitfield);
        s.append(&self.finalized_epoch);
        s.append(&self.latest_crosslinks);
        s.append(&self.latest_block_roots);
        s.append(&self.latest_index_roots);
        s.append(&self.latest_penalized_balances);
        s.append(&self.latest_attestations);
        s.append(&self.batched_block_roots);
        s.append(&self.latest_eth1_data);
        s.append(&self.eth1_data_votes);
    }
}

impl Decodable for BeaconState {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (genesis_time, i) = <_>::ssz_decode(bytes, i)?;
        let (fork, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_balances, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_update_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_randao_mixes, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_epoch_start_shard, i) = <_>::ssz_decode(bytes, i)?;
        let (current_epoch_start_shard, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_calculation_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (current_calculation_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_epoch_seed, i) = <_>::ssz_decode(bytes, i)?;
        let (current_epoch_seed, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_justified_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (justified_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (justification_bitfield, i) = <_>::ssz_decode(bytes, i)?;
        let (finalized_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_crosslinks, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_block_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_index_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_penalized_balances, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_attestations, i) = <_>::ssz_decode(bytes, i)?;
        let (batched_block_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_eth1_data, i) = <_>::ssz_decode(bytes, i)?;
        let (eth1_data_votes, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                genesis_time,
                fork,
                validator_registry,
                validator_balances,
                validator_registry_update_epoch,
                latest_randao_mixes,
                previous_epoch_start_shard,
                current_epoch_start_shard,
                previous_calculation_epoch,
                current_calculation_epoch,
                previous_epoch_seed,
                current_epoch_seed,
                previous_justified_epoch,
                justified_epoch,
                justification_bitfield,
                finalized_epoch,
                latest_crosslinks,
                latest_block_roots,
                latest_index_roots,
                latest_penalized_balances,
                latest_attestations,
                batched_block_roots,
                latest_eth1_data,
                eth1_data_votes,
            },
            i,
        ))
    }
}

impl TreeHash for BeaconState {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.slot.hash_tree_root());
        result.append(&mut self.genesis_time.hash_tree_root());
        result.append(&mut self.fork.hash_tree_root());
        result.append(&mut self.validator_registry.hash_tree_root());
        result.append(&mut self.validator_balances.hash_tree_root());
        result.append(&mut self.validator_registry_update_epoch.hash_tree_root());
        result.append(&mut self.latest_randao_mixes.hash_tree_root());
        result.append(&mut self.previous_epoch_start_shard.hash_tree_root());
        result.append(&mut self.current_epoch_start_shard.hash_tree_root());
        result.append(&mut self.previous_calculation_epoch.hash_tree_root());
        result.append(&mut self.current_calculation_epoch.hash_tree_root());
        result.append(&mut self.previous_epoch_seed.hash_tree_root());
        result.append(&mut self.current_epoch_seed.hash_tree_root());
        result.append(&mut self.previous_justified_epoch.hash_tree_root());
        result.append(&mut self.justified_epoch.hash_tree_root());
        result.append(&mut self.justification_bitfield.hash_tree_root());
        result.append(&mut self.finalized_epoch.hash_tree_root());
        result.append(&mut self.latest_crosslinks.hash_tree_root());
        result.append(&mut self.latest_block_roots.hash_tree_root());
        result.append(&mut self.latest_index_roots.hash_tree_root());
        result.append(&mut self.latest_penalized_balances.hash_tree_root());
        result.append(&mut self.latest_attestations.hash_tree_root());
        result.append(&mut self.batched_block_roots.hash_tree_root());
        result.append(&mut self.latest_eth1_data.hash_tree_root());
        result.append(&mut self.eth1_data_votes.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for BeaconState {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            genesis_time: <_>::random_for_test(rng),
            fork: <_>::random_for_test(rng),
            validator_registry: <_>::random_for_test(rng),
            validator_balances: <_>::random_for_test(rng),
            validator_registry_update_epoch: <_>::random_for_test(rng),
            latest_randao_mixes: <_>::random_for_test(rng),
            previous_epoch_start_shard: <_>::random_for_test(rng),
            current_epoch_start_shard: <_>::random_for_test(rng),
            previous_calculation_epoch: <_>::random_for_test(rng),
            current_calculation_epoch: <_>::random_for_test(rng),
            previous_epoch_seed: <_>::random_for_test(rng),
            current_epoch_seed: <_>::random_for_test(rng),
            previous_justified_epoch: <_>::random_for_test(rng),
            justified_epoch: <_>::random_for_test(rng),
            justification_bitfield: <_>::random_for_test(rng),
            finalized_epoch: <_>::random_for_test(rng),
            latest_crosslinks: <_>::random_for_test(rng),
            latest_block_roots: <_>::random_for_test(rng),
            latest_index_roots: <_>::random_for_test(rng),
            latest_penalized_balances: <_>::random_for_test(rng),
            latest_attestations: <_>::random_for_test(rng),
            batched_block_roots: <_>::random_for_test(rng),
            latest_eth1_data: <_>::random_for_test(rng),
            eth1_data_votes: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = BeaconState::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = BeaconState::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
