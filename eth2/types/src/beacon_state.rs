use crate::test_utils::TestRandom;
use crate::{
    validator::StatusFlags, validator_registry::get_active_validator_indices, AggregatePublicKey,
    Attestation, AttestationData, BeaconBlock, Bitfield, ChainSpec, Crosslink, Eth1Data,
    Eth1DataVote, Exit, Fork, Hash256, PendingAttestation, PublicKey, Signature, Slot, Validator,
};
use bls::bls_verify_aggregate;
use honey_badger_split::SplitExt;
use integer_sqrt::IntegerSquareRoot;
use log::debug;
use rand::RngCore;
use rayon::prelude::*;
use serde_derive::Serialize;
use ssz::ssz_encode;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::ops::Range;
use vec_shuffle::shuffle;

// TODO: define elsehwere.
const DOMAIN_PROPOSAL: u64 = 2;
const DOMAIN_EXIT: u64 = 3;
const DOMAIN_RANDAO: u64 = 4;
const PHASE_0_CUSTODY_BIT: bool = false;
const DOMAIN_ATTESTATION: u64 = 1;

pub enum Error {
    InsufficientValidators,
    BadBlockSignature,
    InvalidEpoch(u64, Range<u64>),
    CommitteesError(CommitteesError),
}

#[derive(Debug, PartialEq)]
pub enum BlockProcessingError {
    DBError(String),
    StateAlreadyTransitioned,
    PresentSlotIsNone,
    UnableToDecodeBlock,
    MissingParentState(Hash256),
    InvalidParentState(Hash256),
    MissingBeaconBlock(Hash256),
    InvalidBeaconBlock(Hash256),
    MissingParentBlock(Hash256),
    NoBlockProducer,
    StateSlotMismatch,
    BadBlockSignature,
    BadRandaoSignature,
    MaxProposerSlashingsExceeded,
    BadProposerSlashing,
    MaxAttestationsExceeded,
    InvalidAttestation(AttestationValidationError),
    NoBlockRoot,
    MaxDepositsExceeded,
    MaxExitsExceeded,
    BadExit,
    BadCustodyReseeds,
    BadCustodyChallenges,
    BadCustodyResponses,
    CommitteesError(CommitteesError),
    SlotProcessingError(SlotProcessingError),
}

#[derive(Debug, PartialEq)]
pub enum EpochError {
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

#[derive(Debug, PartialEq)]
pub enum CommitteesError {
    InvalidEpoch(u64, Range<u64>),
    InsufficientNumberOfValidators,
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
pub enum SlotProcessingError {
    CommitteesError(CommitteesError),
    EpochProcessingError(EpochError),
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

#[derive(Clone)]
pub struct WinningRoot {
    pub shard_block_root: Hash256,
    pub attesting_validator_indices: Vec<usize>,
    pub total_balance: u64,
    pub total_attesting_balance: u64,
}

macro_rules! ensure {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
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

// Custody will not be added to the specs until Phase 1 (Sharding Phase) so dummy class used.
type CustodyChallenge = usize;

#[derive(Debug, PartialEq, Clone, Default, Serialize)]
pub struct BeaconState {
    // Misc
    pub slot: Slot,
    pub genesis_time: u64,
    pub fork_data: Fork,

    // Validator registry
    pub validator_registry: Vec<Validator>,
    pub validator_balances: Vec<u64>,
    pub validator_registry_update_slot: Slot,
    pub validator_registry_exit_count: u64,
    pub validator_registry_delta_chain_tip: Hash256,

    // Randomness and committees
    pub latest_randao_mixes: Vec<Hash256>,
    pub latest_vdf_outputs: Vec<Hash256>,
    pub previous_epoch_start_shard: u64,
    pub current_epoch_start_shard: u64,
    pub previous_epoch_calculation_slot: Slot,
    pub current_epoch_calculation_slot: Slot,
    pub previous_epoch_seed: Hash256,
    pub current_epoch_seed: Hash256,

    // Custody challenges
    pub custody_challenges: Vec<CustodyChallenge>,

    // Finality
    pub previous_justified_slot: Slot,
    pub justified_slot: Slot,
    pub justification_bitfield: u64,
    pub finalized_slot: Slot,

    // Recent state
    pub latest_crosslinks: Vec<Crosslink>,
    pub latest_block_roots: Vec<Hash256>,
    pub latest_penalized_balances: Vec<u64>,
    pub latest_attestations: Vec<PendingAttestation>,
    pub batched_block_roots: Vec<Hash256>,

    // Ethereum 1.0 chain data
    pub latest_eth1_data: Eth1Data,
    pub eth1_data_votes: Vec<Eth1DataVote>,
}

impl BeaconState {
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from(&self.hash_tree_root()[..])
    }

    pub fn current_epoch(&self, spec: &ChainSpec) -> u64 {
        self.slot / spec.epoch_length
    }

    pub fn previous_epoch(&self, spec: &ChainSpec) -> u64 {
        self.current_epoch(spec).saturating_sub(1)
    }

    pub fn current_epoch_start_slot(&self, spec: &ChainSpec) -> u64 {
        self.current_epoch(spec) * spec.epoch_length
    }

    pub fn previous_epoch_start_slot(&self, spec: &ChainSpec) -> u64 {
        self.previous_epoch(spec) * spec.epoch_length
    }

    /// Returns the number of committees per slot.
    ///
    /// Note: this is _not_ the committee size.
    pub fn get_committee_count_per_slot(
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
        )
    }

    /// Returns the start slot and end slot of the current epoch containing `self.slot`.
    pub fn get_current_epoch_boundaries(&self, epoch_length: u64) -> Range<u64> {
        let slot_in_epoch = self.slot % epoch_length;
        let start = self.slot - slot_in_epoch;
        let end = self.slot + (epoch_length - slot_in_epoch);
        start..end
    }

    /// Returns the start slot and end slot of the current epoch containing `self.slot`.
    pub fn get_previous_epoch_boundaries(&self, spec: &ChainSpec) -> Range<u64> {
        let current_epoch = self.slot / spec.epoch_length;
        let previous_epoch = current_epoch.saturating_sub(1);
        let start = previous_epoch * spec.epoch_length;
        let end = start + spec.epoch_length;
        start..end
    }

    fn get_previous_epoch_committee_count_per_slot(&self, spec: &ChainSpec) -> u64 {
        let previous_active_validators = get_active_validator_indices(
            &self.validator_registry,
            self.previous_epoch_calculation_slot,
        );
        self.get_committee_count_per_slot(previous_active_validators.len(), spec) as u64
    }

    pub fn get_current_epoch_committee_count_per_slot(&self, spec: &ChainSpec) -> u64 {
        let current_active_validators = get_active_validator_indices(
            &self.validator_registry,
            self.current_epoch_calculation_slot,
        );
        self.get_committee_count_per_slot(current_active_validators.len(), spec)
    }

    pub fn get_crosslink_committees_at_slot(
        &self,
        slot: u64,
        spec: &ChainSpec,
    ) -> Result<Vec<(Vec<usize>, u64)>, CommitteesError> {
        let epoch = slot / spec.epoch_length;
        let current_epoch = self.slot / spec.epoch_length;
        let previous_epoch = if current_epoch == spec.genesis_slot {
            current_epoch
        } else {
            current_epoch.saturating_sub(1)
        };
        let next_epoch = current_epoch + 1;

        ensure!(
            (previous_epoch <= epoch) & (epoch < next_epoch),
            CommitteesError::InvalidEpoch(slot, previous_epoch..current_epoch)
        );

        let offset = slot % spec.epoch_length;

        let (committees_per_slot, shuffling, slot_start_shard) = if epoch < current_epoch {
            let committees_per_slot = self.get_previous_epoch_committee_count_per_slot(spec);
            let shuffling = self.get_shuffling(
                self.previous_epoch_seed,
                self.previous_epoch_calculation_slot,
                spec,
            );
            let slot_start_shard =
                (self.previous_epoch_start_shard + committees_per_slot * offset) % spec.shard_count;
            (committees_per_slot, shuffling, slot_start_shard)
        } else {
            let committees_per_slot = self.get_current_epoch_committee_count_per_slot(spec);
            let shuffling = self.get_shuffling(
                self.current_epoch_seed,
                self.current_epoch_calculation_slot,
                spec,
            );
            let slot_start_shard =
                (self.current_epoch_start_shard + committees_per_slot * offset) % spec.shard_count;
            (committees_per_slot, shuffling, slot_start_shard)
        };

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

    pub fn per_slot_processing(
        &mut self,
        previous_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), SlotProcessingError> {
        if (self.slot + 1) % spec.epoch_length == 0 {
            self.per_epoch_processing(spec)?;
        }

        self.slot += 1;

        let block_proposer = self.get_beacon_proposer_index(self.slot, spec)?;

        self.validator_registry[block_proposer].proposer_slots += 1;
        self.latest_randao_mixes[(self.slot % spec.latest_randao_mixes_length) as usize] =
            self.latest_randao_mixes[((self.slot - 1) % spec.latest_randao_mixes_length) as usize];

        // Block roots.
        self.latest_block_roots[((self.slot - 1) % spec.latest_block_roots_length) as usize] =
            previous_block_root;

        if self.slot % spec.latest_block_roots_length == 0 {
            let root = merkle_root(&self.latest_block_roots[..]);
            self.batched_block_roots.push(root);
        }
        Ok(())
    }

    pub fn attestation_slot_and_shard_for_validator(
        &self,
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<Option<(u64, u64, u64)>, CommitteesError> {
        let mut result = None;
        for slot in self.get_current_epoch_boundaries(spec.epoch_length) {
            for (committee, shard) in self.get_crosslink_committees_at_slot(slot, spec)? {
                if let Some(committee_index) = committee.iter().position(|&i| i == validator_index)
                {
                    result = Some((slot, shard, committee_index as u64));
                }
            }
        }
        Ok(result)
    }

    pub fn per_block_processing(
        &mut self,
        block: &BeaconBlock,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        self.per_block_processing_signature_optional(block, true, spec)
    }

    pub fn per_block_processing_without_verifying_block_signature(
        &mut self,
        block: &BeaconBlock,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        self.per_block_processing_signature_optional(block, false, spec)
    }

    fn per_block_processing_signature_optional(
        &mut self,
        block: &BeaconBlock,
        verify_block_signature: bool,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        ensure!(
            block.slot == self.slot,
            BlockProcessingError::StateSlotMismatch
        );

        /*
         * Proposer Signature
         */
        let block_proposer_index = self
            .get_beacon_proposer_index(block.slot, spec)
            .map_err(|_| BlockProcessingError::NoBlockProducer)?;
        let block_proposer = &self.validator_registry[block_proposer_index];

        if verify_block_signature {
            ensure!(
                bls_verify(
                    &block_proposer.pubkey,
                    &block.proposal_root(spec)[..],
                    &block.signature,
                    get_domain(&self.fork_data, self.slot, DOMAIN_PROPOSAL)
                ),
                BlockProcessingError::BadBlockSignature
            );
        }

        /*
         * RANDAO
         */
        ensure!(
            bls_verify(
                &block_proposer.pubkey,
                &ssz_encode(&block_proposer.proposer_slots),
                &block.randao_reveal,
                get_domain(&self.fork_data, self.slot, DOMAIN_RANDAO)
            ),
            BlockProcessingError::BadRandaoSignature
        );

        // TODO: check this is correct.
        let new_mix = {
            let mut mix = self.latest_randao_mixes
                [(self.slot % spec.latest_randao_mixes_length) as usize]
                .to_vec();
            mix.append(&mut ssz_encode(&block.randao_reveal));
            Hash256::from(&hash(&mix)[..])
        };

        self.latest_randao_mixes[(self.slot % spec.latest_randao_mixes_length) as usize] = new_mix;

        /*
         * Eth1 data
         */

        // TODO: Eth1 data processing.

        /*
         * Proposer slashings
         */
        ensure!(
            block.body.proposer_slashings.len() as u64 <= spec.max_proposer_slashings,
            BlockProcessingError::MaxProposerSlashingsExceeded
        );
        for proposer_slashing in &block.body.proposer_slashings {
            let proposer = self
                .validator_registry
                .get(proposer_slashing.proposer_index as usize)
                .ok_or(BlockProcessingError::BadProposerSlashing)?;
            ensure!(
                proposer_slashing.proposal_data_1.slot == proposer_slashing.proposal_data_2.slot,
                BlockProcessingError::BadProposerSlashing
            );
            ensure!(
                proposer_slashing.proposal_data_1.shard == proposer_slashing.proposal_data_2.shard,
                BlockProcessingError::BadProposerSlashing
            );
            ensure!(
                proposer_slashing.proposal_data_1.block_root
                    != proposer_slashing.proposal_data_2.block_root,
                BlockProcessingError::BadProposerSlashing
            );
            ensure!(
                proposer.penalized_slot > self.slot,
                BlockProcessingError::BadProposerSlashing
            );
            ensure!(
                bls_verify(
                    &proposer.pubkey,
                    &proposer_slashing.proposal_data_1.hash_tree_root(),
                    &proposer_slashing.proposal_signature_1,
                    get_domain(
                        &self.fork_data,
                        proposer_slashing.proposal_data_1.slot,
                        DOMAIN_PROPOSAL
                    )
                ),
                BlockProcessingError::BadProposerSlashing
            );
            ensure!(
                bls_verify(
                    &proposer.pubkey,
                    &proposer_slashing.proposal_data_2.hash_tree_root(),
                    &proposer_slashing.proposal_signature_2,
                    get_domain(
                        &self.fork_data,
                        proposer_slashing.proposal_data_2.slot,
                        DOMAIN_PROPOSAL
                    )
                ),
                BlockProcessingError::BadProposerSlashing
            );
            penalize_validator(&self, proposer_slashing.proposer_index as usize);
        }

        /*
         * Attestations
         */
        ensure!(
            block.body.attestations.len() as u64 <= spec.max_attestations,
            BlockProcessingError::MaxAttestationsExceeded
        );

        for attestation in &block.body.attestations {
            self.validate_attestation(attestation, spec)?;

            let pending_attestation = PendingAttestation {
                data: attestation.data.clone(),
                aggregation_bitfield: attestation.aggregation_bitfield.clone(),
                custody_bitfield: attestation.custody_bitfield.clone(),
                slot_included: self.slot,
            };
            self.latest_attestations.push(pending_attestation);
        }

        debug!(
            "{} attestations verified & processed.",
            block.body.attestations.len()
        );

        /*
         * Deposits
         */
        ensure!(
            block.body.deposits.len() as u64 <= spec.max_deposits,
            BlockProcessingError::MaxDepositsExceeded
        );

        // TODO: process deposits.

        /*
         * Exits
         */

        ensure!(
            block.body.exits.len() as u64 <= spec.max_exits,
            BlockProcessingError::MaxExitsExceeded
        );

        for exit in &block.body.exits {
            let validator = self
                .validator_registry
                .get(exit.validator_index as usize)
                .ok_or(BlockProcessingError::BadExit)?;
            ensure!(
                validator.exit_slot > self.slot + spec.entry_exit_delay,
                BlockProcessingError::BadExit
            );
            ensure!(self.slot >= exit.slot, BlockProcessingError::BadExit);
            let exit_message = {
                let exit_struct = Exit {
                    slot: exit.slot,
                    validator_index: exit.validator_index,
                    signature: spec.empty_signature.clone(),
                };
                exit_struct.hash_tree_root()
            };
            ensure!(
                bls_verify(
                    &validator.pubkey,
                    &exit_message,
                    &exit.signature,
                    get_domain(&self.fork_data, exit.slot, DOMAIN_EXIT)
                ),
                BlockProcessingError::BadProposerSlashing
            );
            initiate_validator_exit(&self, exit.validator_index);
        }

        /*
         * Custody
         */
        ensure!(
            block.body.custody_reseeds.is_empty(),
            BlockProcessingError::BadCustodyReseeds
        );
        ensure!(
            block.body.custody_challenges.is_empty(),
            BlockProcessingError::BadCustodyChallenges
        );
        ensure!(
            block.body.custody_responses.is_empty(),
            BlockProcessingError::BadCustodyResponses
        );

        debug!("State transition complete.");

        Ok(())
    }

    pub fn get_shuffling(&self, seed: Hash256, slot: u64, spec: &ChainSpec) -> Vec<Vec<usize>> {
        let slot = slot - (slot % spec.epoch_length);

        let active_validator_indices = get_active_validator_indices(&self.validator_registry, slot);

        let committees_per_slot =
            self.get_committee_count_per_slot(active_validator_indices.len(), spec);

        // TODO: check that Hash256 matches 'int_to_bytes32'.
        let seed = seed ^ Hash256::from(slot);
        let shuffled_active_validator_indices =
            shuffle(&seed, active_validator_indices).expect("Max validator count exceed!");

        shuffled_active_validator_indices
            .honey_badger_split((committees_per_slot * spec.epoch_length) as usize)
            .filter_map(|slice: &[usize]| Some(slice.to_vec()))
            .collect()
    }

    /// Returns the beacon proposer index for the `slot`.
    /// If the state does not contain an index for a beacon proposer at the requested `slot`, then `None` is returned.
    pub fn get_beacon_proposer_index(
        &self,
        slot: u64,
        spec: &ChainSpec,
    ) -> Result<usize, CommitteesError> {
        let committees = self.get_crosslink_committees_at_slot(slot, spec)?;
        committees
            .first()
            .ok_or(CommitteesError::InsufficientNumberOfValidators)
            .and_then(|(first_committee, _)| {
                let index = (slot as usize)
                    .checked_rem(first_committee.len())
                    .ok_or(CommitteesError::InsufficientNumberOfValidators)?;
                // NOTE: next index will not panic as we have already returned if this is the case
                Ok(first_committee[index])
            })
    }

    pub fn per_epoch_processing(&mut self, spec: &ChainSpec) -> Result<(), EpochError> {
        debug!(
            "Starting per-epoch processing on epoch {}...",
            self.current_epoch(spec)
        );
        /*
         * All Validators
         */
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, self.slot);
        let total_balance = self.get_effective_balances(&active_validator_indices[..], spec);

        debug!(
            "{} validators with a total balance of {} wei.",
            active_validator_indices.len(),
            total_balance
        );

        let current_epoch_attestations: Vec<&PendingAttestation> = self
            .latest_attestations
            .par_iter()
            .filter(|a| a.data.slot / spec.epoch_length == self.current_epoch(spec))
            .collect();

        debug!(
            "Current epoch attestations: {}",
            current_epoch_attestations.len()
        );

        /*
         * Validators attesting during the current epoch.
         */
        if self.latest_block_roots.is_empty() {
            return Err(EpochError::NoBlockRoots);
        }

        let current_epoch_boundary_attestations: Vec<&PendingAttestation> =
            current_epoch_attestations
                .par_iter()
                .filter(|a| {
                    match self.get_block_root(self.current_epoch_start_slot(spec), spec) {
                        Some(block_root) => {
                            (a.data.epoch_boundary_root == *block_root)
                                && (a.data.justified_slot == self.justified_slot)
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
            self.get_effective_balances(&current_epoch_boundary_attester_indices[..], spec);

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
                a.data.slot / spec.epoch_length == self.previous_epoch(spec)
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
                .filter(|a| a.data.justified_slot == self.previous_justified_slot)
                .cloned()
                .collect();
            let mut b: Vec<&PendingAttestation> = previous_epoch_attestations
                .iter()
                .filter(|a| a.data.justified_slot == self.previous_justified_slot)
                .cloned()
                .collect();
            a.append(&mut b);
            a
        };

        let previous_epoch_justified_attester_indices = self
            .get_attestation_participants_union(&previous_epoch_justified_attestations[..], spec)?;
        let previous_epoch_justified_attesting_balance =
            self.get_effective_balances(&previous_epoch_justified_attester_indices[..], spec);

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
            self.get_effective_balances(&previous_epoch_boundary_attester_indices[..], spec);

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
            self.get_effective_balances(&previous_epoch_head_attester_indices[..], spec);

        debug!(
            "previous_epoch_head_attester_balance of {} wei.",
            previous_epoch_head_attesting_balance
        );

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
            debug!(">= 2/3 voted for previous epoch boundary");
        }

        // If >= 2/3 of validators voted for the current epoch boundary
        if (3 * current_epoch_boundary_attesting_balance) >= (2 * total_balance) {
            // TODO: check saturating_sub is correct.
            self.justification_bitfield |= 1;
            self.justified_slot = self.slot.saturating_sub(1 * spec.epoch_length);
            debug!(">= 2/3 voted for current epoch boundary");
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

        debug!(
            "Finalized slot {}, justified slot {}.",
            self.finalized_slot, self.justified_slot
        );

        /*
         * Crosslinks
         */

        // Cached for later lookups.
        let mut winning_root_for_shards: HashMap<u64, Result<WinningRoot, WinningRootError>> =
            HashMap::new();

        // for slot in self.slot.saturating_sub(2 * spec.epoch_length)..self.slot {
        for slot in self.get_previous_epoch_boundaries(spec) {
            let crosslink_committees_at_slot = self.get_crosslink_committees_at_slot(slot, spec)?;

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
                        self.get_effective_balances(&crosslink_committee[..], spec);

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
            return Err(EpochError::BaseRewardQuotientIsZero);
        }

        /*
         * Justification and finalization
         */
        let epochs_since_finality =
            self.slot.saturating_sub(self.finalized_slot) / spec.epoch_length;

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
                .map_err(|_| EpochError::UnableToDetermineProducer)?;
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
        for slot in self.get_previous_epoch_boundaries(spec) {
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
        self.previous_epoch_calculation_slot = self.current_epoch_calculation_slot;
        self.previous_epoch_start_shard = self.current_epoch_start_shard;
        self.previous_epoch_seed = self.current_epoch_seed;

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
            self.current_epoch_seed = self.get_randao_mix(
                self.current_epoch_calculation_slot
                    .saturating_sub(spec.seed_lookahead),
                spec,
            );
        } else {
            let epochs_since_last_registry_change =
                (self.slot - self.validator_registry_update_slot) / spec.epoch_length;
            if epochs_since_last_registry_change.is_power_of_two() {
                self.current_epoch_calculation_slot = self.slot;
                self.current_epoch_seed = self.get_randao_mix(
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
            .filter(|a| a.data.slot / spec.epoch_length >= self.current_epoch(spec))
            .cloned()
            .collect();

        debug!("Epoch transition complete.");

        Ok(())
    }

    fn process_penalties_and_exits(&mut self, spec: &ChainSpec) {
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, self.slot);
        let total_balance = self.get_effective_balances(&active_validator_indices[..], spec);

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
        let total_balance = self.get_effective_balances(&active_validator_indices[..], spec);

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

    fn inclusion_distance(
        &self,
        attestations: &[&PendingAttestation],
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<u64, InclusionError> {
        let attestation =
            self.earliest_included_attestation(attestations, validator_index, spec)?;
        Ok(attestation
            .slot_included
            .saturating_sub(attestation.data.slot))
    }

    fn inclusion_slot(
        &self,
        attestations: &[&PendingAttestation],
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<u64, InclusionError> {
        let attestation =
            self.earliest_included_attestation(attestations, validator_index, spec)?;
        Ok(attestation.slot_included)
    }

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
            if participants
                .iter()
                .find(|i| **i == validator_index)
                .is_some()
            {
                included_attestations.push(i);
            }
        }

        let earliest_attestation_index = included_attestations
            .iter()
            .min_by_key(|i| attestations[**i].slot_included)
            .ok_or_else(|| InclusionError::NoIncludedAttestations)?;
        Ok(attestations[*earliest_attestation_index].clone())
    }

    fn base_reward(
        &self,
        validator_index: usize,
        base_reward_quotient: u64,
        spec: &ChainSpec,
    ) -> u64 {
        self.get_effective_balance(validator_index, spec) / base_reward_quotient / 5
    }

    pub fn get_effective_balances(&self, validator_indices: &[usize], spec: &ChainSpec) -> u64 {
        validator_indices
            .iter()
            .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec))
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

    pub(crate) fn winning_root(
        &self,
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
            >>(
                vec![],
                |mut acc, a| {
                    if (a.data.shard == shard) && (a.data.shard_block_root == *shard_block_root) {
                        acc.append(&mut self.get_attestation_participants(
                            &a.data,
                            &a.aggregation_bitfield,
                            spec,
                        )?);
                    }
                    Ok(acc)
                },
            )?;

            let total_balance: u64 = attesting_validator_indices
                .iter()
                .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

            let total_attesting_balance: u64 = attesting_validator_indices
                .iter()
                .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec));

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

    // TODO: analyse for efficiency improvments. This implementation is naive.
    pub fn get_attestation_participants(
        &self,
        attestation_data: &AttestationData,
        aggregation_bitfield: &Bitfield,
        spec: &ChainSpec,
    ) -> Result<Vec<usize>, AttestationParticipantsError> {
        let crosslink_committees =
            self.get_crosslink_committees_at_slot(attestation_data.slot, spec)?;

        let committee_index: usize = crosslink_committees
            .iter()
            .position(|(_committee, shard)| *shard == attestation_data.shard)
            .ok_or_else(|| AttestationParticipantsError::NoCommitteeForShard)?;
        let (crosslink_committee, _shard) = &crosslink_committees[committee_index];

        /*
         * TODO: that bitfield length is valid.
         *
         */

        let mut participants = vec![];
        for (i, validator_index) in crosslink_committee.iter().enumerate() {
            if aggregation_bitfield.get(i).unwrap() {
                participants.push(*validator_index);
            }
        }
        Ok(participants)
    }

    pub fn validate_attestation(
        &self,
        attestation: &Attestation,
        spec: &ChainSpec,
    ) -> Result<(), AttestationValidationError> {
        self.validate_attestation_signature_optional(attestation, spec, true)
    }

    pub fn validate_attestation_without_signature(
        &self,
        attestation: &Attestation,
        spec: &ChainSpec,
    ) -> Result<(), AttestationValidationError> {
        self.validate_attestation_signature_optional(attestation, spec, false)
    }

    fn validate_attestation_signature_optional(
        &self,
        attestation: &Attestation,
        spec: &ChainSpec,
        verify_signature: bool,
    ) -> Result<(), AttestationValidationError> {
        ensure!(
            attestation.data.slot + spec.min_attestation_inclusion_delay <= self.slot,
            AttestationValidationError::IncludedTooEarly
        );
        ensure!(
            attestation.data.slot + spec.epoch_length >= self.slot,
            AttestationValidationError::IncludedTooLate
        );
        if attestation.data.slot >= self.current_epoch_start_slot(spec) {
            ensure!(
                attestation.data.justified_slot == self.justified_slot,
                AttestationValidationError::WrongJustifiedSlot
            );
        } else {
            ensure!(
                attestation.data.justified_slot == self.previous_justified_slot,
                AttestationValidationError::WrongJustifiedSlot
            );
        }
        ensure!(
            attestation.data.justified_block_root
                == *self
                    .get_block_root(attestation.data.justified_slot, &spec)
                    .ok_or(AttestationValidationError::NoBlockRoot)?,
            AttestationValidationError::WrongJustifiedRoot
        );
        ensure!(
            (attestation.data.latest_crosslink_root
                == self.latest_crosslinks[attestation.data.shard as usize].shard_block_root)
                || (attestation.data.shard_block_root
                    == self.latest_crosslinks[attestation.data.shard as usize].shard_block_root),
            AttestationValidationError::BadLatestCrosslinkRoot
        );
        if verify_signature {
            let participants = self.get_attestation_participants(
                &attestation.data,
                &attestation.aggregation_bitfield,
                spec,
            )?;
            let mut group_public_key = AggregatePublicKey::new();
            for participant in participants {
                group_public_key.add(
                    self.validator_registry[participant as usize]
                        .pubkey
                        .as_raw(),
                )
            }
            ensure!(
                bls_verify_aggregate(
                    &group_public_key,
                    &attestation.signable_message(PHASE_0_CUSTODY_BIT),
                    &attestation.aggregate_signature,
                    get_domain(&self.fork_data, attestation.data.slot, DOMAIN_ATTESTATION)
                ),
                AttestationValidationError::BadSignature
            );
        }
        ensure!(
            attestation.data.shard_block_root == spec.zero_hash,
            AttestationValidationError::ShardBlockRootNotZero
        );
        Ok(())
    }
}

fn merkle_root(_input: &[Hash256]) -> Hash256 {
    Hash256::zero()
}

fn initiate_validator_exit(_state: &BeaconState, _index: u32) {
    // TODO: stubbed out.
}

fn penalize_validator(_state: &BeaconState, _proposer_index: usize) {
    // TODO: stubbed out.
}

fn get_domain(_fork: &Fork, _slot: u64, _domain_type: u64) -> u64 {
    // TODO: stubbed out.
    0
}

fn bls_verify(pubkey: &PublicKey, message: &[u8], signature: &Signature, _domain: u64) -> bool {
    // TODO: add domain
    signature.verify(message, pubkey)
}

impl From<AttestationParticipantsError> for AttestationValidationError {
    fn from(e: AttestationParticipantsError) -> AttestationValidationError {
        AttestationValidationError::AttestationParticipantsError(e)
    }
}

impl From<AttestationParticipantsError> for WinningRootError {
    fn from(e: AttestationParticipantsError) -> WinningRootError {
        WinningRootError::AttestationParticipantsError(e)
    }
}

impl From<CommitteesError> for AttestationParticipantsError {
    fn from(e: CommitteesError) -> AttestationParticipantsError {
        AttestationParticipantsError::CommitteesError(e)
    }
}

impl From<AttestationValidationError> for BlockProcessingError {
    fn from(e: AttestationValidationError) -> BlockProcessingError {
        BlockProcessingError::InvalidAttestation(e)
    }
}

impl From<CommitteesError> for BlockProcessingError {
    fn from(e: CommitteesError) -> BlockProcessingError {
        BlockProcessingError::CommitteesError(e)
    }
}

impl From<SlotProcessingError> for BlockProcessingError {
    fn from(e: SlotProcessingError) -> BlockProcessingError {
        BlockProcessingError::SlotProcessingError(e)
    }
}

impl From<CommitteesError> for SlotProcessingError {
    fn from(e: CommitteesError) -> SlotProcessingError {
        SlotProcessingError::CommitteesError(e)
    }
}

impl From<EpochError> for SlotProcessingError {
    fn from(e: EpochError) -> SlotProcessingError {
        SlotProcessingError::EpochProcessingError(e)
    }
}

impl From<AttestationParticipantsError> for InclusionError {
    fn from(e: AttestationParticipantsError) -> InclusionError {
        InclusionError::AttestationParticipantsError(e)
    }
}

impl From<InclusionError> for EpochError {
    fn from(e: InclusionError) -> EpochError {
        EpochError::InclusionError(e)
    }
}

impl From<CommitteesError> for EpochError {
    fn from(e: CommitteesError) -> EpochError {
        EpochError::CommitteesError(e)
    }
}

impl From<AttestationParticipantsError> for EpochError {
    fn from(e: AttestationParticipantsError) -> EpochError {
        EpochError::AttestationParticipantsError(e)
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
        s.append(&self.fork_data);
        s.append(&self.validator_registry);
        s.append(&self.validator_balances);
        s.append(&self.validator_registry_update_slot);
        s.append(&self.validator_registry_exit_count);
        s.append(&self.validator_registry_delta_chain_tip);
        s.append(&self.latest_randao_mixes);
        s.append(&self.latest_vdf_outputs);
        s.append(&self.previous_epoch_start_shard);
        s.append(&self.current_epoch_start_shard);
        s.append(&self.previous_epoch_calculation_slot);
        s.append(&self.current_epoch_calculation_slot);
        s.append(&self.previous_epoch_seed);
        s.append(&self.current_epoch_seed);
        s.append(&self.custody_challenges);
        s.append(&self.previous_justified_slot);
        s.append(&self.justified_slot);
        s.append(&self.justification_bitfield);
        s.append(&self.finalized_slot);
        s.append(&self.latest_crosslinks);
        s.append(&self.latest_block_roots);
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
        let (fork_data, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_balances, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_update_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_exit_count, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_delta_chain_tip, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_randao_mixes, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_vdf_outputs, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_epoch_start_shard, i) = <_>::ssz_decode(bytes, i)?;
        let (current_epoch_start_shard, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_epoch_calculation_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (current_epoch_calculation_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_epoch_seed, i) = <_>::ssz_decode(bytes, i)?;
        let (current_epoch_seed, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_challenges, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_justified_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (justified_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (justification_bitfield, i) = <_>::ssz_decode(bytes, i)?;
        let (finalized_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_crosslinks, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_block_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_penalized_balances, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_attestations, i) = <_>::ssz_decode(bytes, i)?;
        let (batched_block_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_eth1_data, i) = <_>::ssz_decode(bytes, i)?;
        let (eth1_data_votes, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                genesis_time,
                fork_data,
                validator_registry,
                validator_balances,
                validator_registry_update_slot,
                validator_registry_exit_count,
                validator_registry_delta_chain_tip,
                latest_randao_mixes,
                latest_vdf_outputs,
                previous_epoch_start_shard,
                current_epoch_start_shard,
                previous_epoch_calculation_slot,
                current_epoch_calculation_slot,
                previous_epoch_seed,
                current_epoch_seed,
                custody_challenges,
                previous_justified_slot,
                justified_slot,
                justification_bitfield,
                finalized_slot,
                latest_crosslinks,
                latest_block_roots,
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
        result.append(&mut self.fork_data.hash_tree_root());
        result.append(&mut self.validator_registry.hash_tree_root());
        result.append(&mut self.validator_balances.hash_tree_root());
        result.append(&mut self.validator_registry_update_slot.hash_tree_root());
        result.append(&mut self.validator_registry_exit_count.hash_tree_root());
        result.append(&mut self.validator_registry_delta_chain_tip.hash_tree_root());
        result.append(&mut self.latest_randao_mixes.hash_tree_root());
        result.append(&mut self.latest_vdf_outputs.hash_tree_root());
        result.append(&mut self.previous_epoch_start_shard.hash_tree_root());
        result.append(&mut self.current_epoch_start_shard.hash_tree_root());
        result.append(&mut self.previous_epoch_calculation_slot.hash_tree_root());
        result.append(&mut self.current_epoch_calculation_slot.hash_tree_root());
        result.append(&mut self.previous_epoch_seed.hash_tree_root());
        result.append(&mut self.current_epoch_seed.hash_tree_root());
        result.append(&mut self.custody_challenges.hash_tree_root());
        result.append(&mut self.previous_justified_slot.hash_tree_root());
        result.append(&mut self.justified_slot.hash_tree_root());
        result.append(&mut self.justification_bitfield.hash_tree_root());
        result.append(&mut self.finalized_slot.hash_tree_root());
        result.append(&mut self.latest_crosslinks.hash_tree_root());
        result.append(&mut self.latest_block_roots.hash_tree_root());
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
            fork_data: <_>::random_for_test(rng),
            validator_registry: <_>::random_for_test(rng),
            validator_balances: <_>::random_for_test(rng),
            validator_registry_update_slot: <_>::random_for_test(rng),
            validator_registry_exit_count: <_>::random_for_test(rng),
            validator_registry_delta_chain_tip: <_>::random_for_test(rng),
            latest_randao_mixes: <_>::random_for_test(rng),
            latest_vdf_outputs: <_>::random_for_test(rng),
            previous_epoch_start_shard: <_>::random_for_test(rng),
            current_epoch_start_shard: <_>::random_for_test(rng),
            previous_epoch_calculation_slot: <_>::random_for_test(rng),
            current_epoch_calculation_slot: <_>::random_for_test(rng),
            previous_epoch_seed: <_>::random_for_test(rng),
            current_epoch_seed: <_>::random_for_test(rng),
            custody_challenges: <_>::random_for_test(rng),
            previous_justified_slot: <_>::random_for_test(rng),
            justified_slot: <_>::random_for_test(rng),
            justification_bitfield: <_>::random_for_test(rng),
            finalized_slot: <_>::random_for_test(rng),
            latest_crosslinks: <_>::random_for_test(rng),
            latest_block_roots: <_>::random_for_test(rng),
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
