mod attestation;
pub mod attestation_storage;
mod attester_slashing;
mod bls_to_execution_changes;
mod max_cover;
mod metrics;
mod persistence;
mod reward_cache;
mod sync_aggregate_id;

pub use crate::bls_to_execution_changes::ReceivedPreCapella;
pub use attestation::{AttMaxCover, PROPOSER_REWARD_DENOMINATOR, earliest_attestation_validators};
pub use attestation_storage::{CompactAttestationRef, SplitAttestation};
pub use max_cover::MaxCover;
pub use persistence::{
    PersistedOperationPool, PersistedOperationPoolV15, PersistedOperationPoolV20,
};
pub use reward_cache::RewardCache;
use state_processing::epoch_cache::is_epoch_cache_initialized;
use types::EpochCacheError;

use crate::attestation_storage::{AttestationMap, CheckpointKey};
use crate::bls_to_execution_changes::BlsToExecutionChanges;
use crate::sync_aggregate_id::SyncAggregateId;
use attester_slashing::AttesterSlashingMaxCover;
use bls::AggregateSignature;
use max_cover::maximum_cover;
use parking_lot::{RwLock, RwLockWriteGuard};
use rand::rng;
use rand::seq::SliceRandom;
use ssz::BitVector;
use state_processing::per_block_processing::errors::AttestationValidationError;
use state_processing::per_block_processing::{
    VerifySignatures, get_slashable_indices_modular, verify_exit,
};
use state_processing::{SigVerifiedOp, VerifyOperation};
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::marker::PhantomData;
use std::ptr;
use typenum::Unsigned;
use types::{
    AbstractExecPayload, Attestation, AttestationData, AttesterSlashing, BeaconState,
    BeaconStateError, ChainSpec, Epoch, EthSpec, Hash256, PayloadAttestation,
    PayloadAttestationData, PayloadAttestationMessage, ProposerSlashing, SignedBeaconBlock,
    SignedBlsToExecutionChange, SignedVoluntaryExit, Slot, SyncAggregate, SyncAggregateError,
    SyncCommitteeContribution, Validator,
};

type SyncContributions<E> = RwLock<HashMap<SyncAggregateId, Vec<SyncCommitteeContribution<E>>>>;

#[derive(Default, Debug)]
pub struct OperationPool<E: EthSpec + Default> {
    /// Map from attestation ID (see below) to vectors of attestations.
    pub attestations: RwLock<AttestationMap<E>>,
    /// Map from sync aggregate ID to the best `SyncCommitteeContribution`s seen for that ID.
    sync_contributions: SyncContributions<E>,
    /// Set of attester slashings, and the fork version they were verified against.
    attester_slashings: RwLock<HashSet<SigVerifiedOp<AttesterSlashing<E>, E>>>,
    /// Map from proposer index to slashing.
    proposer_slashings: RwLock<HashMap<u64, SigVerifiedOp<ProposerSlashing, E>>>,
    /// Map from exiting validator to their exit data.
    voluntary_exits: RwLock<HashMap<u64, SigVerifiedOp<SignedVoluntaryExit, E>>>,
    /// Map from credential changing validator to their position in the queue.
    bls_to_execution_changes: RwLock<BlsToExecutionChanges<E>>,
    /// Map from payload attestation data to individual messages for aggregation at block production.
    payload_attestation_messages:
        RwLock<HashMap<PayloadAttestationData, Vec<PayloadAttestationMessage>>>,
    /// Reward cache for accelerating attestation packing.
    reward_cache: RwLock<RewardCache>,
    _phantom: PhantomData<E>,
}

#[derive(Debug, PartialEq)]
pub enum OpPoolError {
    GetAttestationsTotalBalanceError(BeaconStateError),
    GetBlockRootError(BeaconStateError),
    SyncAggregateError(SyncAggregateError),
    RewardCacheUpdatePrevEpoch(BeaconStateError),
    RewardCacheUpdateCurrEpoch(BeaconStateError),
    RewardCacheGetBlockRoot(BeaconStateError),
    RewardCacheWrongEpoch,
    RewardCacheValidatorUnknown(BeaconStateError),
    RewardCacheOutOfBounds,
    IncorrectOpPoolVariant,
    EpochCacheNotInitialized,
    EpochCacheError(EpochCacheError),
    GetPtcError(BeaconStateError),
    PayloadAttestationBitError,
}

#[derive(Default)]
pub struct AttestationStats {
    /// Total number of attestations for all committeees/indices/votes.
    pub num_attestations: usize,
    /// Number of unique `AttestationData` attested to.
    pub num_attestation_data: usize,
    /// Maximum number of aggregates for a single `AttestationData`.
    pub max_aggregates_per_data: usize,
}

impl From<SyncAggregateError> for OpPoolError {
    fn from(e: SyncAggregateError) -> Self {
        OpPoolError::SyncAggregateError(e)
    }
}

impl<E: EthSpec> OperationPool<E> {
    /// Create a new operation pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a sync contribution into the pool. We don't aggregate these contributions until they
    /// are retrieved from the pool.
    ///
    /// ## Note
    ///
    /// This function assumes the given `contribution` is valid.
    pub fn insert_sync_contribution(
        &self,
        contribution: SyncCommitteeContribution<E>,
    ) -> Result<(), OpPoolError> {
        let aggregate_id = SyncAggregateId::new(contribution.slot, contribution.beacon_block_root);
        let mut contributions = self.sync_contributions.write();

        match contributions.entry(aggregate_id) {
            Entry::Vacant(entry) => {
                // If no contributions exist for the key, insert the given contribution.
                entry.insert(vec![contribution]);
            }
            Entry::Occupied(mut entry) => {
                // If contributions exists for this key, check whether there exists a contribution
                // with a matching `subcommittee_index`. If one exists, check whether the new or
                // old contribution has more aggregation bits set. If the new one does, add it to the
                // pool in place of the old one.
                let existing_contributions = entry.get_mut();
                match existing_contributions
                    .iter_mut()
                    .find(|existing_contribution| {
                        existing_contribution.subcommittee_index == contribution.subcommittee_index
                    }) {
                    Some(existing_contribution) => {
                        // Only need to replace the contribution if the new contribution has more
                        // bits set.
                        if existing_contribution.aggregation_bits.num_set_bits()
                            < contribution.aggregation_bits.num_set_bits()
                        {
                            *existing_contribution = contribution;
                        }
                    }
                    None => {
                        // If there has been no previous sync contribution for this subcommittee index,
                        // add it to the pool.
                        existing_contributions.push(contribution);
                    }
                }
            }
        };
        Ok(())
    }

    /// Calculate the `SyncAggregate` from the sync contributions that exist in the pool for the
    /// slot previous to the slot associated with `state`. Return the calculated `SyncAggregate` if
    /// contributions exist at this slot, or else `None`.
    pub fn get_sync_aggregate(
        &self,
        state: &BeaconState<E>,
    ) -> Result<Option<SyncAggregate<E>>, OpPoolError> {
        // Sync aggregates are formed from the contributions from the previous slot.
        let slot = state.slot().saturating_sub(1u64);
        let block_root = *state
            .get_block_root(slot)
            .map_err(OpPoolError::GetBlockRootError)?;
        let id = SyncAggregateId::new(slot, block_root);
        self.sync_contributions
            .read()
            .get(&id)
            .map(|contributions| SyncAggregate::from_contributions(contributions))
            .transpose()
            .map_err(|e| e.into())
    }

    /// Total number of sync contributions in the pool.
    pub fn num_sync_contributions(&self) -> usize {
        self.sync_contributions
            .read()
            .values()
            .map(|contributions| contributions.len())
            .sum()
    }

    /// Remove sync contributions which are too old to be included in a block.
    pub fn prune_sync_contributions(&self, current_slot: Slot) {
        // Prune sync contributions that are from before the previous slot.
        self.sync_contributions.write().retain(|_, contributions| {
            // All the contributions in this bucket have the same data, so we only need to
            // check the first one.
            contributions.first().is_some_and(|contribution| {
                current_slot <= contribution.slot.saturating_add(Slot::new(1))
            })
        });
    }

    /// Insert a validated `PayloadAttestationMessage` into the pool.
    pub fn insert_payload_attestation_message(
        &self,
        message: PayloadAttestationMessage,
    ) -> Result<(), OpPoolError> {
        let mut messages = self.payload_attestation_messages.write();
        let entry = messages.entry(message.data.clone()).or_default();
        if !entry
            .iter()
            .any(|m| m.validator_index == message.validator_index)
        {
            entry.push(message);
        }
        Ok(())
    }

    /// Build `PayloadAttestation`s from stored messages for block production.
    ///
    /// `parent_block_root` is the root of the parent block (the block PTC members attested to).
    /// Returns one `PayloadAttestation` per distinct `PayloadAttestationData`. With two boolean
    /// fields this yields at most 4, capped to `MaxPayloadAttestations`.
    pub fn get_payload_attestations(
        &self,
        state: &BeaconState<E>,
        parent_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<Vec<PayloadAttestation<E>>, OpPoolError> {
        let target_slot = state.slot().saturating_sub(1u64);

        let ptc = state
            .get_ptc(target_slot, spec)
            .map_err(OpPoolError::GetPtcError)?;

        let messages = self.payload_attestation_messages.read();
        let mut result = Vec::new();

        for (data, msgs) in messages.iter() {
            if data.slot != target_slot || data.beacon_block_root != parent_block_root {
                continue;
            }

            let mut aggregation_bits = BitVector::new();
            let mut aggregate_sig = AggregateSignature::infinity();

            for msg in msgs {
                if let Some(pos) = ptc
                    .0
                    .iter()
                    .position(|&idx| idx == msg.validator_index as usize)
                    && !aggregation_bits.get(pos).unwrap_or(false)
                {
                    aggregation_bits
                        .set(pos, true)
                        .map_err(|_| OpPoolError::PayloadAttestationBitError)?;
                    aggregate_sig.add_assign(&msg.signature);
                }
            }

            if aggregation_bits.num_set_bits() > 0 {
                result.push(PayloadAttestation {
                    aggregation_bits,
                    data: data.clone(),
                    signature: aggregate_sig,
                });
            }
        }

        // Prefer most participation and cap by `max_payload_attestations`
        result.sort_by(|a, b| {
            b.aggregation_bits
                .num_set_bits()
                .cmp(&a.aggregation_bits.num_set_bits())
        });
        result.truncate(E::max_payload_attestations());

        Ok(result)
    }

    /// Remove payload attestation messages that are too old for block inclusion.
    pub fn prune_payload_attestation_messages(&self, current_slot: Slot) {
        self.payload_attestation_messages
            .write()
            .retain(|data, _| current_slot <= data.slot.saturating_add(Slot::new(1)));
    }

    /// Total number of payload attestation messages in the pool.
    pub fn num_payload_attestation_messages(&self) -> usize {
        self.payload_attestation_messages
            .read()
            .values()
            .map(|msgs| msgs.len())
            .sum()
    }

    /// Insert an attestation into the pool, aggregating it with existing attestations if possible.
    ///
    /// ## Note
    ///
    /// This function assumes the given `attestation` is valid.
    pub fn insert_attestation(
        &self,
        attestation: Attestation<E>,
        attesting_indices: Vec<u64>,
    ) -> Result<(), AttestationValidationError> {
        self.attestations
            .write()
            .insert(attestation, attesting_indices);
        Ok(())
    }

    /// Total number of attestations in the pool, including attestations for the same data.
    pub fn num_attestations(&self) -> usize {
        self.attestation_stats().num_attestations
    }

    pub fn attestation_stats(&self) -> AttestationStats {
        self.attestations.read().stats()
    }

    /// Return all valid attestations for the given epoch, for use in max cover.
    #[allow(clippy::too_many_arguments)]
    fn get_valid_attestations_for_epoch<'a>(
        &'a self,
        checkpoint_key: &'a CheckpointKey,
        all_attestations: &'a AttestationMap<E>,
        state: &'a BeaconState<E>,
        reward_cache: &'a RewardCache,
        total_active_balance: u64,
        validity_filter: impl FnMut(&CompactAttestationRef<'a, E>) -> bool + Send,
        spec: &'a ChainSpec,
    ) -> impl Iterator<Item = AttMaxCover<'a, E>> + Send {
        all_attestations
            .get_attestations(checkpoint_key)
            .filter(|att| {
                att.data.slot + spec.min_attestation_inclusion_delay <= state.slot()
                    && state.slot() <= att.data.slot + E::slots_per_epoch()
            })
            .filter(validity_filter)
            .filter_map(move |att| {
                AttMaxCover::new(att, state, reward_cache, total_active_balance, spec)
            })
    }

    /// Get a list of attestations for inclusion in a block.
    ///
    /// The `validity_filter` is a closure that provides extra filtering of the attestations
    /// before an approximately optimal bundle is constructed. We use it to provide access
    /// to the fork choice data from the `BeaconChain` struct that doesn't logically belong
    /// in the operation pool.
    pub fn get_attestations(
        &self,
        state: &BeaconState<E>,
        prev_epoch_validity_filter: impl for<'a> FnMut(&CompactAttestationRef<'a, E>) -> bool + Send,
        curr_epoch_validity_filter: impl for<'a> FnMut(&CompactAttestationRef<'a, E>) -> bool + Send,
        spec: &ChainSpec,
    ) -> Result<Vec<Attestation<E>>, OpPoolError> {
        let fork_name = state.fork_name_unchecked();
        if !matches!(state, BeaconState::Base(_)) {
            // Epoch cache must be initialized to fetch base reward values in the max cover `score`
            // function. Currently max cover ignores items on errors. If epoch cache is not
            // initialized, this function returns an error.
            if !is_epoch_cache_initialized(state).map_err(OpPoolError::EpochCacheError)? {
                return Err(OpPoolError::EpochCacheNotInitialized);
            }
        }

        // Attestations for the current fork, which may be from the current or previous epoch.
        let (prev_epoch_key, curr_epoch_key) = CheckpointKey::keys_for_state(state);
        let total_active_balance = state
            .get_total_active_balance()
            .map_err(OpPoolError::GetAttestationsTotalBalanceError)?;

        // Update the reward cache.
        let reward_timer = metrics::start_timer(&metrics::BUILD_REWARD_CACHE_TIME);
        let mut reward_cache = self.reward_cache.write();
        reward_cache.update(state)?;
        let reward_cache = RwLockWriteGuard::downgrade(reward_cache);
        drop(reward_timer);

        // Split attestations for the previous & current epochs, so that we
        // can optimise them individually in parallel.
        let mut num_prev_valid = 0_i64;
        let mut num_curr_valid = 0_i64;

        // TODO(electra): Work out how to do this more elegantly. This is a bit of a hack.
        let mut all_attestations = self.attestations.write();

        if fork_name.electra_enabled() {
            all_attestations.aggregate_across_committees(prev_epoch_key);
            all_attestations.aggregate_across_committees(curr_epoch_key);
        }

        let all_attestations = parking_lot::RwLockWriteGuard::downgrade(all_attestations);

        let prev_epoch_att = self
            .get_valid_attestations_for_epoch(
                &prev_epoch_key,
                &*all_attestations,
                state,
                &reward_cache,
                total_active_balance,
                prev_epoch_validity_filter,
                spec,
            )
            .inspect(|_| num_prev_valid += 1);
        let curr_epoch_att = self
            .get_valid_attestations_for_epoch(
                &curr_epoch_key,
                &*all_attestations,
                state,
                &reward_cache,
                total_active_balance,
                curr_epoch_validity_filter,
                spec,
            )
            .inspect(|_| num_curr_valid += 1);

        let curr_epoch_limit = if fork_name.electra_enabled() {
            E::MaxAttestationsElectra::to_usize()
        } else {
            E::MaxAttestations::to_usize()
        };
        let prev_epoch_limit = if let BeaconState::Base(base_state) = state {
            std::cmp::min(
                E::MaxPendingAttestations::to_usize()
                    .saturating_sub(base_state.previous_epoch_attestations.len()),
                E::MaxAttestations::to_usize(),
            )
        } else {
            curr_epoch_limit
        };

        let (prev_cover, curr_cover) = rayon::join(
            move || {
                let _timer = metrics::start_timer(&metrics::ATTESTATION_PREV_EPOCH_PACKING_TIME);
                // If we're in the genesis epoch, just use the current epoch attestations.
                if prev_epoch_key == curr_epoch_key {
                    vec![]
                } else {
                    maximum_cover(prev_epoch_att, prev_epoch_limit, "prev_epoch_attestations")
                }
            },
            move || {
                let _timer = metrics::start_timer(&metrics::ATTESTATION_CURR_EPOCH_PACKING_TIME);
                maximum_cover(curr_epoch_att, curr_epoch_limit, "curr_epoch_attestations")
            },
        );

        metrics::set_gauge(&metrics::NUM_PREV_EPOCH_ATTESTATIONS, num_prev_valid);
        metrics::set_gauge(&metrics::NUM_CURR_EPOCH_ATTESTATIONS, num_curr_valid);

        Ok(max_cover::merge_solutions(
            curr_cover,
            prev_cover,
            curr_epoch_limit,
        ))
    }

    /// Remove attestations which are too old to be included in a block.
    pub fn prune_attestations(&self, current_epoch: Epoch) {
        self.attestations.write().prune(current_epoch);
    }

    /// Insert a proposer slashing into the pool.
    pub fn insert_proposer_slashing(
        &self,
        verified_proposer_slashing: SigVerifiedOp<ProposerSlashing, E>,
    ) {
        self.proposer_slashings.write().insert(
            verified_proposer_slashing.as_inner().proposer_index(),
            verified_proposer_slashing,
        );
    }

    /// Insert an attester slashing into the pool.
    pub fn insert_attester_slashing(
        &self,
        verified_slashing: SigVerifiedOp<AttesterSlashing<E>, E>,
    ) {
        self.attester_slashings.write().insert(verified_slashing);
    }

    /// Get proposer and attester slashings for inclusion in a block.
    ///
    /// This function computes both types of slashings together, because
    /// attester slashings may be invalidated by proposer slashings included
    /// earlier in the block.
    pub fn get_slashings_and_exits(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> (
        Vec<ProposerSlashing>,
        Vec<AttesterSlashing<E>>,
        Vec<SignedVoluntaryExit>,
    ) {
        let proposer_slashings = filter_limit_operations(
            self.proposer_slashings.read().values(),
            |slashing| {
                slashing.signature_is_still_valid(&state.fork())
                    && state
                        .validators()
                        .get(slashing.as_inner().signed_header_1.message.proposer_index as usize)
                        .is_some_and(|validator| !validator.slashed)
            },
            |slashing| slashing.as_inner().clone(),
            E::MaxProposerSlashings::to_usize(),
        );

        // Set of validators to be slashed, so we don't attempt to construct invalid attester
        // slashings.
        let mut to_be_slashed = proposer_slashings
            .iter()
            .map(|s| s.proposer_index())
            .collect();

        let attester_slashings = self.get_attester_slashings(state, &mut to_be_slashed);

        let voluntary_exits = self.get_voluntary_exits(
            state,
            |exit| !to_be_slashed.contains(&exit.message.validator_index),
            spec,
        );

        (proposer_slashings, attester_slashings, voluntary_exits)
    }

    /// Get attester slashings taking into account already slashed validators.
    ///
    /// This function *must* remain private.
    fn get_attester_slashings(
        &self,
        state: &BeaconState<E>,
        to_be_slashed: &mut HashSet<u64>,
    ) -> Vec<AttesterSlashing<E>> {
        let reader = self.attester_slashings.read();

        let relevant_attester_slashings = reader.iter().flat_map(|slashing| {
            if slashing.signature_is_still_valid(&state.fork()) {
                AttesterSlashingMaxCover::new(slashing.as_inner().to_ref(), to_be_slashed, state)
            } else {
                None
            }
        });

        let max_attester_slashings = if state.fork_name_unchecked().electra_enabled() {
            E::max_attester_slashings_electra()
        } else {
            E::MaxAttesterSlashings::to_usize()
        };

        maximum_cover(
            relevant_attester_slashings,
            max_attester_slashings,
            "attester_slashings",
        )
        .into_iter()
        .map(|cover| {
            to_be_slashed.extend(cover.covering_set().keys());
            AttesterSlashingMaxCover::convert_to_object(cover.intermediate())
        })
        .collect()
    }

    /// Prune proposer slashings for validators which are already slashed or exited in the finalized
    /// epoch.
    pub fn prune_proposer_slashings(&self, finalized_state: &BeaconState<E>) {
        prune_validator_hash_map(
            &mut self.proposer_slashings.write(),
            |_, validator| {
                validator.slashed || validator.exit_epoch <= finalized_state.current_epoch()
            },
            finalized_state,
        );
    }

    /// Prune attester slashings for all slashed or withdrawn validators, or attestations on another
    /// fork.
    pub fn prune_attester_slashings(&self, finalized_state: &BeaconState<E>) {
        self.attester_slashings.write().retain(|slashing| {
            // Check that the attestation's signature is still valid wrt the fork version.
            // We might be a bit slower to detect signature staleness by using the finalized state
            // here, but we filter when proposing anyway, so in the worst case we just keep some
            // stuff around until we finalize.
            let signature_ok = slashing.signature_is_still_valid(&finalized_state.fork());
            // Slashings that don't slash any validators can also be dropped.
            let slashing_ok = get_slashable_indices_modular(
                finalized_state,
                slashing.as_inner().to_ref(),
                |_, validator| {
                    // Declare that a validator is still slashable if they have not been slashed in
                    // the finalized state, and have not exited at the finalized epoch.
                    !validator.slashed && validator.exit_epoch > finalized_state.current_epoch()
                },
            )
            .is_ok_and(|indices| !indices.is_empty());

            signature_ok && slashing_ok
        });
    }

    /// Total number of attester slashings in the pool.
    pub fn num_attester_slashings(&self) -> usize {
        self.attester_slashings.read().len()
    }

    /// Total number of proposer slashings in the pool.
    pub fn num_proposer_slashings(&self) -> usize {
        self.proposer_slashings.read().len()
    }

    /// Insert a voluntary exit that has previously been checked elsewhere.
    pub fn insert_voluntary_exit(&self, exit: SigVerifiedOp<SignedVoluntaryExit, E>) {
        self.voluntary_exits
            .write()
            .insert(exit.as_inner().message.validator_index, exit);
    }

    /// Get a list of voluntary exits for inclusion in a block.
    fn get_voluntary_exits<F>(
        &self,
        state: &BeaconState<E>,
        filter: F,
        spec: &ChainSpec,
    ) -> Vec<SignedVoluntaryExit>
    where
        F: Fn(&SignedVoluntaryExit) -> bool,
    {
        filter_limit_operations(
            self.voluntary_exits.read().values(),
            |exit| {
                filter(exit.as_inner())
                    && exit.signature_is_still_valid(&state.fork())
                    && verify_exit(state, None, exit.as_inner(), VerifySignatures::False, spec)
                        .is_ok()
            },
            |exit| exit.as_inner().clone(),
            E::MaxVoluntaryExits::to_usize(),
        )
    }

    /// Prune if validator has already exited in the finalized state.
    pub fn prune_voluntary_exits(&self, finalized_state: &BeaconState<E>, spec: &ChainSpec) {
        prune_validator_hash_map(
            &mut self.voluntary_exits.write(),
            |_, validator| validator.exit_epoch != spec.far_future_epoch,
            finalized_state,
        );
    }

    /// Check if an address change equal to `address_change` is already in the pool.
    ///
    /// Return `None` if no address change for the validator index exists in the pool.
    pub fn bls_to_execution_change_in_pool_equals(
        &self,
        address_change: &SignedBlsToExecutionChange,
    ) -> Option<bool> {
        self.bls_to_execution_changes
            .read()
            .existing_change_equals(address_change)
    }

    /// Insert a BLS to execution change into the pool, *only if* no prior change is known.
    ///
    /// Return `true` if the change was inserted.
    pub fn insert_bls_to_execution_change(
        &self,
        verified_change: SigVerifiedOp<SignedBlsToExecutionChange, E>,
        received_pre_capella: ReceivedPreCapella,
    ) -> bool {
        self.bls_to_execution_changes
            .write()
            .insert(verified_change, received_pre_capella)
    }

    /// Get a list of execution changes for inclusion in a block.
    ///
    /// They're in random `HashMap` order, which isn't exactly fair, but isn't unfair either.
    pub fn get_bls_to_execution_changes(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Vec<SignedBlsToExecutionChange> {
        filter_limit_operations(
            self.bls_to_execution_changes.read().iter_lifo(),
            |address_change| {
                address_change.signature_is_still_valid(&state.fork())
                    && state
                        .get_validator(address_change.as_inner().message.validator_index as usize)
                        .is_ok_and(|validator| !validator.has_execution_withdrawal_credential(spec))
            },
            |address_change| address_change.as_inner().clone(),
            E::MaxBlsToExecutionChanges::to_usize(),
        )
    }

    /// Get a list of execution changes to be broadcast at the Capella fork.
    ///
    /// The list that is returned will be shuffled to help provide a fair
    /// broadcast of messages.
    pub fn get_bls_to_execution_changes_received_pre_capella(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Vec<SignedBlsToExecutionChange> {
        let mut changes = filter_limit_operations(
            self.bls_to_execution_changes
                .read()
                .iter_received_pre_capella(),
            |address_change| {
                address_change.signature_is_still_valid(&state.fork())
                    && state
                        .get_validator(address_change.as_inner().message.validator_index as usize)
                        .is_ok_and(|validator| !validator.has_eth1_withdrawal_credential(spec))
            },
            |address_change| address_change.as_inner().clone(),
            usize::MAX,
        );
        changes.shuffle(&mut rng());
        changes
    }

    /// Removes `broadcasted` validators from the set of validators that should
    /// have their BLS changes broadcast at the Capella fork boundary.
    pub fn register_indices_broadcasted_at_capella(&self, broadcasted: &HashSet<u64>) {
        self.bls_to_execution_changes
            .write()
            .register_indices_broadcasted_at_capella(broadcasted);
    }

    /// Prune BLS to execution changes that have been applied to the state more than 1 block ago.
    pub fn prune_bls_to_execution_changes<Payload: AbstractExecPayload<E>>(
        &self,
        head_block: &SignedBeaconBlock<E, Payload>,
        head_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) {
        self.bls_to_execution_changes
            .write()
            .prune(head_block, head_state, spec)
    }

    /// Prune all types of transactions given the latest head state and head fork.
    pub fn prune_all<Payload: AbstractExecPayload<E>>(
        &self,
        head_block: &SignedBeaconBlock<E, Payload>,
        head_state: &BeaconState<E>,
        finalized_state: &BeaconState<E>,
        current_epoch: Epoch,
        spec: &ChainSpec,
    ) {
        self.prune_attestations(current_epoch);
        self.prune_sync_contributions(head_state.slot());
        self.prune_payload_attestation_messages(head_state.slot());
        self.prune_proposer_slashings(finalized_state);
        self.prune_attester_slashings(finalized_state);
        self.prune_voluntary_exits(finalized_state, spec);
        self.prune_bls_to_execution_changes(head_block, head_state, spec);
    }

    /// Total number of voluntary exits in the pool.
    pub fn num_voluntary_exits(&self) -> usize {
        self.voluntary_exits.read().len()
    }

    /// Returns all known `Attestation` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_attestations(&self) -> Vec<Attestation<E>> {
        self.attestations
            .read()
            .iter()
            .map(|att| att.clone_as_attestation())
            .collect()
    }

    /// Returns all known `Attestation` objects that pass the provided filter.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_filtered_attestations<F>(&self, filter: F) -> Vec<Attestation<E>>
    where
        F: Fn(&AttestationData, HashSet<u64>) -> bool,
    {
        self.attestations
            .read()
            .iter()
            .filter(|att| filter(&att.attestation_data(), att.get_committee_indices_map()))
            .map(|att| att.clone_as_attestation())
            .collect()
    }

    /// Returns all known `AttesterSlashing` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_attester_slashings(&self) -> Vec<AttesterSlashing<E>> {
        self.attester_slashings
            .read()
            .iter()
            .map(|slashing| slashing.as_inner().clone())
            .collect()
    }

    /// Returns all known `ProposerSlashing` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_proposer_slashings(&self) -> Vec<ProposerSlashing> {
        self.proposer_slashings
            .read()
            .values()
            .map(|slashing| slashing.as_inner().clone())
            .collect()
    }

    /// Returns all known `SignedVoluntaryExit` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_voluntary_exits(&self) -> Vec<SignedVoluntaryExit> {
        self.voluntary_exits
            .read()
            .values()
            .map(|exit| exit.as_inner().clone())
            .collect()
    }

    /// Returns all known `SignedBlsToExecutionChange` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_bls_to_execution_changes(&self) -> Vec<SignedBlsToExecutionChange> {
        self.bls_to_execution_changes
            .read()
            .iter_fifo()
            .map(|address_change| address_change.as_inner().clone())
            .collect()
    }
}

/// Filter up to a maximum number of operations out of an iterator.
fn filter_limit_operations<'a, T, V: 'a, I, F, G>(
    operations: I,
    filter: F,
    mapping: G,
    limit: usize,
) -> Vec<V>
where
    I: IntoIterator<Item = &'a T>,
    F: Fn(&T) -> bool,
    G: Fn(&T) -> V,
    T: Clone + 'a,
{
    operations
        .into_iter()
        .filter(|x| filter(*x))
        .take(limit)
        .map(mapping)
        .collect()
}

/// Remove all entries from the given hash map for which `prune_if` returns true.
///
/// The keys in the map should be validator indices, which will be looked up
/// in the state's validator registry and then passed to `prune_if`.
/// Entries for unknown validators will be kept.
fn prune_validator_hash_map<T, F, E: EthSpec>(
    map: &mut HashMap<u64, SigVerifiedOp<T, E>>,
    prune_if: F,
    state: &BeaconState<E>,
) where
    F: Fn(u64, &Validator) -> bool,
    T: VerifyOperation<E>,
{
    map.retain(|&validator_index, op| {
        op.signature_is_still_valid(&state.fork())
            && state
                .validators()
                .get(validator_index as usize)
                .is_none_or(|validator| !prune_if(validator_index, validator))
    });
}

/// Compare two operation pools.
impl<E: EthSpec + Default> PartialEq for OperationPool<E> {
    fn eq(&self, other: &Self) -> bool {
        if ptr::eq(self, other) {
            return true;
        }
        *self.attestations.read() == *other.attestations.read()
            && *self.sync_contributions.read() == *other.sync_contributions.read()
            && *self.attester_slashings.read() == *other.attester_slashings.read()
            && *self.proposer_slashings.read() == *other.proposer_slashings.read()
            && *self.voluntary_exits.read() == *other.voluntary_exits.read()
            && *self.bls_to_execution_changes.read() == *other.bls_to_execution_changes.read()
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod release_tests {
    use super::attestation::earliest_attestation_validators;
    use super::*;
    use beacon_chain::test_utils::{
        BeaconChainHarness, EphemeralHarnessType, RelativeSyncCommittee, test_spec,
    };
    use bls::Keypair;
    use maplit::hashset;
    use state_processing::epoch_cache::initialize_epoch_cache;
    use state_processing::{VerifyOperation, common::get_attesting_indices_from_state};
    use std::collections::BTreeSet;
    use std::sync::{Arc, LazyLock};
    use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
    use types::*;

    pub const MAX_VALIDATOR_COUNT: usize = 4 * 32 * 128;

    /// A cached set of keys.
    static KEYPAIRS: LazyLock<Vec<Keypair>> =
        LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(MAX_VALIDATOR_COUNT));

    fn get_harness<E: EthSpec>(
        validator_count: usize,
        spec: Option<ChainSpec>,
    ) -> BeaconChainHarness<EphemeralHarnessType<E>> {
        let harness = BeaconChainHarness::builder(E::default())
            .spec_or_default(spec.map(Arc::new))
            .keypairs(KEYPAIRS[0..validator_count].to_vec())
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        harness.advance_slot();

        harness
    }

    /// The maximum number of attester slashings allowed in a block for the state's fork.
    fn max_attester_slashings<E: EthSpec>(state: &BeaconState<E>) -> usize {
        if state.fork_name_unchecked().electra_enabled() {
            E::max_attester_slashings_electra()
        } else {
            E::MaxAttesterSlashings::to_usize()
        }
    }

    /// Given the candidate slashings ordered most-profitable first, return the prefix that a
    /// block on the state's fork would actually include (i.e. the N most profitable, where N
    /// is the per-block attester slashing limit). This keeps the max-cover assertions generic
    /// across forks.
    fn most_profitable_slashings<E: EthSpec, T>(
        state: &BeaconState<E>,
        ordered_by_profitability: Vec<T>,
    ) -> Vec<T> {
        ordered_by_profitability
            .into_iter()
            .take(max_attester_slashings(state))
            .collect()
    }

    /// Test state for attestation-related tests.
    fn attestation_test_state<E: EthSpec>(
        num_committees: usize,
    ) -> (BeaconChainHarness<EphemeralHarnessType<E>>, ChainSpec) {
        let spec = test_spec::<E>();

        let num_validators =
            num_committees * E::slots_per_epoch() as usize * spec.target_committee_size;
        let harness = get_harness::<E>(num_validators, Some(spec.clone()));

        (harness, spec)
    }

    fn get_current_state_initialize_epoch_cache<E: EthSpec>(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
        spec: &ChainSpec,
    ) -> (BeaconState<E>, Hash256) {
        let (mut state, state_root) = harness.get_current_state_and_root();
        initialize_epoch_cache(&mut state, spec).unwrap();
        (state, state_root)
    }

    /// Test state for sync contribution-related tests.
    async fn sync_contribution_test_state<E: EthSpec>(
        num_committees: usize,
    ) -> (BeaconChainHarness<EphemeralHarnessType<E>>, ChainSpec) {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));

        let num_validators =
            num_committees * E::slots_per_epoch() as usize * spec.target_committee_size;
        let harness = get_harness::<E>(num_validators, Some(spec.clone()));

        let state = harness.get_current_state();
        harness
            .add_attested_blocks_at_slots(
                state,
                &[Slot::new(1)],
                (0..num_validators).collect::<Vec<_>>().as_slice(),
            )
            .await;

        (harness, spec)
    }

    #[test]
    fn test_earliest_attestation() {
        let (harness, ref spec) = attestation_test_state::<MainnetEthSpec>(1);

        // Only run this test on the phase0 hard-fork.
        if spec.altair_fork_epoch.is_some() {
            return;
        }

        let (mut state, state_root) = get_current_state_initialize_epoch_cache(&harness, spec);
        let slot = state.slot();
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        let num_validators =
            MainnetEthSpec::slots_per_epoch() as usize * spec.target_committee_size;

        let attestations = harness.make_attestations(
            (0..num_validators).collect::<Vec<_>>().as_slice(),
            &state,
            state_root,
            harness.head_block_root().into(),
            slot,
        );

        for (atts, aggregate) in &attestations {
            let att2 = aggregate.as_ref().unwrap().message().aggregate();

            let att1 = atts
                .iter()
                .map(|(att, _)| att)
                .take(2)
                .fold::<Option<Attestation<MainnetEthSpec>>, _>(None, |att, new_att| {
                    if let Some(mut a) = att {
                        a.aggregate(new_att.to_ref());
                        Some(a)
                    } else {
                        Some(new_att.clone())
                    }
                })
                .unwrap();

            let att1_indices = get_attesting_indices_from_state(&state, att1.to_ref()).unwrap();
            let att2_indices = get_attesting_indices_from_state(&state, att2).unwrap();
            let att1_split = SplitAttestation::new(att1.clone(), att1_indices);
            let att2_split = SplitAttestation::new(att2.clone_as_attestation(), att2_indices);

            assert_eq!(
                att1.num_set_aggregation_bits(),
                earliest_attestation_validators(
                    &att1_split.as_ref(),
                    &state,
                    state.as_base().unwrap()
                )
                .num_set_bits()
            );

            state
                .as_base_mut()
                .unwrap()
                .current_epoch_attestations
                .push(PendingAttestation {
                    aggregation_bits: att1.aggregation_bits_base().unwrap().clone(),
                    data: att1.data().clone(),
                    inclusion_delay: 0,
                    proposer_index: 0,
                })
                .unwrap();

            assert_eq!(
                committees.first().unwrap().committee.len() - 2,
                earliest_attestation_validators(
                    &att2_split.as_ref(),
                    &state,
                    state.as_base().unwrap()
                )
                .num_set_bits()
            );
        }
    }

    /// End-to-end test of basic attestation handling.
    #[test]
    fn attestation_aggregation_insert_get_prune() {
        let (harness, ref spec) = attestation_test_state::<MainnetEthSpec>(1);

        let op_pool = OperationPool::<MainnetEthSpec>::new();
        let (mut state, state_root) = get_current_state_initialize_epoch_cache(&harness, spec);

        let slot = state.slot();
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        assert_eq!(
            committees.len(),
            1,
            "we expect just one committee with this many validators"
        );

        let num_validators =
            MainnetEthSpec::slots_per_epoch() as usize * spec.target_committee_size;

        let attestations = harness.make_attestations(
            (0..num_validators).collect::<Vec<_>>().as_slice(),
            &state,
            state_root,
            harness.head_block_root().into(),
            slot,
        );

        for (atts, _) in attestations {
            for (att, _) in atts {
                let attesting_indices =
                    get_attesting_indices_from_state(&state, att.to_ref()).unwrap();
                op_pool.insert_attestation(att, attesting_indices).unwrap();
            }
        }

        assert_eq!(op_pool.num_attestations(), committees.len());

        // Before the min attestation inclusion delay, get_attestations shouldn't return anything.
        assert_eq!(
            op_pool
                .get_attestations(&state, |_| true, |_| true, spec)
                .expect("should have attestations")
                .len(),
            0
        );

        // Then once the delay has elapsed, we should get a single aggregated attestation.
        *state.slot_mut() += spec.min_attestation_inclusion_delay;

        let block_attestations = op_pool
            .get_attestations(&state, |_| true, |_| true, spec)
            .expect("Should have block attestations");
        assert_eq!(block_attestations.len(), committees.len());

        let agg_att = &block_attestations[0];
        assert_eq!(
            agg_att.num_set_aggregation_bits(),
            spec.target_committee_size
        );

        // Prune attestations shouldn't do anything at this point.
        op_pool.prune_attestations(state.current_epoch());
        assert_eq!(op_pool.num_attestations(), committees.len());

        // But once we advance to more than an epoch after the attestation, it should prune it
        // out of existence.
        *state.slot_mut() += 2 * MainnetEthSpec::slots_per_epoch();
        op_pool.prune_attestations(state.current_epoch());
        assert_eq!(op_pool.num_attestations(), 0);
    }

    /// Adding an attestation already in the pool should not increase the size of the pool.
    #[test]
    fn attestation_duplicate() {
        let (harness, ref spec) = attestation_test_state::<MainnetEthSpec>(1);

        let (state, state_root) = get_current_state_initialize_epoch_cache(&harness, spec);

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slot = state.slot();
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        let num_validators =
            MainnetEthSpec::slots_per_epoch() as usize * spec.target_committee_size;
        let attestations = harness.make_attestations(
            (0..num_validators).collect::<Vec<_>>().as_slice(),
            &state,
            state_root,
            harness.head_block_root().into(),
            slot,
        );

        for (_, aggregate) in attestations {
            let agg = aggregate.unwrap();
            let att = agg.message().aggregate();
            let attesting_indices = get_attesting_indices_from_state(&state, att).unwrap();
            op_pool
                .insert_attestation(att.clone_as_attestation(), attesting_indices.clone())
                .unwrap();
            op_pool
                .insert_attestation(att.clone_as_attestation(), attesting_indices)
                .unwrap();
        }

        assert_eq!(op_pool.num_attestations(), committees.len());
    }

    /// Adding lots of attestations that only intersect pairwise should lead to two aggregate
    /// attestations.
    #[test]
    fn attestation_pairwise_overlapping() {
        let (harness, ref spec) = attestation_test_state::<MainnetEthSpec>(1);

        let (state, state_root) = get_current_state_initialize_epoch_cache(&harness, spec);

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slot = state.slot();
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        let num_validators =
            MainnetEthSpec::slots_per_epoch() as usize * spec.target_committee_size;

        let attestations = harness.make_attestations(
            (0..num_validators).collect::<Vec<_>>().as_slice(),
            &state,
            state_root,
            harness.head_block_root().into(),
            slot,
        );

        let step_size = 2;
        // Create attestations that overlap on `step_size` validators, like:
        // {0,1,2,3}, {2,3,4,5}, {4,5,6,7}, ...
        for (atts1, _) in attestations {
            let atts2 = atts1.clone();
            let aggs1 = atts1
                .chunks_exact(step_size * 2)
                .map(|chunk| {
                    let agg = chunk
                        .iter()
                        .map(|(att, _)| att)
                        .fold::<Option<Attestation<MainnetEthSpec>>, _>(None, |att, new_att| {
                            if let Some(mut a) = att {
                                a.aggregate(new_att.to_ref());
                                Some(a)
                            } else {
                                Some(new_att.clone())
                            }
                        });
                    agg.unwrap()
                })
                .collect::<Vec<_>>();
            let aggs2 = atts2
                .into_iter()
                .skip(step_size)
                .collect::<Vec<_>>()
                .as_slice()
                .chunks_exact(step_size * 2)
                .map(|chunk| {
                    let agg = chunk
                        .iter()
                        .map(|(att, _)| att)
                        .fold::<Option<Attestation<MainnetEthSpec>>, _>(None, |att, new_att| {
                            if let Some(mut a) = att {
                                a.aggregate(new_att.to_ref());
                                Some(a)
                            } else {
                                Some(new_att.clone())
                            }
                        });
                    agg.unwrap()
                })
                .collect::<Vec<_>>();

            for att in aggs1.into_iter().chain(aggs2) {
                let attesting_indices =
                    get_attesting_indices_from_state(&state, att.to_ref()).unwrap();
                op_pool.insert_attestation(att, attesting_indices).unwrap();
            }
        }

        // The attestations should get aggregated into two attestations that comprise all
        // validators.
        let stats = op_pool.attestation_stats();
        assert_eq!(stats.num_attestation_data, committees.len());
        assert_eq!(stats.num_attestations, 2 * committees.len());
        assert_eq!(stats.max_aggregates_per_data, 2);
    }

    /// Create a bunch of attestations signed by a small number of validators, and another
    /// bunch signed by a larger number, such that there are at least `max_attestations`
    /// signed by the larger number. Then, check that `get_attestations` only returns the
    /// high-quality attestations. To ensure that no aggregation occurs, ALL attestations
    /// are also signed by the 0th member of the committee.
    #[test]
    fn attestation_get_max() {
        let small_step_size = 2;
        let big_step_size = 4;
        let num_committees = big_step_size;

        let (harness, ref spec) = attestation_test_state::<MainnetEthSpec>(num_committees);

        let (mut state, state_root) = get_current_state_initialize_epoch_cache(&harness, spec);

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slot = state.slot();
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        let max_attestations = <MainnetEthSpec as EthSpec>::MaxAttestations::to_usize();
        let target_committee_size = spec.target_committee_size;
        let num_validators = num_committees
            * MainnetEthSpec::slots_per_epoch() as usize
            * spec.target_committee_size;

        let attestations = harness.make_attestations(
            (0..num_validators).collect::<Vec<_>>().as_slice(),
            &state,
            state_root,
            harness.head_block_root().into(),
            slot,
        );

        let insert_attestations = |attestations: Vec<(Attestation<MainnetEthSpec>, SubnetId)>,
                                   step_size| {
            let att_0 = attestations.first().unwrap().0.clone();
            let aggs = attestations
                .chunks_exact(step_size)
                .map(|chunk| {
                    chunk
                        .iter()
                        .map(|(att, _)| att)
                        .fold::<Attestation<MainnetEthSpec>, _>(
                            att_0.clone(),
                            |mut att, new_att| {
                                att.aggregate(new_att.to_ref());
                                att
                            },
                        )
                })
                .collect::<Vec<_>>();

            for att in aggs {
                let attesting_indices =
                    get_attesting_indices_from_state(&state, att.to_ref()).unwrap();
                op_pool.insert_attestation(att, attesting_indices).unwrap();
            }
        };

        for (atts, _) in attestations {
            assert_eq!(atts.len(), target_committee_size);
            // Attestations signed by only 2-3 validators
            insert_attestations(atts.clone(), small_step_size);
            // Attestations signed by 4+ validators
            insert_attestations(atts, big_step_size);
        }

        let num_small = target_committee_size / small_step_size;
        let num_big = target_committee_size / big_step_size;

        let stats = op_pool.attestation_stats();
        let fork_name = state.fork_name_unchecked();

        if fork_name.electra_enabled() {
            assert_eq!(stats.num_attestation_data, 1);
        } else {
            assert_eq!(stats.num_attestation_data, committees.len());
        }

        assert_eq!(
            stats.num_attestations,
            (num_small + num_big) * committees.len()
        );
        assert!(stats.num_attestations > max_attestations);

        *state.slot_mut() += spec.min_attestation_inclusion_delay;
        let best_attestations = op_pool
            .get_attestations(&state, |_| true, |_| true, spec)
            .expect("should have best attestations");
        if fork_name.electra_enabled() {
            assert_eq!(best_attestations.len(), 8);
        } else {
            assert_eq!(best_attestations.len(), max_attestations);
        }

        // All the best attestations should be signed by at least `big_step_size` (4) validators.
        for att in &best_attestations {
            if fork_name.electra_enabled() {
                assert!(att.num_set_aggregation_bits() >= small_step_size);
            } else {
                assert!(att.num_set_aggregation_bits() >= big_step_size);
            }
        }
    }

    #[test]
    fn attestation_rewards() {
        let small_step_size = 2;
        let big_step_size = 4;
        let num_committees = big_step_size;

        let (harness, ref spec) = attestation_test_state::<MainnetEthSpec>(num_committees);

        let (mut state, state_root) = get_current_state_initialize_epoch_cache(&harness, spec);
        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slot = state.slot();
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        let max_attestations = <MainnetEthSpec as EthSpec>::MaxAttestations::to_usize();
        let target_committee_size = spec.target_committee_size;

        // Each validator will have a multiple of 1_000_000_000 wei.
        // Safe from overflow unless there are about 18B validators (2^64 / 1_000_000_000).
        for i in 0..state.validators().len() {
            state.validators_mut().get_mut(i).unwrap().effective_balance = 1_000_000_000 * i as u64;
        }

        let num_validators = num_committees
            * MainnetEthSpec::slots_per_epoch() as usize
            * spec.target_committee_size;
        let attestations = harness.make_attestations(
            (0..num_validators).collect::<Vec<_>>().as_slice(),
            &state,
            state_root,
            harness.head_block_root().into(),
            slot,
        );

        let insert_attestations = |attestations: Vec<(Attestation<MainnetEthSpec>, SubnetId)>,
                                   step_size| {
            let att_0 = attestations.first().unwrap().0.clone();
            let aggs = attestations
                .chunks_exact(step_size)
                .map(|chunk| {
                    chunk
                        .iter()
                        .map(|(att, _)| att)
                        .fold::<Attestation<MainnetEthSpec>, _>(
                            att_0.clone(),
                            |mut att, new_att| {
                                att.aggregate(new_att.to_ref());
                                att
                            },
                        )
                })
                .collect::<Vec<_>>();

            for att in aggs {
                let attesting_indices =
                    get_attesting_indices_from_state(&state, att.to_ref()).unwrap();
                op_pool.insert_attestation(att, attesting_indices).unwrap();
            }
        };

        for (atts, _) in attestations {
            assert_eq!(atts.len(), target_committee_size);
            // Attestations signed by only 2-3 validators
            insert_attestations(atts.clone(), small_step_size);
            // Attestations signed by 4+ validators
            insert_attestations(atts, big_step_size);
        }

        let num_small = target_committee_size / small_step_size;
        let num_big = target_committee_size / big_step_size;
        let fork_name = state.fork_name_unchecked();

        if fork_name.electra_enabled() {
            assert_eq!(op_pool.attestation_stats().num_attestation_data, 1);
        } else {
            assert_eq!(
                op_pool.attestation_stats().num_attestation_data,
                committees.len()
            );
        }

        assert_eq!(
            op_pool.num_attestations(),
            (num_small + num_big) * committees.len()
        );
        assert!(op_pool.num_attestations() > max_attestations);

        *state.slot_mut() += spec.min_attestation_inclusion_delay;
        let best_attestations = op_pool
            .get_attestations(&state, |_| true, |_| true, spec)
            .expect("should have valid best attestations");

        if fork_name.electra_enabled() {
            assert_eq!(best_attestations.len(), 8);
        } else {
            assert_eq!(best_attestations.len(), max_attestations);
        }

        let total_active_balance = state.get_total_active_balance().unwrap();

        // Set of indices covered by previous attestations in `best_attestations`.
        let mut seen_indices = BTreeSet::<u64>::new();
        // Used for asserting that rewards are in decreasing order.
        let mut prev_reward = u64::MAX;

        let mut reward_cache = RewardCache::default();
        reward_cache.update(&state).unwrap();

        for att in best_attestations {
            let attesting_indices = get_attesting_indices_from_state(&state, att.to_ref()).unwrap();
            let split_attestation = SplitAttestation::new(att, attesting_indices);
            let mut fresh_validators_rewards = AttMaxCover::new(
                split_attestation.as_ref(),
                &state,
                &reward_cache,
                total_active_balance,
                spec,
            )
            .unwrap()
            .fresh_validators_rewards;

            // Remove validators covered by previous attestations.
            fresh_validators_rewards
                .retain(|validator_index, _| !seen_indices.contains(validator_index));

            // Check that rewards are in decreasing order
            let rewards =
                fresh_validators_rewards.values().sum::<u64>() / PROPOSER_REWARD_DENOMINATOR;
            assert!(prev_reward >= rewards);
            prev_reward = rewards;
            seen_indices.extend(fresh_validators_rewards.keys());
        }
    }

    /// Insert two slashings for the same proposer and ensure only one is returned.
    #[test]
    fn duplicate_proposer_slashing() {
        let harness = get_harness(32, None);
        let state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let proposer_index = 0;
        let slashing1 = harness.make_proposer_slashing(proposer_index);

        let slashing2 = ProposerSlashing {
            signed_header_1: slashing1.signed_header_2.clone(),
            signed_header_2: slashing1.signed_header_1.clone(),
        };

        // Both slashings should be valid and accepted by the pool.
        op_pool
            .insert_proposer_slashing(slashing1.clone().validate(&state, &harness.spec).unwrap());
        op_pool
            .insert_proposer_slashing(slashing2.clone().validate(&state, &harness.spec).unwrap());

        // Should only get the second slashing back.
        assert_eq!(
            op_pool.get_slashings_and_exits(&state, &harness.spec).0,
            vec![slashing2]
        );
    }

    // Sanity check on the pruning of proposer slashings
    #[test]
    fn prune_proposer_slashing_noop() {
        let harness = get_harness(32, None);
        let state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slashing = harness.make_proposer_slashing(0);
        op_pool.insert_proposer_slashing(slashing.clone().validate(&state, &harness.spec).unwrap());
        op_pool.prune_proposer_slashings(&state);
        assert_eq!(
            op_pool.get_slashings_and_exits(&state, &harness.spec).0,
            vec![slashing]
        );
    }

    // Sanity check on the pruning of attester slashings
    #[test]
    fn prune_attester_slashing_noop() {
        let harness = get_harness(32, None);
        let spec = &harness.spec;
        let state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slashing = harness.make_attester_slashing(vec![1, 3, 5, 7, 9]);
        op_pool.insert_attester_slashing(slashing.clone().validate(&state, spec).unwrap());
        op_pool.prune_attester_slashings(&state);
        assert_eq!(
            op_pool.get_slashings_and_exits(&state, &harness.spec).1,
            vec![slashing]
        );
    }

    // Check that we get maximum coverage for attester slashings (highest qty of validators slashed)
    #[test]
    fn simple_max_cover_attester_slashing() {
        let harness = get_harness(32, None);
        let spec = &harness.spec;
        let state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slashing_1 = harness.make_attester_slashing(vec![1]);
        let slashing_2 = harness.make_attester_slashing(vec![2, 3]);
        let slashing_3 = harness.make_attester_slashing(vec![4, 5, 6]);
        let slashing_4 = harness.make_attester_slashing(vec![7, 8, 9, 10]);

        op_pool.insert_attester_slashing(slashing_1.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_2.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_3.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_4.clone().validate(&state, spec).unwrap());

        let best_slashings = op_pool.get_slashings_and_exits(&state, &harness.spec);
        assert_eq!(
            best_slashings.1,
            most_profitable_slashings(&state, vec![slashing_4, slashing_3])
        );
    }

    // Check that we get maximum coverage for attester slashings with overlapping indices
    #[test]
    fn overlapping_max_cover_attester_slashing() {
        let harness = get_harness(32, None);
        let spec = &harness.spec;
        let state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slashing_1 = harness.make_attester_slashing(vec![1, 2, 3, 4]);
        let slashing_2 = harness.make_attester_slashing(vec![1, 2, 5]);
        let slashing_3 = harness.make_attester_slashing(vec![5, 6]);
        let slashing_4 = harness.make_attester_slashing(vec![6]);

        op_pool.insert_attester_slashing(slashing_1.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_2.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_3.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_4.clone().validate(&state, spec).unwrap());

        let best_slashings = op_pool.get_slashings_and_exits(&state, &harness.spec);
        assert_eq!(
            best_slashings.1,
            most_profitable_slashings(&state, vec![slashing_1, slashing_3])
        );
    }

    // Max coverage of attester slashings taking into account proposer slashings
    #[test]
    fn max_coverage_attester_proposer_slashings() {
        let harness = get_harness(32, None);
        let spec = &harness.spec;
        let state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let p_slashing = harness.make_proposer_slashing(1);
        let a_slashing_1 = harness.make_attester_slashing(vec![1, 2, 3, 4]);
        let a_slashing_2 = harness.make_attester_slashing(vec![1, 3, 4]);
        let a_slashing_3 = harness.make_attester_slashing(vec![5, 6]);

        op_pool.insert_proposer_slashing(p_slashing.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(a_slashing_1.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(a_slashing_2.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(a_slashing_3.clone().validate(&state, spec).unwrap());

        let best_slashings = op_pool.get_slashings_and_exits(&state, &harness.spec);
        assert_eq!(
            best_slashings.1,
            most_profitable_slashings(&state, vec![a_slashing_1, a_slashing_3])
        );
    }

    //Max coverage checking that non overlapping indices are still recognized for their value
    #[test]
    fn max_coverage_different_indices_set() {
        let harness = get_harness(32, None);
        let spec = &harness.spec;
        let state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slashing_1 = harness.make_attester_slashing_different_indices(
            vec![1, 2, 3, 4, 5, 6],
            vec![3, 4, 5, 6, 7, 8],
        );
        let slashing_2 = harness.make_attester_slashing(vec![5, 6]);
        let slashing_3 = harness.make_attester_slashing(vec![1, 2, 3]);

        op_pool.insert_attester_slashing(slashing_1.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_2.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_3.clone().validate(&state, spec).unwrap());

        let best_slashings = op_pool.get_slashings_and_exits(&state, &harness.spec);
        assert_eq!(
            best_slashings.1,
            most_profitable_slashings(&state, vec![slashing_1, slashing_3])
        );
    }

    // Max coverage should be affected by the overall effective balances
    #[test]
    fn max_coverage_effective_balances() {
        let harness = get_harness(32, None);
        let spec = &harness.spec;
        let mut state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();
        state.validators_mut().get_mut(1).unwrap().effective_balance = 17_000_000_000;
        state.validators_mut().get_mut(2).unwrap().effective_balance = 17_000_000_000;
        state.validators_mut().get_mut(3).unwrap().effective_balance = 17_000_000_000;

        let slashing_1 = harness.make_attester_slashing(vec![1, 2, 3]);
        let slashing_2 = harness.make_attester_slashing(vec![4, 5, 6]);
        let slashing_3 = harness.make_attester_slashing(vec![7, 8]);

        op_pool.insert_attester_slashing(slashing_1.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_2.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_3.clone().validate(&state, spec).unwrap());

        let best_slashings = op_pool.get_slashings_and_exits(&state, &harness.spec);
        assert_eq!(
            best_slashings.1,
            most_profitable_slashings(&state, vec![slashing_2, slashing_3])
        );
    }

    /// End-to-end test of basic sync contribution handling.
    #[tokio::test]
    async fn sync_contribution_aggregation_insert_get_prune() {
        let (harness, _) = sync_contribution_test_state::<MainnetEthSpec>(1).await;

        let op_pool = OperationPool::<MainnetEthSpec>::new();
        let state = harness.get_current_state();

        let block_root = *state
            .get_block_root(state.slot() - Slot::new(1))
            .expect("block root should exist at slot");
        let contributions = harness.make_sync_contributions(
            &state,
            block_root,
            state.slot() - Slot::new(1),
            RelativeSyncCommittee::Current,
        );

        for (_, contribution_and_proof) in contributions {
            let contribution = contribution_and_proof
                .expect("contribution exists for committee")
                .message
                .contribution;
            op_pool.insert_sync_contribution(contribution).unwrap();
        }

        assert_eq!(op_pool.sync_contributions.read().len(), 1);
        assert_eq!(
            op_pool.num_sync_contributions(),
            SYNC_COMMITTEE_SUBNET_COUNT as usize
        );

        let sync_aggregate = op_pool
            .get_sync_aggregate(&state)
            .expect("Should calculate the sync aggregate")
            .expect("Should have block sync aggregate");
        assert_eq!(
            sync_aggregate.sync_committee_bits.num_set_bits(),
            MainnetEthSpec::sync_committee_size()
        );

        // Prune sync contributions shouldn't do anything at this point.
        op_pool.prune_sync_contributions(state.slot() - Slot::new(1));
        assert_eq!(
            op_pool.num_sync_contributions(),
            SYNC_COMMITTEE_SUBNET_COUNT as usize
        );
        op_pool.prune_sync_contributions(state.slot());
        assert_eq!(
            op_pool.num_sync_contributions(),
            SYNC_COMMITTEE_SUBNET_COUNT as usize
        );

        // But once we advance to more than one slot after the contribution, it should prune it
        // out of existence.
        op_pool.prune_sync_contributions(state.slot() + Slot::new(1));
        assert_eq!(op_pool.num_sync_contributions(), 0);
    }

    /// Adding a sync contribution already in the pool should not increase the size of the pool.
    #[tokio::test]
    async fn sync_contribution_duplicate() {
        let (harness, _) = sync_contribution_test_state::<MainnetEthSpec>(1).await;

        let op_pool = OperationPool::<MainnetEthSpec>::new();
        let state = harness.get_current_state();
        let block_root = *state
            .get_block_root(state.slot() - Slot::new(1))
            .expect("block root should exist at slot");
        let contributions = harness.make_sync_contributions(
            &state,
            block_root,
            state.slot() - Slot::new(1),
            RelativeSyncCommittee::Current,
        );

        for (_, contribution_and_proof) in contributions {
            let contribution = contribution_and_proof
                .expect("contribution exists for committee")
                .message
                .contribution;
            op_pool
                .insert_sync_contribution(contribution.clone())
                .unwrap();
            op_pool.insert_sync_contribution(contribution).unwrap();
        }

        assert_eq!(op_pool.sync_contributions.read().len(), 1);
        assert_eq!(
            op_pool.num_sync_contributions(),
            SYNC_COMMITTEE_SUBNET_COUNT as usize
        );
    }

    /// Adding a sync contribution already in the pool with more bits set should increase the
    /// number of bits set in the aggregate.
    #[tokio::test]
    async fn sync_contribution_with_more_bits() {
        let (harness, _) = sync_contribution_test_state::<MainnetEthSpec>(1).await;

        let op_pool = OperationPool::<MainnetEthSpec>::new();
        let state = harness.get_current_state();
        let block_root = *state
            .get_block_root(state.slot() - Slot::new(1))
            .expect("block root should exist at slot");
        let contributions = harness.make_sync_contributions(
            &state,
            block_root,
            state.slot() - Slot::new(1),
            RelativeSyncCommittee::Current,
        );

        let expected_bits = MainnetEthSpec::sync_committee_size() - (2 * contributions.len());
        let mut first_contribution = contributions[0]
            .1
            .as_ref()
            .unwrap()
            .message
            .contribution
            .clone();

        // Add all contributions, but unset the first two bits of each.
        for (_, contribution_and_proof) in contributions {
            let mut contribution_fewer_bits = contribution_and_proof
                .expect("contribution exists for committee")
                .message
                .contribution;

            // Unset the first two bits of each contribution.
            contribution_fewer_bits
                .aggregation_bits
                .set(0, false)
                .expect("set bit");
            contribution_fewer_bits
                .aggregation_bits
                .set(1, false)
                .expect("set bit");

            op_pool
                .insert_sync_contribution(contribution_fewer_bits)
                .unwrap();
        }

        let sync_aggregate = op_pool
            .get_sync_aggregate(&state)
            .expect("Should calculate the sync aggregate")
            .expect("Should have block sync aggregate");
        assert_eq!(
            sync_aggregate.sync_committee_bits.num_set_bits(),
            expected_bits
        );

        // Unset the first bit of the first contribution and re-insert it. This should increase the
        // number of bits set in the sync aggregate by one.
        first_contribution
            .aggregation_bits
            .set(0, false)
            .expect("set bit");
        op_pool
            .insert_sync_contribution(first_contribution)
            .unwrap();

        // The sync aggregate should now include the additional set bit.
        let sync_aggregate = op_pool
            .get_sync_aggregate(&state)
            .expect("Should calculate the sync aggregate")
            .expect("Should have block sync aggregate");
        assert_eq!(
            sync_aggregate.sync_committee_bits.num_set_bits(),
            expected_bits + 1
        );
    }

    /// Adding a sync contribution already in the pool with fewer bits set should not increase the
    /// number of bits set in the aggregate.
    #[tokio::test]
    async fn sync_contribution_with_fewer_bits() {
        let (harness, _) = sync_contribution_test_state::<MainnetEthSpec>(1).await;

        let op_pool = OperationPool::<MainnetEthSpec>::new();
        let state = harness.get_current_state();
        let block_root = *state
            .get_block_root(state.slot() - Slot::new(1))
            .expect("block root should exist at slot");
        let contributions = harness.make_sync_contributions(
            &state,
            block_root,
            state.slot() - Slot::new(1),
            RelativeSyncCommittee::Current,
        );

        let expected_bits = MainnetEthSpec::sync_committee_size() - (2 * contributions.len());
        let mut first_contribution = contributions[0]
            .1
            .as_ref()
            .unwrap()
            .message
            .contribution
            .clone();

        // Add all contributions, but unset the first two bits of each.
        for (_, contribution_and_proof) in contributions {
            let mut contribution_fewer_bits = contribution_and_proof
                .expect("contribution exists for committee")
                .message
                .contribution;

            // Unset the first two bits of each contribution.
            contribution_fewer_bits
                .aggregation_bits
                .set(0, false)
                .expect("set bit");
            contribution_fewer_bits
                .aggregation_bits
                .set(1, false)
                .expect("set bit");

            op_pool
                .insert_sync_contribution(contribution_fewer_bits)
                .unwrap();
        }

        let sync_aggregate = op_pool
            .get_sync_aggregate(&state)
            .expect("Should calculate the sync aggregate")
            .expect("Should have block sync aggregate");
        assert_eq!(
            sync_aggregate.sync_committee_bits.num_set_bits(),
            expected_bits
        );

        // Unset the first three bits of the first contribution and re-insert it. This should
        // not affect the number of bits set in the sync aggregate.
        first_contribution
            .aggregation_bits
            .set(0, false)
            .expect("set bit");
        first_contribution
            .aggregation_bits
            .set(1, false)
            .expect("set bit");
        first_contribution
            .aggregation_bits
            .set(2, false)
            .expect("set bit");
        op_pool
            .insert_sync_contribution(first_contribution)
            .unwrap();

        // The sync aggregate should still have the same number of set bits.
        let sync_aggregate = op_pool
            .get_sync_aggregate(&state)
            .expect("Should calculate the sync aggregate")
            .expect("Should have block sync aggregate");
        assert_eq!(
            sync_aggregate.sync_committee_bits.num_set_bits(),
            expected_bits
        );
    }

    fn cross_fork_harness<E: EthSpec>() -> (BeaconChainHarness<EphemeralHarnessType<E>>, ChainSpec)
    {
        let mut spec = E::default_spec();

        // Give some room to sign surround slashings.
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(0));
        spec.capella_fork_epoch = Some(Epoch::new(0));
        spec.deneb_fork_epoch = Some(Epoch::new(2));
        spec.electra_fork_epoch = Some(Epoch::new(4));

        // To make exits immediately valid.
        spec.shard_committee_period = 0;

        let num_validators = 32;

        let harness = get_harness::<E>(num_validators, Some(spec.clone()));
        if let Some(mock_el) = harness.mock_execution_layer.as_ref() {
            mock_el.server.all_payloads_valid();
        }
        (harness, spec)
    }

    // Voluntary exits signed post-Capella are perpetually valid across forks, so no
    // cross-fork test is required here.

    /// Test several cross-fork proposer slashings:
    ///
    /// - Capella slashing (not valid after Electra)
    /// - Electra signed with Deneb fork version (not valid after Electra)
    /// - Capella exit signed with Deneb fork version (only valid after Electra)
    #[tokio::test]
    async fn cross_fork_proposer_slashings() {
        let (harness, spec) = cross_fork_harness::<MainnetEthSpec>();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        let deneb_fork_epoch = spec.deneb_fork_epoch.unwrap();
        let electra_fork_epoch = spec.electra_fork_epoch.unwrap();
        let electra_fork_slot = electra_fork_epoch.start_slot(slots_per_epoch);

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        // Sign a proposer slashing in Capella with a Capella slot.
        let slashing1 = harness.make_proposer_slashing_at_slot(0, Some(Slot::new(1)));

        // Advance to Deneb.
        harness
            .extend_to_slot(deneb_fork_epoch.start_slot(slots_per_epoch))
            .await;
        let deneb_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(deneb_head.beacon_state.current_epoch(), deneb_fork_epoch);

        // Add slashing1 to the op pool during Deneb. It's still valid at this point and should be
        // returned.
        let verified_slashing1 = slashing1
            .clone()
            .validate(&deneb_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_proposer_slashing(verified_slashing1);
        let (proposer_slashings, _, _) =
            op_pool.get_slashings_and_exits(&deneb_head.beacon_state, &harness.chain.spec);
        assert!(proposer_slashings.contains(&slashing1));
        assert_eq!(proposer_slashings.len(), 1);

        // Sign a proposer slashing with a Electra slot using the Deneb fork domain.
        //
        // This slashing is valid only before the Electra fork epoch.
        let slashing2 = harness.make_proposer_slashing_at_slot(1, Some(electra_fork_slot));
        let verified_slashing2 = slashing2
            .clone()
            .validate(&deneb_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_proposer_slashing(verified_slashing2);
        let (proposer_slashings, _, _) =
            op_pool.get_slashings_and_exits(&deneb_head.beacon_state, &harness.chain.spec);
        assert!(proposer_slashings.contains(&slashing1));
        assert!(proposer_slashings.contains(&slashing2));
        assert_eq!(proposer_slashings.len(), 2);

        // Advance to Electra.
        harness.extend_to_slot(electra_fork_slot).await;
        let electra_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(
            electra_head.beacon_state.current_epoch(),
            electra_fork_epoch
        );

        // Sign a proposer slashing with the Deneb domain and a Capella slot. This is a weird type
        // of slashing that is only valid after the Electra fork because we'll use the Deneb fork
        // domain to verify all prior epochs.
        let slashing3 = harness.make_proposer_slashing_at_slot(2, Some(Slot::new(1)));
        let verified_slashing3 = slashing3
            .clone()
            .validate(&electra_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_proposer_slashing(verified_slashing3);

        // Attempting to fetch slashing1 now should fail, despite it still being in the pool.
        // Likewise slashing2 is also invalid now because it should be signed with the
        // Electra fork version.
        // slashing3 should still be valid, because it was signed with the Deneb fork domain.
        assert_eq!(op_pool.proposer_slashings.read().len(), 3);
        let (proposer_slashings, _, _) =
            op_pool.get_slashings_and_exits(&electra_head.beacon_state, &harness.spec);
        assert!(proposer_slashings.contains(&slashing3));
        assert_eq!(proposer_slashings.len(), 1);
    }

    /// Test several cross-fork attester slashings:
    ///
    /// - both target epochs in Capella (not valid after Electra)
    /// - both target epochs in Electra but signed with Deneb domain (not valid after Electra)
    /// - Deneb attestation that surrounds a Capella attestation (not valid after Electra)
    /// - both target epochs in Capella but signed with Deneb domain (only valid after Electra)
    #[tokio::test]
    async fn cross_fork_attester_slashings() {
        let (harness, spec) = cross_fork_harness::<MainnetEthSpec>();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        let zero_epoch = Epoch::new(0);
        let deneb_fork_epoch = spec.deneb_fork_epoch.unwrap();
        let electra_fork_epoch = spec.electra_fork_epoch.unwrap();
        let electra_fork_slot = electra_fork_epoch.start_slot(slots_per_epoch);

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        // Sign an attester slashing with the Capella fork version, with both target epochs in Capella.
        let slashing1 = harness.make_attester_slashing_with_epochs(
            vec![0],
            None,
            Some(zero_epoch),
            None,
            Some(zero_epoch),
        );

        // Advance to Deneb.
        harness
            .extend_to_slot(deneb_fork_epoch.start_slot(slots_per_epoch))
            .await;
        let deneb_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(deneb_head.beacon_state.current_epoch(), deneb_fork_epoch);

        // Add slashing1 to the op pool during Deneb. It's still valid at this point and should be
        // returned.
        let verified_slashing1 = slashing1
            .clone()
            .validate(&deneb_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_attester_slashing(verified_slashing1);

        // Sign an attester slashing with two Electra epochs using the Deneb fork domain.
        //
        // This slashing is valid only before the Electra fork epoch.
        let slashing2 = harness.make_attester_slashing_with_epochs(
            vec![1],
            None,
            Some(electra_fork_epoch),
            None,
            Some(electra_fork_epoch),
        );
        let verified_slashing2 = slashing2
            .clone()
            .validate(&deneb_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_attester_slashing(verified_slashing2);
        let (_, attester_slashings, _) =
            op_pool.get_slashings_and_exits(&deneb_head.beacon_state, &harness.chain.spec);
        assert!(attester_slashings.contains(&slashing1));
        assert!(attester_slashings.contains(&slashing2));
        assert_eq!(attester_slashings.len(), 2);

        // Sign an attester slashing where a Deneb attestation surrounds a Capella one.
        //
        // This slashing is valid only before the Electra fork epoch.
        let slashing3 = harness.make_attester_slashing_with_epochs(
            vec![2],
            Some(Epoch::new(0)),
            Some(deneb_fork_epoch),
            Some(Epoch::new(1)),
            Some(deneb_fork_epoch - 1),
        );
        let verified_slashing3 = slashing3
            .clone()
            .validate(&deneb_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_attester_slashing(verified_slashing3);

        // All three slashings should be valid and returned from the pool at this point.
        // Seeing as we can only extract 2 at time we'll just pretend that validator 0 is already
        // slashed.
        let mut to_be_slashed = hashset! {0};
        let attester_slashings =
            op_pool.get_attester_slashings(&deneb_head.beacon_state, &mut to_be_slashed);
        assert!(attester_slashings.contains(&slashing2));
        assert!(attester_slashings.contains(&slashing3));
        assert_eq!(attester_slashings.len(), 2);

        // Advance to Electra
        harness.extend_to_slot(electra_fork_slot).await;
        let electra_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(
            electra_head.beacon_state.current_epoch(),
            electra_fork_epoch
        );

        // Sign an attester slashing with the Deneb domain and Capella epochs. This is only valid
        // after the Electra fork.
        let slashing4 = harness.make_attester_slashing_with_epochs(
            vec![3],
            Some(Epoch::new(0)),
            Some(deneb_fork_epoch - 1),
            Some(Epoch::new(0)),
            Some(deneb_fork_epoch - 1),
        );
        let verified_slashing4 = slashing4
            .clone()
            .validate(&electra_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_attester_slashing(verified_slashing4);

        // All slashings except slashing4 are now invalid (despite being present in the pool).
        assert_eq!(op_pool.attester_slashings.read().len(), 4);
        let (_, attester_slashings, _) =
            op_pool.get_slashings_and_exits(&electra_head.beacon_state, &harness.spec);
        assert!(attester_slashings.contains(&slashing4));
        assert_eq!(attester_slashings.len(), 1);

        // Pruning the attester slashings should remove all but slashing4.
        op_pool.prune_attester_slashings(&electra_head.beacon_state);
        assert_eq!(op_pool.attester_slashings.read().len(), 1);
    }

    /// Regression test to ensure that we are using the correct spec value for max attester slashings post-Electra.
    #[tokio::test]
    async fn attester_slashings_capped_at_electra_limit() {
        let (harness, spec) = cross_fork_harness::<MainnetEthSpec>();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        let electra_fork_epoch = spec.electra_fork_epoch.unwrap();
        let deneb_fork_epoch = spec.deneb_fork_epoch.unwrap();

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        harness
            .extend_to_slot(electra_fork_epoch.start_slot(slots_per_epoch))
            .await;
        let electra_head = harness.chain.canonical_head.cached_head().snapshot;
        assert!(
            electra_head
                .beacon_state
                .fork_name_unchecked()
                .electra_enabled()
        );

        // Create two slashings
        for validators in [vec![0], vec![1]] {
            let slashing = harness.make_attester_slashing_with_epochs(
                validators,
                Some(Epoch::new(0)),
                Some(deneb_fork_epoch - 1),
                Some(Epoch::new(0)),
                Some(deneb_fork_epoch - 1),
            );
            let verified = slashing
                .validate(&electra_head.beacon_state, &harness.chain.spec)
                .unwrap();
            op_pool.insert_attester_slashing(verified);
        }
        assert_eq!(op_pool.attester_slashings.read().len(), 2);

        // Despite two valid slashings being pending, only one may be extracted post-Electra.
        let mut to_be_slashed = HashSet::new();
        let attester_slashings =
            op_pool.get_attester_slashings(&electra_head.beacon_state, &mut to_be_slashed);
        assert_eq!(
            attester_slashings.len(),
            MainnetEthSpec::max_attester_slashings_electra()
        );
    }

    fn make_payload_attestation_message(
        slot: Slot,
        validator_index: u64,
        beacon_block_root: Hash256,
    ) -> PayloadAttestationMessage {
        make_payload_attestation_message_with_flags(
            slot,
            validator_index,
            beacon_block_root,
            true,
            true,
        )
    }

    fn make_payload_attestation_message_with_flags(
        slot: Slot,
        validator_index: u64,
        beacon_block_root: Hash256,
        payload_present: bool,
        blob_data_available: bool,
    ) -> PayloadAttestationMessage {
        PayloadAttestationMessage {
            validator_index,
            data: PayloadAttestationData {
                beacon_block_root,
                slot,
                payload_present,
                blob_data_available,
            },
            signature: bls::Signature::empty(),
        }
    }

    #[test]
    fn payload_attestation_insert_and_dedup() {
        let op_pool = OperationPool::<MinimalEthSpec>::new();
        let root = Hash256::repeat_byte(0xaa);
        let slot = Slot::new(1);

        let msg1 = make_payload_attestation_message(slot, 0, root);
        let msg2 = make_payload_attestation_message(slot, 1, root);
        let msg1_dup = make_payload_attestation_message(slot, 0, root);

        op_pool.insert_payload_attestation_message(msg1).unwrap();
        op_pool.insert_payload_attestation_message(msg2).unwrap();
        op_pool
            .insert_payload_attestation_message(msg1_dup)
            .unwrap();

        assert_eq!(op_pool.num_payload_attestation_messages(), 2);
    }

    #[test]
    fn payload_attestation_prune() {
        let op_pool = OperationPool::<MinimalEthSpec>::new();
        let root = Hash256::repeat_byte(0xaa);

        let msg_slot1 = make_payload_attestation_message(Slot::new(1), 0, root);
        let msg_slot2 = make_payload_attestation_message(Slot::new(2), 1, root);
        let msg_slot3 = make_payload_attestation_message(Slot::new(3), 2, root);

        op_pool
            .insert_payload_attestation_message(msg_slot1)
            .unwrap();
        op_pool
            .insert_payload_attestation_message(msg_slot2)
            .unwrap();
        op_pool
            .insert_payload_attestation_message(msg_slot3)
            .unwrap();

        assert_eq!(op_pool.num_payload_attestation_messages(), 3);

        op_pool.prune_payload_attestation_messages(Slot::new(3));
        assert_eq!(op_pool.num_payload_attestation_messages(), 2);

        op_pool.prune_payload_attestation_messages(Slot::new(4));
        assert_eq!(op_pool.num_payload_attestation_messages(), 1);

        op_pool.prune_payload_attestation_messages(Slot::new(5));
        assert_eq!(op_pool.num_payload_attestation_messages(), 0);
    }

    #[tokio::test]
    async fn payload_attestation_packs_bits_from_ptc_positions() {
        let spec = test_spec::<MinimalEthSpec>();
        if spec.gloas_fork_epoch.is_none() {
            return;
        };

        let num_validators = 64;
        let harness = get_harness::<MinimalEthSpec>(num_validators, Some(spec.clone()));

        harness
            .add_attested_blocks_at_slots(
                harness.get_current_state(),
                &[Slot::new(1)],
                (0..num_validators).collect::<Vec<_>>().as_slice(),
            )
            .await;

        let head = harness.chain.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        assert_eq!(state.slot(), Slot::new(1));

        let target_slot = Slot::new(1);
        let parent_root = head.head_block_root();
        let ptc = state.get_ptc(target_slot, &spec).unwrap();
        let ptc_member_0 = ptc.0[0] as u64;
        let ptc_member_1 = ptc.0[1] as u64;

        let op_pool = OperationPool::<MinimalEthSpec>::new();

        let msg0 = make_payload_attestation_message(target_slot, ptc_member_0, parent_root);
        let msg1 = make_payload_attestation_message(target_slot, ptc_member_1, parent_root);
        op_pool.insert_payload_attestation_message(msg0).unwrap();
        op_pool.insert_payload_attestation_message(msg1).unwrap();

        // Advance state to slot 2 so get_payload_attestations looks at slot 1.
        let mut advanced_state = state.clone();
        state_processing::state_advance::complete_state_advance(
            &mut advanced_state,
            None,
            Slot::new(2),
            &spec,
        )
        .unwrap();

        let attestations = op_pool
            .get_payload_attestations(&advanced_state, parent_root, &spec)
            .unwrap();

        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].aggregation_bits.num_set_bits(), 2);
        assert!(attestations[0].aggregation_bits.get(0).unwrap());
        assert!(attestations[0].aggregation_bits.get(1).unwrap());
        assert!(attestations[0].data.payload_present);
    }

    #[tokio::test]
    async fn payload_attestation_multiple_data_combos_capped() {
        let spec = test_spec::<MinimalEthSpec>();
        if spec.gloas_fork_epoch.is_none() {
            return;
        };

        let num_validators = 64;
        let harness = get_harness::<MinimalEthSpec>(num_validators, Some(spec.clone()));

        harness
            .add_attested_blocks_at_slots(
                harness.get_current_state(),
                &[Slot::new(1)],
                (0..num_validators).collect::<Vec<_>>().as_slice(),
            )
            .await;

        let head = harness.chain.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        let target_slot = Slot::new(1);
        let parent_root = head.head_block_root();
        let ptc = state.get_ptc(target_slot, &spec).unwrap();

        let op_pool = OperationPool::<MinimalEthSpec>::new();

        // Given: PTC members vote with all 4 boolean combos, with varying participation.
        let combos: [(bool, bool, &[usize]); 4] = [
            (true, true, &[0, 1, 2]),
            (true, false, &[3, 4]),
            (false, true, &[5]),
            (false, false, &[6]),
        ];
        for (payload_present, blob_available, positions) in &combos {
            for &pos in *positions {
                let validator_index = ptc.0[pos] as u64;
                let msg = make_payload_attestation_message_with_flags(
                    target_slot,
                    validator_index,
                    parent_root,
                    *payload_present,
                    *blob_available,
                );
                op_pool.insert_payload_attestation_message(msg).unwrap();
            }
        }

        // When: we pack attestations for block production at slot 2.
        let mut advanced_state = state.clone();
        state_processing::state_advance::complete_state_advance(
            &mut advanced_state,
            None,
            Slot::new(2),
            &spec,
        )
        .unwrap();
        let attestations = op_pool
            .get_payload_attestations(&advanced_state, parent_root, &spec)
            .unwrap();

        // Then: one attestation per combo, sorted by participation (most first).
        assert_eq!(attestations.len(), 4);
        let bit_counts: Vec<_> = attestations
            .iter()
            .map(|a| a.aggregation_bits.num_set_bits())
            .collect();
        assert_eq!(bit_counts, vec![3, 2, 1, 1]);
    }
}
