mod attestation;
mod attestation_id;
mod attestation_storage;
mod attester_slashing;
mod max_cover;
mod metrics;
mod persistence;
mod reward_cache;
mod sync_aggregate_id;

pub use attestation::AttMaxCover;
pub use attestation_storage::{AttestationRef, SplitAttestation};
pub use max_cover::MaxCover;
pub use persistence::{
    PersistedOperationPool, PersistedOperationPoolV12, PersistedOperationPoolV5,
};
pub use reward_cache::RewardCache;

use crate::attestation_storage::{AttestationMap, CheckpointKey};
use crate::sync_aggregate_id::SyncAggregateId;
use attester_slashing::AttesterSlashingMaxCover;
use max_cover::maximum_cover;
use parking_lot::{RwLock, RwLockWriteGuard};
use state_processing::per_block_processing::errors::AttestationValidationError;
use state_processing::per_block_processing::{
    get_slashable_indices_modular, verify_exit, VerifySignatures,
};
use state_processing::{SigVerifiedOp, VerifyOperation};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::marker::PhantomData;
use std::ptr;
use types::{
    sync_aggregate::Error as SyncAggregateError, typenum::Unsigned, AbstractExecPayload,
    Attestation, AttestationData, AttesterSlashing, BeaconState, BeaconStateError, ChainSpec,
    Epoch, EthSpec, ProposerSlashing, SignedBeaconBlock, SignedBlsToExecutionChange,
    SignedVoluntaryExit, Slot, SyncAggregate, SyncCommitteeContribution, Validator,
};

type SyncContributions<T> = RwLock<HashMap<SyncAggregateId, Vec<SyncCommitteeContribution<T>>>>;

#[derive(Default, Debug)]
pub struct OperationPool<T: EthSpec + Default> {
    /// Map from attestation ID (see below) to vectors of attestations.
    attestations: RwLock<AttestationMap<T>>,
    /// Map from sync aggregate ID to the best `SyncCommitteeContribution`s seen for that ID.
    sync_contributions: SyncContributions<T>,
    /// Set of attester slashings, and the fork version they were verified against.
    attester_slashings: RwLock<HashSet<SigVerifiedOp<AttesterSlashing<T>, T>>>,
    /// Map from proposer index to slashing.
    proposer_slashings: RwLock<HashMap<u64, SigVerifiedOp<ProposerSlashing, T>>>,
    /// Map from exiting validator to their exit data.
    voluntary_exits: RwLock<HashMap<u64, SigVerifiedOp<SignedVoluntaryExit, T>>>,
    /// Map from credential changing validator to their execution change data.
    #[cfg(feature = "withdrawals-processing")]
    bls_to_execution_changes: RwLock<HashMap<u64, SigVerifiedOp<SignedBlsToExecutionChange, T>>>,
    /// Reward cache for accelerating attestation packing.
    reward_cache: RwLock<RewardCache>,
    _phantom: PhantomData<T>,
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

impl<T: EthSpec> OperationPool<T> {
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
        contribution: SyncCommitteeContribution<T>,
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
        state: &BeaconState<T>,
    ) -> Result<Option<SyncAggregate<T>>, OpPoolError> {
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
            contributions.first().map_or(false, |contribution| {
                current_slot <= contribution.slot.saturating_add(Slot::new(1))
            })
        });
    }

    /// Insert an attestation into the pool, aggregating it with existing attestations if possible.
    ///
    /// ## Note
    ///
    /// This function assumes the given `attestation` is valid.
    pub fn insert_attestation(
        &self,
        attestation: Attestation<T>,
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
        all_attestations: &'a AttestationMap<T>,
        state: &'a BeaconState<T>,
        reward_cache: &'a RewardCache,
        total_active_balance: u64,
        validity_filter: impl FnMut(&AttestationRef<'a, T>) -> bool + Send,
        spec: &'a ChainSpec,
    ) -> impl Iterator<Item = AttMaxCover<'a, T>> + Send {
        all_attestations
            .get_attestations(checkpoint_key)
            .filter(|att| {
                att.data.slot + spec.min_attestation_inclusion_delay <= state.slot()
                    && state.slot() <= att.data.slot + T::slots_per_epoch()
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
        state: &BeaconState<T>,
        prev_epoch_validity_filter: impl for<'a> FnMut(&AttestationRef<'a, T>) -> bool + Send,
        curr_epoch_validity_filter: impl for<'a> FnMut(&AttestationRef<'a, T>) -> bool + Send,
        spec: &ChainSpec,
    ) -> Result<Vec<Attestation<T>>, OpPoolError> {
        // Attestations for the current fork, which may be from the current or previous epoch.
        let (prev_epoch_key, curr_epoch_key) = CheckpointKey::keys_for_state(state);
        let all_attestations = self.attestations.read();
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

        let prev_epoch_limit = if let BeaconState::Base(base_state) = state {
            std::cmp::min(
                T::MaxPendingAttestations::to_usize()
                    .saturating_sub(base_state.previous_epoch_attestations.len()),
                T::MaxAttestations::to_usize(),
            )
        } else {
            T::MaxAttestations::to_usize()
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
                maximum_cover(
                    curr_epoch_att,
                    T::MaxAttestations::to_usize(),
                    "curr_epoch_attestations",
                )
            },
        );

        metrics::set_gauge(&metrics::NUM_PREV_EPOCH_ATTESTATIONS, num_prev_valid);
        metrics::set_gauge(&metrics::NUM_CURR_EPOCH_ATTESTATIONS, num_curr_valid);

        Ok(max_cover::merge_solutions(
            curr_cover,
            prev_cover,
            T::MaxAttestations::to_usize(),
        ))
    }

    /// Remove attestations which are too old to be included in a block.
    pub fn prune_attestations(&self, current_epoch: Epoch) {
        self.attestations.write().prune(current_epoch);
    }

    /// Insert a proposer slashing into the pool.
    pub fn insert_proposer_slashing(
        &self,
        verified_proposer_slashing: SigVerifiedOp<ProposerSlashing, T>,
    ) {
        self.proposer_slashings.write().insert(
            verified_proposer_slashing.as_inner().proposer_index(),
            verified_proposer_slashing,
        );
    }

    /// Insert an attester slashing into the pool.
    pub fn insert_attester_slashing(
        &self,
        verified_slashing: SigVerifiedOp<AttesterSlashing<T>, T>,
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
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> (
        Vec<ProposerSlashing>,
        Vec<AttesterSlashing<T>>,
        Vec<SignedVoluntaryExit>,
    ) {
        let proposer_slashings = filter_limit_operations(
            self.proposer_slashings.read().values(),
            |slashing| {
                slashing.signature_is_still_valid(&state.fork())
                    && state
                        .validators()
                        .get(slashing.as_inner().signed_header_1.message.proposer_index as usize)
                        .map_or(false, |validator| !validator.slashed)
            },
            |slashing| slashing.as_inner().clone(),
            T::MaxProposerSlashings::to_usize(),
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
        state: &BeaconState<T>,
        to_be_slashed: &mut HashSet<u64>,
    ) -> Vec<AttesterSlashing<T>> {
        let reader = self.attester_slashings.read();

        let relevant_attester_slashings = reader.iter().flat_map(|slashing| {
            if slashing.signature_is_still_valid(&state.fork()) {
                AttesterSlashingMaxCover::new(slashing.as_inner(), to_be_slashed, state)
            } else {
                None
            }
        });

        maximum_cover(
            relevant_attester_slashings,
            T::MaxAttesterSlashings::to_usize(),
            "attester_slashings",
        )
        .into_iter()
        .map(|cover| {
            to_be_slashed.extend(cover.covering_set().keys());
            cover.intermediate().clone()
        })
        .collect()
    }

    /// Prune proposer slashings for validators which are exited in the finalized epoch.
    pub fn prune_proposer_slashings(&self, head_state: &BeaconState<T>) {
        prune_validator_hash_map(
            &mut self.proposer_slashings.write(),
            |_, validator| validator.exit_epoch <= head_state.finalized_checkpoint().epoch,
            head_state,
        );
    }

    /// Prune attester slashings for all slashed or withdrawn validators, or attestations on another
    /// fork.
    pub fn prune_attester_slashings(&self, head_state: &BeaconState<T>) {
        self.attester_slashings.write().retain(|slashing| {
            // Check that the attestation's signature is still valid wrt the fork version.
            let signature_ok = slashing.signature_is_still_valid(&head_state.fork());
            // Slashings that don't slash any validators can also be dropped.
            let slashing_ok =
                get_slashable_indices_modular(head_state, slashing.as_inner(), |_, validator| {
                    // Declare that a validator is still slashable if they have not exited prior
                    // to the finalized epoch.
                    //
                    // We cannot check the `slashed` field since the `head` is not finalized and
                    // a fork could un-slash someone.
                    validator.exit_epoch > head_state.finalized_checkpoint().epoch
                })
                .map_or(false, |indices| !indices.is_empty());

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
    pub fn insert_voluntary_exit(&self, exit: SigVerifiedOp<SignedVoluntaryExit, T>) {
        self.voluntary_exits
            .write()
            .insert(exit.as_inner().message.validator_index, exit);
    }

    /// Get a list of voluntary exits for inclusion in a block.
    fn get_voluntary_exits<F>(
        &self,
        state: &BeaconState<T>,
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
                    && verify_exit(state, exit.as_inner(), VerifySignatures::False, spec).is_ok()
            },
            |exit| exit.as_inner().clone(),
            T::MaxVoluntaryExits::to_usize(),
        )
    }

    /// Prune if validator has already exited at or before the finalized checkpoint of the head.
    pub fn prune_voluntary_exits(&self, head_state: &BeaconState<T>) {
        prune_validator_hash_map(
            &mut self.voluntary_exits.write(),
            // This condition is slightly too loose, since there will be some finalized exits that
            // are missed here.
            //
            // We choose simplicity over the gain of pruning more exits since they are small and
            // should not be seen frequently.
            |_, validator| validator.exit_epoch <= head_state.finalized_checkpoint().epoch,
            head_state,
        );
    }

    /// Insert a BLS to execution change into the pool.
    pub fn insert_bls_to_execution_change(
        &self,
        verified_change: SigVerifiedOp<SignedBlsToExecutionChange, T>,
    ) {
        #[cfg(feature = "withdrawals-processing")]
        {
            self.bls_to_execution_changes.write().insert(
                verified_change.as_inner().message.validator_index,
                verified_change,
            );
        }
        #[cfg(not(feature = "withdrawals-processing"))]
        {
            drop(verified_change);
        }
    }

    /// Get a list of execution changes for inclusion in a block.
    ///
    /// They're in random `HashMap` order, which isn't exactly fair, but isn't unfair either.
    pub fn get_bls_to_execution_changes(
        &self,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Vec<SignedBlsToExecutionChange> {
        #[cfg(feature = "withdrawals-processing")]
        {
            filter_limit_operations(
                self.bls_to_execution_changes.read().values(),
                |address_change| {
                    address_change.signature_is_still_valid(&state.fork())
                        && state
                            .get_validator(
                                address_change.as_inner().message.validator_index as usize,
                            )
                            .map_or(false, |validator| {
                                !validator.has_eth1_withdrawal_credential(spec)
                            })
                },
                |address_change| address_change.as_inner().clone(),
                T::MaxBlsToExecutionChanges::to_usize(),
            )
        }

        // TODO: remove this whole block once withdrwals-processing is removed
        #[cfg(not(feature = "withdrawals-processing"))]
        {
            #[allow(clippy::drop_copy)]
            drop((state, spec));
            vec![]
        }
    }

    /// Prune BLS to execution changes that have been applied to the state more than 1 block ago.
    ///
    /// The block check is necessary to avoid pruning too eagerly and losing the ability to include
    /// address changes during re-orgs. This is isn't *perfect* so some address changes could
    /// still get stuck if there are gnarly re-orgs and the changes can't be widely republished
    /// due to the gossip duplicate rules.
    pub fn prune_bls_to_execution_changes<Payload: AbstractExecPayload<T>>(
        &self,
        head_block: &SignedBeaconBlock<T, Payload>,
        head_state: &BeaconState<T>,
        spec: &ChainSpec,
    ) {
        #[cfg(feature = "withdrawals-processing")]
        {
            prune_validator_hash_map(
                &mut self.bls_to_execution_changes.write(),
                |validator_index, validator| {
                    validator.has_eth1_withdrawal_credential(spec)
                        && head_block
                            .message()
                            .body()
                            .bls_to_execution_changes()
                            .map_or(true, |recent_changes| {
                                !recent_changes
                                    .iter()
                                    .any(|c| c.message.validator_index == validator_index)
                            })
                },
                head_state,
            );
        }

        // TODO: remove this whole block once withdrwals-processing is removed
        #[cfg(not(feature = "withdrawals-processing"))]
        {
            #[allow(clippy::drop_copy)]
            drop((head_block, head_state, spec));
        }
    }

    /// Prune all types of transactions given the latest head state and head fork.
    pub fn prune_all<Payload: AbstractExecPayload<T>>(
        &self,
        head_block: &SignedBeaconBlock<T, Payload>,
        head_state: &BeaconState<T>,
        current_epoch: Epoch,
        spec: &ChainSpec,
    ) {
        self.prune_attestations(current_epoch);
        self.prune_sync_contributions(head_state.slot());
        self.prune_proposer_slashings(head_state);
        self.prune_attester_slashings(head_state);
        self.prune_voluntary_exits(head_state);
        self.prune_bls_to_execution_changes(head_block, head_state, spec);
    }

    /// Total number of voluntary exits in the pool.
    pub fn num_voluntary_exits(&self) -> usize {
        self.voluntary_exits.read().len()
    }

    /// Returns all known `Attestation` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_attestations(&self) -> Vec<Attestation<T>> {
        self.attestations
            .read()
            .iter()
            .map(|att| att.clone_as_attestation())
            .collect()
    }

    /// Returns all known `Attestation` objects that pass the provided filter.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_filtered_attestations<F>(&self, filter: F) -> Vec<Attestation<T>>
    where
        F: Fn(&AttestationData) -> bool,
    {
        self.attestations
            .read()
            .iter()
            .filter(|att| filter(&att.attestation_data()))
            .map(|att| att.clone_as_attestation())
            .collect()
    }

    /// Returns all known `AttesterSlashing` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_attester_slashings(&self) -> Vec<AttesterSlashing<T>> {
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
            .iter()
            .map(|(_, slashing)| slashing.as_inner().clone())
            .collect()
    }

    /// Returns all known `SignedVoluntaryExit` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_voluntary_exits(&self) -> Vec<SignedVoluntaryExit> {
        self.voluntary_exits
            .read()
            .iter()
            .map(|(_, exit)| exit.as_inner().clone())
            .collect()
    }

    /// Returns all known `SignedBlsToExecutionChange` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_bls_to_execution_changes(&self) -> Vec<SignedBlsToExecutionChange> {
        #[cfg(feature = "withdrawals-processing")]
        {
            self.bls_to_execution_changes
                .read()
                .iter()
                .map(|(_, address_change)| address_change.as_inner().clone())
                .collect()
        }

        #[cfg(not(feature = "withdrawals-processing"))]
        vec![]
    }
}

/// Filter up to a maximum number of operations out of an iterator.
fn filter_limit_operations<'a, T: 'a, V: 'a, I, F, G>(
    operations: I,
    filter: F,
    mapping: G,
    limit: usize,
) -> Vec<V>
where
    I: IntoIterator<Item = &'a T>,
    F: Fn(&T) -> bool,
    G: Fn(&T) -> V,
    T: Clone,
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
    head_state: &BeaconState<E>,
) where
    F: Fn(u64, &Validator) -> bool,
    T: VerifyOperation<E>,
{
    map.retain(|&validator_index, op| {
        op.signature_is_still_valid(&head_state.fork())
            && head_state
                .validators()
                .get(validator_index as usize)
                .map_or(true, |validator| !prune_if(validator_index, validator))
    });
}

/// Compare two operation pools.
impl<T: EthSpec + Default> PartialEq for OperationPool<T> {
    fn eq(&self, other: &Self) -> bool {
        if ptr::eq(self, other) {
            return true;
        }
        *self.attestations.read() == *other.attestations.read()
            && *self.sync_contributions.read() == *other.sync_contributions.read()
            && *self.attester_slashings.read() == *other.attester_slashings.read()
            && *self.proposer_slashings.read() == *other.proposer_slashings.read()
            && *self.voluntary_exits.read() == *other.voluntary_exits.read()
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod release_tests {
    use super::attestation::earliest_attestation_validators;
    use super::*;
    use beacon_chain::test_utils::{
        test_spec, BeaconChainHarness, EphemeralHarnessType, RelativeSyncCommittee,
    };
    use lazy_static::lazy_static;
    use maplit::hashset;
    use state_processing::{common::get_attesting_indices_from_state, VerifyOperation};
    use std::collections::BTreeSet;
    use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
    use types::*;

    pub const MAX_VALIDATOR_COUNT: usize = 4 * 32 * 128;

    lazy_static! {
        /// A cached set of keys.
        static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(MAX_VALIDATOR_COUNT);
    }

    fn get_harness<E: EthSpec>(
        validator_count: usize,
        spec: Option<ChainSpec>,
    ) -> BeaconChainHarness<EphemeralHarnessType<E>> {
        let harness = BeaconChainHarness::builder(E::default())
            .spec_or_default(spec)
            .keypairs(KEYPAIRS[0..validator_count].to_vec())
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        harness.advance_slot();

        harness
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
                Hash256::zero(),
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
        if spec.altair_fork_epoch != None {
            return;
        }

        let mut state = harness.get_current_state();
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
            Hash256::zero(),
            SignedBeaconBlockHash::from(Hash256::zero()),
            slot,
        );

        for (atts, aggregate) in &attestations {
            let att2 = aggregate.as_ref().unwrap().message.aggregate.clone();

            let att1 = atts
                .into_iter()
                .map(|(att, _)| att)
                .take(2)
                .fold::<Option<Attestation<MainnetEthSpec>>, _>(None, |att, new_att| {
                    if let Some(mut a) = att {
                        a.aggregate(&new_att);
                        Some(a)
                    } else {
                        Some(new_att.clone())
                    }
                })
                .unwrap();

            let att1_indices = get_attesting_indices_from_state(&state, &att1).unwrap();
            let att2_indices = get_attesting_indices_from_state(&state, &att2).unwrap();
            let att1_split = SplitAttestation::new(att1.clone(), att1_indices);
            let att2_split = SplitAttestation::new(att2.clone(), att2_indices);

            assert_eq!(
                att1.aggregation_bits.num_set_bits(),
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
                    aggregation_bits: att1.aggregation_bits.clone(),
                    data: att1.data.clone(),
                    inclusion_delay: 0,
                    proposer_index: 0,
                })
                .unwrap();

            assert_eq!(
                committees.get(0).unwrap().committee.len() - 2,
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
        let mut state = harness.get_current_state();

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
            Hash256::zero(),
            SignedBeaconBlockHash::from(Hash256::zero()),
            slot,
        );

        for (atts, _) in attestations {
            for (att, _) in atts {
                let attesting_indices = get_attesting_indices_from_state(&state, &att).unwrap();
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
            agg_att.aggregation_bits.num_set_bits(),
            spec.target_committee_size as usize
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

        let state = harness.get_current_state();

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
            Hash256::zero(),
            SignedBeaconBlockHash::from(Hash256::zero()),
            slot,
        );

        for (_, aggregate) in attestations {
            let att = aggregate.unwrap().message.aggregate;
            let attesting_indices = get_attesting_indices_from_state(&state, &att).unwrap();
            op_pool
                .insert_attestation(att.clone(), attesting_indices.clone())
                .unwrap();
            op_pool.insert_attestation(att, attesting_indices).unwrap();
        }

        assert_eq!(op_pool.num_attestations(), committees.len());
    }

    /// Adding lots of attestations that only intersect pairwise should lead to two aggregate
    /// attestations.
    #[test]
    fn attestation_pairwise_overlapping() {
        let (harness, ref spec) = attestation_test_state::<MainnetEthSpec>(1);

        let state = harness.get_current_state();

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
            Hash256::zero(),
            SignedBeaconBlockHash::from(Hash256::zero()),
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
                    let agg = chunk.into_iter().map(|(att, _)| att).fold::<Option<
                        Attestation<MainnetEthSpec>,
                    >, _>(
                        None,
                        |att, new_att| {
                            if let Some(mut a) = att {
                                a.aggregate(new_att);
                                Some(a)
                            } else {
                                Some(new_att.clone())
                            }
                        },
                    );
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
                    let agg = chunk.into_iter().map(|(att, _)| att).fold::<Option<
                        Attestation<MainnetEthSpec>,
                    >, _>(
                        None,
                        |att, new_att| {
                            if let Some(mut a) = att {
                                a.aggregate(new_att);
                                Some(a)
                            } else {
                                Some(new_att.clone())
                            }
                        },
                    );
                    agg.unwrap()
                })
                .collect::<Vec<_>>();

            for att in aggs1.into_iter().chain(aggs2.into_iter()) {
                let attesting_indices = get_attesting_indices_from_state(&state, &att).unwrap();
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

        let mut state = harness.get_current_state();

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slot = state.slot();
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        let max_attestations = <MainnetEthSpec as EthSpec>::MaxAttestations::to_usize();
        let target_committee_size = spec.target_committee_size as usize;
        let num_validators = num_committees
            * MainnetEthSpec::slots_per_epoch() as usize
            * spec.target_committee_size;

        let attestations = harness.make_attestations(
            (0..num_validators).collect::<Vec<_>>().as_slice(),
            &state,
            Hash256::zero(),
            SignedBeaconBlockHash::from(Hash256::zero()),
            slot,
        );

        let insert_attestations = |attestations: Vec<(Attestation<MainnetEthSpec>, SubnetId)>,
                                   step_size| {
            let att_0 = attestations.get(0).unwrap().0.clone();
            let aggs = attestations
                .chunks_exact(step_size)
                .map(|chunk| {
                    chunk
                        .into_iter()
                        .map(|(att, _)| att)
                        .fold::<Attestation<MainnetEthSpec>, _>(
                            att_0.clone(),
                            |mut att, new_att| {
                                att.aggregate(new_att);
                                att
                            },
                        )
                })
                .collect::<Vec<_>>();

            for att in aggs {
                let attesting_indices = get_attesting_indices_from_state(&state, &att).unwrap();
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
        assert_eq!(stats.num_attestation_data, committees.len());
        assert_eq!(
            stats.num_attestations,
            (num_small + num_big) * committees.len()
        );
        assert!(stats.num_attestations > max_attestations);

        *state.slot_mut() += spec.min_attestation_inclusion_delay;
        let best_attestations = op_pool
            .get_attestations(&state, |_| true, |_| true, spec)
            .expect("should have best attestations");
        assert_eq!(best_attestations.len(), max_attestations);

        // All the best attestations should be signed by at least `big_step_size` (4) validators.
        for att in &best_attestations {
            assert!(att.aggregation_bits.num_set_bits() >= big_step_size);
        }
    }

    #[test]
    fn attestation_rewards() {
        let small_step_size = 2;
        let big_step_size = 4;
        let num_committees = big_step_size;

        let (harness, ref spec) = attestation_test_state::<MainnetEthSpec>(num_committees);

        let mut state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();

        let slot = state.slot();
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        let max_attestations = <MainnetEthSpec as EthSpec>::MaxAttestations::to_usize();
        let target_committee_size = spec.target_committee_size as usize;

        // Each validator will have a multiple of 1_000_000_000 wei.
        // Safe from overflow unless there are about 18B validators (2^64 / 1_000_000_000).
        for i in 0..state.validators().len() {
            state.validators_mut()[i].effective_balance = 1_000_000_000 * i as u64;
        }

        let num_validators = num_committees
            * MainnetEthSpec::slots_per_epoch() as usize
            * spec.target_committee_size;
        let attestations = harness.make_attestations(
            (0..num_validators).collect::<Vec<_>>().as_slice(),
            &state,
            Hash256::zero(),
            SignedBeaconBlockHash::from(Hash256::zero()),
            slot,
        );

        let insert_attestations = |attestations: Vec<(Attestation<MainnetEthSpec>, SubnetId)>,
                                   step_size| {
            let att_0 = attestations.get(0).unwrap().0.clone();
            let aggs = attestations
                .chunks_exact(step_size)
                .map(|chunk| {
                    chunk
                        .into_iter()
                        .map(|(att, _)| att)
                        .fold::<Attestation<MainnetEthSpec>, _>(
                            att_0.clone(),
                            |mut att, new_att| {
                                att.aggregate(new_att);
                                att
                            },
                        )
                })
                .collect::<Vec<_>>();

            for att in aggs {
                let attesting_indices = get_attesting_indices_from_state(&state, &att).unwrap();
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

        assert_eq!(
            op_pool.attestation_stats().num_attestation_data,
            committees.len()
        );
        assert_eq!(
            op_pool.num_attestations(),
            (num_small + num_big) * committees.len()
        );
        assert!(op_pool.num_attestations() > max_attestations);

        *state.slot_mut() += spec.min_attestation_inclusion_delay;
        let best_attestations = op_pool
            .get_attestations(&state, |_| true, |_| true, spec)
            .expect("should have valid best attestations");
        assert_eq!(best_attestations.len(), max_attestations);

        let total_active_balance = state.get_total_active_balance().unwrap();

        // Set of indices covered by previous attestations in `best_attestations`.
        let mut seen_indices = BTreeSet::<u64>::new();
        // Used for asserting that rewards are in decreasing order.
        let mut prev_reward = u64::max_value();

        let mut reward_cache = RewardCache::default();
        reward_cache.update(&state).unwrap();

        for att in best_attestations {
            let attesting_indices = get_attesting_indices_from_state(&state, &att).unwrap();
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
            let rewards = fresh_validators_rewards.values().sum();
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
        assert_eq!(best_slashings.1, vec![slashing_4, slashing_3]);
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
        assert_eq!(best_slashings.1, vec![slashing_1, slashing_3]);
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
        assert_eq!(best_slashings.1, vec![a_slashing_1, a_slashing_3]);
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
        assert_eq!(best_slashings.1, vec![slashing_1, slashing_3]);
    }

    // Max coverage should be affected by the overall effective balances
    #[test]
    fn max_coverage_effective_balances() {
        let harness = get_harness(32, None);
        let spec = &harness.spec;
        let mut state = harness.get_current_state();
        let op_pool = OperationPool::<MainnetEthSpec>::new();
        state.validators_mut()[1].effective_balance = 17_000_000_000;
        state.validators_mut()[2].effective_balance = 17_000_000_000;
        state.validators_mut()[3].effective_balance = 17_000_000_000;

        let slashing_1 = harness.make_attester_slashing(vec![1, 2, 3]);
        let slashing_2 = harness.make_attester_slashing(vec![4, 5, 6]);
        let slashing_3 = harness.make_attester_slashing(vec![7, 8]);

        op_pool.insert_attester_slashing(slashing_1.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_2.clone().validate(&state, spec).unwrap());
        op_pool.insert_attester_slashing(slashing_3.clone().validate(&state, spec).unwrap());

        let best_slashings = op_pool.get_slashings_and_exits(&state, &harness.spec);
        assert_eq!(best_slashings.1, vec![slashing_2, slashing_3]);
    }

    /// End-to-end test of basic sync contribution handling.
    #[tokio::test]
    async fn sync_contribution_aggregation_insert_get_prune() {
        let (harness, _) = sync_contribution_test_state::<MainnetEthSpec>(1).await;

        let op_pool = OperationPool::<MainnetEthSpec>::new();
        let state = harness.get_current_state();

        let block_root = *state
            .get_block_root(state.slot() - Slot::new(1))
            .ok()
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
            .ok()
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
            .ok()
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
            .ok()
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
        let mut spec = test_spec::<E>();

        // Give some room to sign surround slashings.
        spec.altair_fork_epoch = Some(Epoch::new(3));
        spec.bellatrix_fork_epoch = Some(Epoch::new(6));

        // To make exits immediately valid.
        spec.shard_committee_period = 0;

        let num_validators = 32;

        let harness = get_harness::<E>(num_validators, Some(spec.clone()));
        (harness, spec)
    }

    /// Test several cross-fork voluntary exits:
    ///
    /// - phase0 exit (not valid after Bellatrix)
    /// - phase0 exit signed with Altair fork version (only valid after Bellatrix)
    #[tokio::test]
    async fn cross_fork_exits() {
        let (harness, spec) = cross_fork_harness::<MainnetEthSpec>();
        let altair_fork_epoch = spec.altair_fork_epoch.unwrap();
        let bellatrix_fork_epoch = spec.bellatrix_fork_epoch.unwrap();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        // Sign an exit in phase0 with a phase0 epoch.
        let exit1 = harness.make_voluntary_exit(0, Epoch::new(0));

        // Advance to Altair.
        harness
            .extend_to_slot(altair_fork_epoch.start_slot(slots_per_epoch))
            .await;
        let altair_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(altair_head.beacon_state.current_epoch(), altair_fork_epoch);

        // Add exit 1 to the op pool during Altair. It's still valid at this point and should be
        // returned.
        let verified_exit1 = exit1
            .clone()
            .validate(&altair_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_voluntary_exit(verified_exit1);
        let exits =
            op_pool.get_voluntary_exits(&altair_head.beacon_state, |_| true, &harness.chain.spec);
        assert!(exits.contains(&exit1));
        assert_eq!(exits.len(), 1);

        // Advance to Bellatrix.
        harness
            .extend_to_slot(bellatrix_fork_epoch.start_slot(slots_per_epoch))
            .await;
        let bellatrix_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(
            bellatrix_head.beacon_state.current_epoch(),
            bellatrix_fork_epoch
        );

        // Sign an exit with the Altair domain and a phase0 epoch. This is a weird type of exit
        // that is valid because after the Bellatrix fork we'll use the Altair fork domain to verify
        // all prior epochs.
        let exit2 = harness.make_voluntary_exit(2, Epoch::new(0));
        let verified_exit2 = exit2
            .clone()
            .validate(&bellatrix_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_voluntary_exit(verified_exit2);

        // Attempting to fetch exit1 now should fail, despite it still being in the pool.
        // exit2 should still be valid, because it was signed with the Altair fork domain.
        assert_eq!(op_pool.voluntary_exits.read().len(), 2);
        let exits =
            op_pool.get_voluntary_exits(&bellatrix_head.beacon_state, |_| true, &harness.spec);
        assert_eq!(&exits, &[exit2]);
    }

    /// Test several cross-fork proposer slashings:
    ///
    /// - phase0 slashing (not valid after Bellatrix)
    /// - Bellatrix signed with Altair fork version (not valid after Bellatrix)
    /// - phase0 exit signed with Altair fork version (only valid after Bellatrix)
    #[tokio::test]
    async fn cross_fork_proposer_slashings() {
        let (harness, spec) = cross_fork_harness::<MainnetEthSpec>();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        let altair_fork_epoch = spec.altair_fork_epoch.unwrap();
        let bellatrix_fork_epoch = spec.bellatrix_fork_epoch.unwrap();
        let bellatrix_fork_slot = bellatrix_fork_epoch.start_slot(slots_per_epoch);

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        // Sign a proposer slashing in phase0 with a phase0 epoch.
        let slashing1 = harness.make_proposer_slashing_at_slot(0, Some(Slot::new(1)));

        // Advance to Altair.
        harness
            .extend_to_slot(altair_fork_epoch.start_slot(slots_per_epoch))
            .await;
        let altair_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(altair_head.beacon_state.current_epoch(), altair_fork_epoch);

        // Add slashing1 to the op pool during Altair. It's still valid at this point and should be
        // returned.
        let verified_slashing1 = slashing1
            .clone()
            .validate(&altair_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_proposer_slashing(verified_slashing1);
        let (proposer_slashings, _, _) =
            op_pool.get_slashings_and_exits(&altair_head.beacon_state, &harness.chain.spec);
        assert!(proposer_slashings.contains(&slashing1));
        assert_eq!(proposer_slashings.len(), 1);

        // Sign a proposer slashing with a Bellatrix slot using the Altair fork domain.
        //
        // This slashing is valid only before the Bellatrix fork epoch.
        let slashing2 = harness.make_proposer_slashing_at_slot(1, Some(bellatrix_fork_slot));
        let verified_slashing2 = slashing2
            .clone()
            .validate(&altair_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_proposer_slashing(verified_slashing2);
        let (proposer_slashings, _, _) =
            op_pool.get_slashings_and_exits(&altair_head.beacon_state, &harness.chain.spec);
        assert!(proposer_slashings.contains(&slashing1));
        assert!(proposer_slashings.contains(&slashing2));
        assert_eq!(proposer_slashings.len(), 2);

        // Advance to Bellatrix.
        harness.extend_to_slot(bellatrix_fork_slot).await;
        let bellatrix_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(
            bellatrix_head.beacon_state.current_epoch(),
            bellatrix_fork_epoch
        );

        // Sign a proposer slashing with the Altair domain and a phase0 slot. This is a weird type
        // of slashing that is only valid after the Bellatrix fork because we'll use the Altair fork
        // domain to verify all prior epochs.
        let slashing3 = harness.make_proposer_slashing_at_slot(2, Some(Slot::new(1)));
        let verified_slashing3 = slashing3
            .clone()
            .validate(&bellatrix_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_proposer_slashing(verified_slashing3);

        // Attempting to fetch slashing1 now should fail, despite it still being in the pool.
        // Likewise slashing2 is also invalid now because it should be signed with the
        // Bellatrix fork version.
        // slashing3 should still be valid, because it was signed with the Altair fork domain.
        assert_eq!(op_pool.proposer_slashings.read().len(), 3);
        let (proposer_slashings, _, _) =
            op_pool.get_slashings_and_exits(&bellatrix_head.beacon_state, &harness.spec);
        assert!(proposer_slashings.contains(&slashing3));
        assert_eq!(proposer_slashings.len(), 1);
    }

    /// Test several cross-fork attester slashings:
    ///
    /// - both target epochs in phase0 (not valid after Bellatrix)
    /// - both target epochs in Bellatrix but signed with Altair domain (not valid after Bellatrix)
    /// - Altair attestation that surrounds a phase0 attestation (not valid after Bellatrix)
    /// - both target epochs in phase0 but signed with Altair domain (only valid after Bellatrix)
    #[tokio::test]
    async fn cross_fork_attester_slashings() {
        let (harness, spec) = cross_fork_harness::<MainnetEthSpec>();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        let zero_epoch = Epoch::new(0);
        let altair_fork_epoch = spec.altair_fork_epoch.unwrap();
        let bellatrix_fork_epoch = spec.bellatrix_fork_epoch.unwrap();
        let bellatrix_fork_slot = bellatrix_fork_epoch.start_slot(slots_per_epoch);

        let op_pool = OperationPool::<MainnetEthSpec>::new();

        // Sign an attester slashing with the phase0 fork version, with both target epochs in phase0.
        let slashing1 = harness.make_attester_slashing_with_epochs(
            vec![0],
            None,
            Some(zero_epoch),
            None,
            Some(zero_epoch),
        );

        // Advance to Altair.
        harness
            .extend_to_slot(altair_fork_epoch.start_slot(slots_per_epoch))
            .await;
        let altair_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(altair_head.beacon_state.current_epoch(), altair_fork_epoch);

        // Add slashing1 to the op pool during Altair. It's still valid at this point and should be
        // returned.
        let verified_slashing1 = slashing1
            .clone()
            .validate(&altair_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_attester_slashing(verified_slashing1);

        // Sign an attester slashing with two Bellatrix epochs using the Altair fork domain.
        //
        // This slashing is valid only before the Bellatrix fork epoch.
        let slashing2 = harness.make_attester_slashing_with_epochs(
            vec![1],
            None,
            Some(bellatrix_fork_epoch),
            None,
            Some(bellatrix_fork_epoch),
        );
        let verified_slashing2 = slashing2
            .clone()
            .validate(&altair_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_attester_slashing(verified_slashing2);
        let (_, attester_slashings, _) =
            op_pool.get_slashings_and_exits(&altair_head.beacon_state, &harness.chain.spec);
        assert!(attester_slashings.contains(&slashing1));
        assert!(attester_slashings.contains(&slashing2));
        assert_eq!(attester_slashings.len(), 2);

        // Sign an attester slashing where an Altair attestation surrounds a phase0 one.
        //
        // This slashing is valid only before the Bellatrix fork epoch.
        let slashing3 = harness.make_attester_slashing_with_epochs(
            vec![2],
            Some(Epoch::new(0)),
            Some(altair_fork_epoch),
            Some(Epoch::new(1)),
            Some(altair_fork_epoch - 1),
        );
        let verified_slashing3 = slashing3
            .clone()
            .validate(&altair_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_attester_slashing(verified_slashing3);

        // All three slashings should be valid and returned from the pool at this point.
        // Seeing as we can only extract 2 at time we'll just pretend that validator 0 is already
        // slashed.
        let mut to_be_slashed = hashset! {0};
        let attester_slashings =
            op_pool.get_attester_slashings(&altair_head.beacon_state, &mut to_be_slashed);
        assert!(attester_slashings.contains(&slashing2));
        assert!(attester_slashings.contains(&slashing3));
        assert_eq!(attester_slashings.len(), 2);

        // Advance to Bellatrix.
        harness.extend_to_slot(bellatrix_fork_slot).await;
        let bellatrix_head = harness.chain.canonical_head.cached_head().snapshot;
        assert_eq!(
            bellatrix_head.beacon_state.current_epoch(),
            bellatrix_fork_epoch
        );

        // Sign an attester slashing with the Altair domain and phase0 epochs. This is a weird type
        // of slashing that is only valid after the Bellatrix fork because we'll use the Altair fork
        // domain to verify all prior epochs.
        let slashing4 = harness.make_attester_slashing_with_epochs(
            vec![3],
            Some(Epoch::new(0)),
            Some(altair_fork_epoch - 1),
            Some(Epoch::new(0)),
            Some(altair_fork_epoch - 1),
        );
        let verified_slashing4 = slashing4
            .clone()
            .validate(&bellatrix_head.beacon_state, &harness.chain.spec)
            .unwrap();
        op_pool.insert_attester_slashing(verified_slashing4);

        // All slashings except slashing4 are now invalid (despite being present in the pool).
        assert_eq!(op_pool.attester_slashings.read().len(), 4);
        let (_, attester_slashings, _) =
            op_pool.get_slashings_and_exits(&bellatrix_head.beacon_state, &harness.spec);
        assert!(attester_slashings.contains(&slashing4));
        assert_eq!(attester_slashings.len(), 1);

        // Pruning the attester slashings should remove all but slashing4.
        op_pool.prune_attester_slashings(&bellatrix_head.beacon_state);
        assert_eq!(op_pool.attester_slashings.read().len(), 1);
    }
}
