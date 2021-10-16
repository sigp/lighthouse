mod attestation;
mod attestation_id;
mod attester_slashing;
mod max_cover;
mod metrics;
mod persistence;
mod sync_aggregate_id;

pub use persistence::{
    PersistedOperationPool, PersistedOperationPoolAltair, PersistedOperationPoolBase,
};

use crate::sync_aggregate_id::SyncAggregateId;
use attestation::AttMaxCover;
use attestation_id::AttestationId;
use attester_slashing::AttesterSlashingMaxCover;
use max_cover::{maximum_cover, MaxCover};
use parking_lot::RwLock;
use state_processing::per_block_processing::errors::AttestationValidationError;
use state_processing::per_block_processing::{
    get_slashable_indices_modular, verify_attestation_for_block_inclusion, verify_exit,
    VerifySignatures,
};
use state_processing::SigVerifiedOp;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::marker::PhantomData;
use std::ptr;
use types::{
    sync_aggregate::Error as SyncAggregateError, typenum::Unsigned, Attestation, AttesterSlashing,
    BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, Fork, ForkVersion, Hash256,
    ProposerSlashing, SignedVoluntaryExit, Slot, SyncAggregate, SyncCommitteeContribution,
    Validator,
};

type SyncContributions<T> = RwLock<HashMap<SyncAggregateId, Vec<SyncCommitteeContribution<T>>>>;

#[derive(Default, Debug)]
pub struct OperationPool<T: EthSpec + Default> {
    /// Map from attestation ID (see below) to vectors of attestations.
    attestations: RwLock<HashMap<AttestationId, Vec<Attestation<T>>>>,
    /// Map from sync aggregate ID to the best `SyncCommitteeContribution`s seen for that ID.
    sync_contributions: SyncContributions<T>,
    /// Set of attester slashings, and the fork version they were verified against.
    attester_slashings: RwLock<HashSet<(AttesterSlashing<T>, ForkVersion)>>,
    /// Map from proposer index to slashing.
    proposer_slashings: RwLock<HashMap<u64, ProposerSlashing>>,
    /// Map from exiting validator to their exit data.
    voluntary_exits: RwLock<HashMap<u64, SignedVoluntaryExit>>,
    _phantom: PhantomData<T>,
}

#[derive(Debug, PartialEq)]
pub enum OpPoolError {
    GetAttestationsTotalBalanceError(BeaconStateError),
    GetBlockRootError(BeaconStateError),
    SyncAggregateError(SyncAggregateError),
    IncorrectOpPoolVariant,
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
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), AttestationValidationError> {
        let id = AttestationId::from_data(&attestation.data, fork, genesis_validators_root, spec);

        // Take a write lock on the attestations map.
        let mut attestations = self.attestations.write();

        let existing_attestations = match attestations.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(vec![attestation]);
                return Ok(());
            }
            Entry::Occupied(entry) => entry.into_mut(),
        };

        let mut aggregated = false;
        for existing_attestation in existing_attestations.iter_mut() {
            if existing_attestation.signers_disjoint_from(&attestation) {
                existing_attestation.aggregate(&attestation);
                aggregated = true;
            } else if *existing_attestation == attestation {
                aggregated = true;
            }
        }

        if !aggregated {
            existing_attestations.push(attestation);
        }

        Ok(())
    }

    /// Total number of attestations in the pool, including attestations for the same data.
    pub fn num_attestations(&self) -> usize {
        self.attestations.read().values().map(Vec::len).sum()
    }

    /// Return all valid attestations for the given epoch, for use in max cover.
    fn get_valid_attestations_for_epoch<'a>(
        &'a self,
        epoch: Epoch,
        all_attestations: &'a HashMap<AttestationId, Vec<Attestation<T>>>,
        state: &'a BeaconState<T>,
        total_active_balance: u64,
        validity_filter: impl FnMut(&&Attestation<T>) -> bool + Send,
        spec: &'a ChainSpec,
    ) -> impl Iterator<Item = AttMaxCover<'a, T>> + Send {
        let domain_bytes = AttestationId::compute_domain_bytes(
            epoch,
            &state.fork(),
            state.genesis_validators_root(),
            spec,
        );
        all_attestations
            .iter()
            .filter(move |(key, _)| key.domain_bytes_match(&domain_bytes))
            .flat_map(|(_, attestations)| attestations)
            .filter(move |attestation| attestation.data.target.epoch == epoch)
            .filter(move |attestation| {
                // Ensure attestations are valid for block inclusion
                verify_attestation_for_block_inclusion(
                    state,
                    attestation,
                    VerifySignatures::False,
                    spec,
                )
                .is_ok()
            })
            .filter(validity_filter)
            .filter_map(move |att| AttMaxCover::new(att, state, total_active_balance, spec))
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
        prev_epoch_validity_filter: impl FnMut(&&Attestation<T>) -> bool + Send,
        curr_epoch_validity_filter: impl FnMut(&&Attestation<T>) -> bool + Send,
        spec: &ChainSpec,
    ) -> Result<Vec<Attestation<T>>, OpPoolError> {
        // Attestations for the current fork, which may be from the current or previous epoch.
        let prev_epoch = state.previous_epoch();
        let current_epoch = state.current_epoch();
        let all_attestations = self.attestations.read();
        let total_active_balance = state
            .get_total_active_balance()
            .map_err(OpPoolError::GetAttestationsTotalBalanceError)?;

        // Split attestations for the previous & current epochs, so that we
        // can optimise them individually in parallel.
        let prev_epoch_att = self.get_valid_attestations_for_epoch(
            prev_epoch,
            &*all_attestations,
            state,
            total_active_balance,
            prev_epoch_validity_filter,
            spec,
        );
        let curr_epoch_att = self.get_valid_attestations_for_epoch(
            current_epoch,
            &*all_attestations,
            state,
            total_active_balance,
            curr_epoch_validity_filter,
            spec,
        );

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
                if prev_epoch == current_epoch {
                    vec![]
                } else {
                    maximum_cover(prev_epoch_att, prev_epoch_limit)
                }
            },
            move || {
                let _timer = metrics::start_timer(&metrics::ATTESTATION_CURR_EPOCH_PACKING_TIME);
                maximum_cover(curr_epoch_att, T::MaxAttestations::to_usize())
            },
        );

        Ok(max_cover::merge_solutions(
            curr_cover,
            prev_cover,
            T::MaxAttestations::to_usize(),
        ))
    }

    /// Remove attestations which are too old to be included in a block.
    pub fn prune_attestations(&self, current_epoch: Epoch) {
        // Prune attestations that are from before the previous epoch.
        self.attestations.write().retain(|_, attestations| {
            // All the attestations in this bucket have the same data, so we only need to
            // check the first one.
            attestations
                .first()
                .map_or(false, |att| current_epoch <= att.data.target.epoch + 1)
        });
    }

    /// Insert a proposer slashing into the pool.
    pub fn insert_proposer_slashing(
        &self,
        verified_proposer_slashing: SigVerifiedOp<ProposerSlashing>,
    ) {
        let slashing = verified_proposer_slashing.into_inner();
        self.proposer_slashings
            .write()
            .insert(slashing.signed_header_1.message.proposer_index, slashing);
    }

    /// Insert an attester slashing into the pool.
    pub fn insert_attester_slashing(
        &self,
        verified_slashing: SigVerifiedOp<AttesterSlashing<T>>,
        fork: Fork,
    ) {
        self.attester_slashings
            .write()
            .insert((verified_slashing.into_inner(), fork.current_version));
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
                state
                    .validators()
                    .get(slashing.signed_header_1.message.proposer_index as usize)
                    .map_or(false, |validator| !validator.slashed)
            },
            T::MaxProposerSlashings::to_usize(),
        );

        // Set of validators to be slashed, so we don't attempt to construct invalid attester
        // slashings.
        let mut to_be_slashed = proposer_slashings
            .iter()
            .map(|s| s.signed_header_1.message.proposer_index)
            .collect::<HashSet<_>>();

        let reader = self.attester_slashings.read();

        let relevant_attester_slashings = reader.iter().flat_map(|(slashing, fork)| {
            if *fork == state.fork().previous_version || *fork == state.fork().current_version {
                AttesterSlashingMaxCover::new(slashing, &to_be_slashed, state)
            } else {
                None
            }
        });

        let attester_slashings = maximum_cover(
            relevant_attester_slashings,
            T::MaxAttesterSlashings::to_usize(),
        )
        .into_iter()
        .map(|cover| {
            to_be_slashed.extend(cover.covering_set().keys());
            cover.object().clone()
        })
        .collect();

        let voluntary_exits = self.get_voluntary_exits(
            state,
            |exit| !to_be_slashed.contains(&exit.message.validator_index),
            spec,
        );

        (proposer_slashings, attester_slashings, voluntary_exits)
    }

    /// Prune proposer slashings for validators which are exited in the finalized epoch.
    pub fn prune_proposer_slashings(&self, head_state: &BeaconState<T>) {
        prune_validator_hash_map(
            &mut self.proposer_slashings.write(),
            |validator| validator.exit_epoch <= head_state.finalized_checkpoint().epoch,
            head_state,
        );
    }

    /// Prune attester slashings for all slashed or withdrawn validators, or attestations on another
    /// fork.
    pub fn prune_attester_slashings(&self, head_state: &BeaconState<T>) {
        self.attester_slashings
            .write()
            .retain(|(slashing, fork_version)| {
                let previous_fork_is_finalized =
                    head_state.finalized_checkpoint().epoch >= head_state.fork().epoch;
                // Prune any slashings which don't match the current fork version, or the previous
                // fork version if it is not finalized yet.
                let fork_ok = (*fork_version == head_state.fork().current_version)
                    || (*fork_version == head_state.fork().previous_version
                        && !previous_fork_is_finalized);
                // Slashings that don't slash any validators can also be dropped.
                let slashing_ok =
                    get_slashable_indices_modular(head_state, slashing, |_, validator| {
                        // Declare that a validator is still slashable if they have not exited prior
                        // to the finalized epoch.
                        //
                        // We cannot check the `slashed` field since the `head` is not finalized and
                        // a fork could un-slash someone.
                        validator.exit_epoch > head_state.finalized_checkpoint().epoch
                    })
                    .map_or(false, |indices| !indices.is_empty());

                fork_ok && slashing_ok
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
    pub fn insert_voluntary_exit(&self, verified_exit: SigVerifiedOp<SignedVoluntaryExit>) {
        let exit = verified_exit.into_inner();
        self.voluntary_exits
            .write()
            .insert(exit.message.validator_index, exit);
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
            |exit| filter(exit) && verify_exit(state, exit, VerifySignatures::False, spec).is_ok(),
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
            |validator| validator.exit_epoch <= head_state.finalized_checkpoint().epoch,
            head_state,
        );
    }

    /// Prune all types of transactions given the latest head state and head fork.
    pub fn prune_all(&self, head_state: &BeaconState<T>, current_epoch: Epoch) {
        self.prune_attestations(current_epoch);
        self.prune_sync_contributions(head_state.slot());
        self.prune_proposer_slashings(head_state);
        self.prune_attester_slashings(head_state);
        self.prune_voluntary_exits(head_state);
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
            .map(|(_, attns)| attns.iter().cloned())
            .flatten()
            .collect()
    }

    /// Returns all known `Attestation` objects that pass the provided filter.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_filtered_attestations<F>(&self, filter: F) -> Vec<Attestation<T>>
    where
        F: Fn(&Attestation<T>) -> bool,
    {
        self.attestations
            .read()
            .iter()
            .map(|(_, attns)| attns.iter().cloned())
            .flatten()
            .filter(filter)
            .collect()
    }

    /// Returns all known `AttesterSlashing` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_attester_slashings(&self) -> Vec<AttesterSlashing<T>> {
        self.attester_slashings
            .read()
            .iter()
            .map(|(slashing, _)| slashing.clone())
            .collect()
    }

    /// Returns all known `ProposerSlashing` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_proposer_slashings(&self) -> Vec<ProposerSlashing> {
        self.proposer_slashings
            .read()
            .iter()
            .map(|(_, slashing)| slashing.clone())
            .collect()
    }

    /// Returns all known `SignedVoluntaryExit` objects.
    ///
    /// This method may return objects that are invalid for block inclusion.
    pub fn get_all_voluntary_exits(&self) -> Vec<SignedVoluntaryExit> {
        self.voluntary_exits
            .read()
            .iter()
            .map(|(_, exit)| exit.clone())
            .collect()
    }
}

/// Filter up to a maximum number of operations out of an iterator.
fn filter_limit_operations<'a, T: 'a, I, F>(operations: I, filter: F, limit: usize) -> Vec<T>
where
    I: IntoIterator<Item = &'a T>,
    F: Fn(&T) -> bool,
    T: Clone,
{
    operations
        .into_iter()
        .filter(|x| filter(*x))
        .take(limit)
        .cloned()
        .collect()
}

/// Remove all entries from the given hash map for which `prune_if` returns true.
///
/// The keys in the map should be validator indices, which will be looked up
/// in the state's validator registry and then passed to `prune_if`.
/// Entries for unknown validators will be kept.
fn prune_validator_hash_map<T, F, E: EthSpec>(
    map: &mut HashMap<u64, T>,
    prune_if: F,
    head_state: &BeaconState<E>,
) where
    F: Fn(&Validator) -> bool,
{
    map.retain(|&validator_index, _| {
        head_state
            .validators()
            .get(validator_index as usize)
            .map_or(true, |validator| !prune_if(validator))
    });
}

/// Compare two operation pools.
impl<T: EthSpec + Default> PartialEq for OperationPool<T> {
    fn eq(&self, other: &Self) -> bool {
        if ptr::eq(self, other) {
            return true;
        }
        *self.attestations.read() == *other.attestations.read()
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
    use state_processing::VerifyOperation;
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
    fn sync_contribution_test_state<E: EthSpec>(
        num_committees: usize,
    ) -> (BeaconChainHarness<EphemeralHarnessType<E>>, ChainSpec) {
        let mut spec = E::default_spec();

        spec.altair_fork_epoch = Some(Epoch::new(0));

        let num_validators =
            num_committees * E::slots_per_epoch() as usize * spec.target_committee_size;
        let harness = get_harness::<E>(num_validators, Some(spec.clone()));

        let state = harness.get_current_state();
        harness.add_attested_blocks_at_slots(
            state,
            Hash256::zero(),
            &[Slot::new(1)],
            (0..num_validators).collect::<Vec<_>>().as_slice(),
        );

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

            assert_eq!(
                att1.aggregation_bits.num_set_bits(),
                earliest_attestation_validators(&att1, &state, state.as_base().unwrap())
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
                earliest_attestation_validators(&att2, &state, state.as_base().unwrap())
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
            for att in atts.into_iter() {
                op_pool
                    .insert_attestation(att.0, &state.fork(), state.genesis_validators_root(), spec)
                    .unwrap();
            }
        }

        assert_eq!(op_pool.attestations.read().len(), committees.len());
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
            op_pool
                .insert_attestation(
                    att.clone(),
                    &state.fork(),
                    state.genesis_validators_root(),
                    spec,
                )
                .unwrap();
            op_pool
                .insert_attestation(att, &state.fork(), state.genesis_validators_root(), spec)
                .unwrap();
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
                op_pool
                    .insert_attestation(att, &state.fork(), state.genesis_validators_root(), spec)
                    .unwrap();
            }
        }

        // The attestations should get aggregated into two attestations that comprise all
        // validators.
        assert_eq!(op_pool.attestations.read().len(), committees.len());
        assert_eq!(op_pool.num_attestations(), 2 * committees.len());
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
                op_pool
                    .insert_attestation(att, &state.fork(), state.genesis_validators_root(), spec)
                    .unwrap();
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

        assert_eq!(op_pool.attestations.read().len(), committees.len());
        assert_eq!(
            op_pool.num_attestations(),
            (num_small + num_big) * committees.len()
        );
        assert!(op_pool.num_attestations() > max_attestations);

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
                op_pool
                    .insert_attestation(att, &state.fork(), state.genesis_validators_root(), spec)
                    .unwrap();
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

        assert_eq!(op_pool.attestations.read().len(), committees.len());
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

        for att in &best_attestations {
            let mut fresh_validators_rewards =
                AttMaxCover::new(att, &state, total_active_balance, spec)
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
        op_pool.insert_attester_slashing(
            slashing.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
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

        op_pool.insert_attester_slashing(
            slashing_1.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_2.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_3.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_4.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );

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

        op_pool.insert_attester_slashing(
            slashing_1.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_2.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_3.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_4.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );

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
        op_pool.insert_attester_slashing(
            a_slashing_1.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            a_slashing_2.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            a_slashing_3.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );

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

        op_pool.insert_attester_slashing(
            slashing_1.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_2.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_3.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );

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

        op_pool.insert_attester_slashing(
            slashing_1.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_2.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );
        op_pool.insert_attester_slashing(
            slashing_3.clone().validate(&state, spec).unwrap(),
            state.fork(),
        );

        let best_slashings = op_pool.get_slashings_and_exits(&state, &harness.spec);
        assert_eq!(best_slashings.1, vec![slashing_2, slashing_3]);
    }

    /// End-to-end test of basic sync contribution handling.
    #[test]
    fn sync_contribution_aggregation_insert_get_prune() {
        let (harness, _) = sync_contribution_test_state::<MainnetEthSpec>(1);

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
    #[test]
    fn sync_contribution_duplicate() {
        let (harness, _) = sync_contribution_test_state::<MainnetEthSpec>(1);

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
    #[test]
    fn sync_contribution_with_more_bits() {
        let (harness, _) = sync_contribution_test_state::<MainnetEthSpec>(1);

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
    #[test]
    fn sync_contribution_with_fewer_bits() {
        let (harness, _) = sync_contribution_test_state::<MainnetEthSpec>(1);

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
}
