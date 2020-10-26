mod attestation;
mod attestation_id;
mod attester_slashing;
mod max_cover;
mod persistence;

pub use persistence::PersistedOperationPool;

use attestation::AttMaxCover;
use attestation_id::AttestationId;
use attester_slashing::AttesterSlashingMaxCover;
use max_cover::maximum_cover;
use parking_lot::RwLock;
use state_processing::per_block_processing::errors::AttestationValidationError;
use state_processing::per_block_processing::{
    get_slashable_indices, verify_attestation_for_block_inclusion, verify_exit, VerifySignatures,
};
use state_processing::SigVerifiedOp;
use std::collections::{hash_map, HashMap, HashSet};
use std::marker::PhantomData;
use std::ptr;
use types::{
    typenum::Unsigned, Attestation, AttesterSlashing, BeaconState, BeaconStateError, ChainSpec,
    Epoch, EthSpec, Fork, ForkVersion, Hash256, ProposerSlashing, RelativeEpoch,
    SignedVoluntaryExit, Validator,
};
#[derive(Default, Debug)]
pub struct OperationPool<T: EthSpec + Default> {
    /// Map from attestation ID (see below) to vectors of attestations.
    attestations: RwLock<HashMap<AttestationId, Vec<Attestation<T>>>>,
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
}

impl<T: EthSpec> OperationPool<T> {
    /// Create a new operation pool.
    pub fn new() -> Self {
        Self::default()
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
            hash_map::Entry::Vacant(entry) => {
                entry.insert(vec![attestation]);
                return Ok(());
            }
            hash_map::Entry::Occupied(entry) => entry.into_mut(),
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

    /// Get a list of attestations for inclusion in a block.
    ///
    /// The `validity_filter` is a closure that provides extra filtering of the attestations
    /// before an approximately optimal bundle is constructed. We use it to provide access
    /// to the fork choice data from the `BeaconChain` struct that doesn't logically belong
    /// in the operation pool.
    pub fn get_attestations(
        &self,
        state: &BeaconState<T>,
        validity_filter: impl FnMut(&&Attestation<T>) -> bool,
        spec: &ChainSpec,
    ) -> Result<Vec<Attestation<T>>, OpPoolError> {
        // Attestations for the current fork, which may be from the current or previous epoch.
        let prev_epoch = state.previous_epoch();
        let current_epoch = state.current_epoch();
        let prev_domain_bytes = AttestationId::compute_domain_bytes(
            prev_epoch,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );
        let curr_domain_bytes = AttestationId::compute_domain_bytes(
            current_epoch,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );
        let reader = self.attestations.read();
        let active_indices = state
            .get_cached_active_validator_indices(RelativeEpoch::Current)
            .map_err(OpPoolError::GetAttestationsTotalBalanceError)?;
        let total_active_balance = state
            .get_total_balance(&active_indices, spec)
            .map_err(OpPoolError::GetAttestationsTotalBalanceError)?;
        let valid_attestations = reader
            .iter()
            .filter(|(key, _)| {
                key.domain_bytes_match(&prev_domain_bytes)
                    || key.domain_bytes_match(&curr_domain_bytes)
            })
            .flat_map(|(_, attestations)| attestations)
            // That are valid...
            .filter(|attestation| {
                verify_attestation_for_block_inclusion(
                    state,
                    attestation,
                    VerifySignatures::False,
                    spec,
                )
                .is_ok()
            })
            .filter(validity_filter)
            .flat_map(|att| AttMaxCover::new(att, state, total_active_balance, spec));

        Ok(maximum_cover(
            valid_attestations,
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
    pub fn get_slashings(
        &self,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> (Vec<ProposerSlashing>, Vec<AttesterSlashing<T>>) {
        let proposer_slashings = filter_limit_operations(
            self.proposer_slashings.read().values(),
            |slashing| {
                state
                    .validators
                    .get(slashing.signed_header_1.message.proposer_index as usize)
                    .map_or(false, |validator| !validator.slashed)
            },
            T::MaxProposerSlashings::to_usize(),
        );

        // Set of validators to be slashed, so we don't attempt to construct invalid attester
        // slashings.
        let to_be_slashed = proposer_slashings
            .iter()
            .map(|s| s.signed_header_1.message.proposer_index)
            .collect::<HashSet<_>>();

        let reader = self.attester_slashings.read();

        let relevant_attester_slashings = reader.iter().flat_map(|(slashing, fork)| {
            if *fork == state.fork.previous_version || *fork == state.fork.current_version {
                AttesterSlashingMaxCover::new(&slashing, &to_be_slashed, state, spec)
            } else {
                None
            }
        });

        let attester_slashings = maximum_cover(
            relevant_attester_slashings,
            T::MaxAttesterSlashings::to_usize(),
        );

        (proposer_slashings, attester_slashings)
    }

    /// Prune proposer slashings for all slashed or withdrawn validators.
    pub fn prune_proposer_slashings(&self, finalized_state: &BeaconState<T>) {
        prune_validator_hash_map(
            &mut self.proposer_slashings.write(),
            |validator| {
                validator.slashed || validator.is_withdrawable_at(finalized_state.current_epoch())
            },
            finalized_state,
        );
    }

    /// Prune attester slashings for all slashed or withdrawn validators, or attestations on another
    /// fork.
    pub fn prune_attester_slashings(&self, finalized_state: &BeaconState<T>, head_fork: Fork) {
        self.attester_slashings
            .write()
            .retain(|(slashing, fork_version)| {
                // Any slashings for forks older than the finalized state's previous fork can be
                // discarded. We allow the head_fork's current version too in case a fork has
                // occurred between the finalized state and the head.
                let fork_ok = *fork_version == finalized_state.fork.previous_version
                    || *fork_version == finalized_state.fork.current_version
                    || *fork_version == head_fork.current_version;
                // Slashings that don't slash any validators can also be dropped.
                let slashing_ok = get_slashable_indices(finalized_state, slashing).is_ok();
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
    pub fn get_voluntary_exits(
        &self,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Vec<SignedVoluntaryExit> {
        filter_limit_operations(
            self.voluntary_exits.read().values(),
            |exit| verify_exit(state, exit, VerifySignatures::False, spec).is_ok(),
            T::MaxVoluntaryExits::to_usize(),
        )
    }

    /// Prune if validator has already exited at the last finalized state.
    pub fn prune_voluntary_exits(&self, finalized_state: &BeaconState<T>, spec: &ChainSpec) {
        prune_validator_hash_map(
            &mut self.voluntary_exits.write(),
            |validator| validator.exit_epoch != spec.far_future_epoch,
            finalized_state,
        );
    }

    /// Prune all types of transactions given the latest finalized state and head fork.
    pub fn prune_all(
        &self,
        finalized_state: &BeaconState<T>,
        current_epoch: Epoch,
        head_fork: Fork,
        spec: &ChainSpec,
    ) {
        self.prune_attestations(current_epoch);
        self.prune_proposer_slashings(finalized_state);
        self.prune_attester_slashings(finalized_state, head_fork);
        self.prune_voluntary_exits(finalized_state, spec);
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
    finalized_state: &BeaconState<E>,
) where
    F: Fn(&Validator) -> bool,
{
    map.retain(|&validator_index, _| {
        finalized_state
            .validators
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

// TODO: more tests
#[cfg(all(test, not(debug_assertions)))]
mod release_tests {
    use super::attestation::earliest_attestation_validators;
    use super::*;
    use state_processing::{
        common::{get_attesting_indices, get_base_reward},
        VerifyOperation,
    };
    use std::collections::BTreeSet;
    use std::iter::FromIterator;
    use types::test_utils::*;
    use types::*;

    /// Create a signed attestation for use in tests.
    /// Signed by all validators in `committee[signing_range]` and `committee[extra_signer]`.
    fn signed_attestation<R: std::slice::SliceIndex<[usize], Output = [usize]>, E: EthSpec>(
        committee: &[usize],
        index: u64,
        keypairs: &[Keypair],
        signing_range: R,
        slot: Slot,
        state: &BeaconState<E>,
        spec: &ChainSpec,
        extra_signer: Option<usize>,
    ) -> Attestation<E> {
        let mut builder = TestingAttestationBuilder::new(
            AttestationTestTask::Valid,
            state,
            committee,
            slot,
            index,
            spec,
        );
        let signers = &committee[signing_range];
        let committee_keys = signers.iter().map(|&i| &keypairs[i].sk).collect::<Vec<_>>();
        builder.sign(
            AttestationTestTask::Valid,
            signers,
            &committee_keys,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );
        extra_signer.map(|c_idx| {
            let validator_index = committee[c_idx];
            builder.sign(
                AttestationTestTask::Valid,
                &[validator_index],
                &[&keypairs[validator_index].sk],
                &state.fork,
                state.genesis_validators_root,
                spec,
            )
        });
        builder.build()
    }

    /// Test state for attestation-related tests.
    fn attestation_test_state<E: EthSpec>(
        num_committees: usize,
    ) -> (BeaconState<E>, Vec<Keypair>, ChainSpec) {
        let spec = E::default_spec();

        let num_validators =
            num_committees * E::slots_per_epoch() as usize * spec.target_committee_size;
        let mut state_builder =
            TestingBeaconStateBuilder::from_deterministic_keypairs(num_validators, &spec);
        let slot_offset = 1000 * E::slots_per_epoch() + E::slots_per_epoch() / 2;
        let slot = spec.genesis_slot + slot_offset;
        state_builder.teleport_to_slot(slot);
        state_builder.build_caches(&spec).unwrap();
        let (state, keypairs) = state_builder.build();
        (state, keypairs, spec)
    }

    #[test]
    fn test_earliest_attestation() {
        let (ref mut state, ref keypairs, ref spec) = attestation_test_state::<MainnetEthSpec>(1);
        let slot = state.slot - 1;
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        for bc in committees {
            let att1 = signed_attestation(
                &bc.committee,
                bc.index,
                keypairs,
                ..2,
                slot,
                state,
                spec,
                None,
            );
            let att2 = signed_attestation(
                &bc.committee,
                bc.index,
                keypairs,
                ..,
                slot,
                state,
                spec,
                None,
            );

            assert_eq!(
                att1.aggregation_bits.num_set_bits(),
                earliest_attestation_validators(&att1, state).num_set_bits()
            );
            state
                .current_epoch_attestations
                .push(PendingAttestation {
                    aggregation_bits: att1.aggregation_bits.clone(),
                    data: att1.data.clone(),
                    inclusion_delay: 0,
                    proposer_index: 0,
                })
                .unwrap();

            assert_eq!(
                bc.committee.len() - 2,
                earliest_attestation_validators(&att2, state).num_set_bits()
            );
        }
    }

    /// End-to-end test of basic attestation handling.
    #[test]
    fn attestation_aggregation_insert_get_prune() {
        let (ref mut state, ref keypairs, ref spec) = attestation_test_state::<MainnetEthSpec>(1);

        let op_pool = OperationPool::new();

        let slot = state.slot - 1;
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

        for bc in &committees {
            let step_size = 2;
            for i in (0..bc.committee.len()).step_by(step_size) {
                let att = signed_attestation(
                    &bc.committee,
                    bc.index,
                    keypairs,
                    i..i + step_size,
                    slot,
                    state,
                    spec,
                    None,
                );
                op_pool
                    .insert_attestation(att, &state.fork, state.genesis_validators_root, spec)
                    .unwrap();
            }
        }

        assert_eq!(op_pool.attestations.read().len(), committees.len());
        assert_eq!(op_pool.num_attestations(), committees.len());

        // Before the min attestation inclusion delay, get_attestations shouldn't return anything.
        state.slot -= 1;
        assert_eq!(
            op_pool
                .get_attestations(state, |_| true, spec)
                .expect("should have attestations")
                .len(),
            0
        );

        // Then once the delay has elapsed, we should get a single aggregated attestation.
        state.slot += spec.min_attestation_inclusion_delay;

        let block_attestations = op_pool
            .get_attestations(state, |_| true, spec)
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
        state.slot += 2 * MainnetEthSpec::slots_per_epoch();
        op_pool.prune_attestations(state.current_epoch());
        assert_eq!(op_pool.num_attestations(), 0);
    }

    /// Adding an attestation already in the pool should not increase the size of the pool.
    #[test]
    fn attestation_duplicate() {
        let (ref mut state, ref keypairs, ref spec) = attestation_test_state::<MainnetEthSpec>(1);

        let op_pool = OperationPool::new();

        let slot = state.slot - 1;
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        for bc in &committees {
            let att = signed_attestation(
                &bc.committee,
                bc.index,
                keypairs,
                ..,
                slot,
                state,
                spec,
                None,
            );
            op_pool
                .insert_attestation(
                    att.clone(),
                    &state.fork,
                    state.genesis_validators_root,
                    spec,
                )
                .unwrap();
            op_pool
                .insert_attestation(att, &state.fork, state.genesis_validators_root, spec)
                .unwrap();
        }

        assert_eq!(op_pool.num_attestations(), committees.len());
    }

    /// Adding lots of attestations that only intersect pairwise should lead to two aggregate
    /// attestations.
    #[test]
    fn attestation_pairwise_overlapping() {
        let (ref mut state, ref keypairs, ref spec) = attestation_test_state::<MainnetEthSpec>(1);

        let op_pool = OperationPool::new();

        let slot = state.slot - 1;
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        let step_size = 2;
        for bc in &committees {
            // Create attestations that overlap on `step_size` validators, like:
            // {0,1,2,3}, {2,3,4,5}, {4,5,6,7}, ...
            for i in (0..bc.committee.len() - step_size).step_by(step_size) {
                let att = signed_attestation(
                    &bc.committee,
                    bc.index,
                    keypairs,
                    i..i + 2 * step_size,
                    slot,
                    state,
                    spec,
                    None,
                );
                op_pool
                    .insert_attestation(att, &state.fork, state.genesis_validators_root, spec)
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

        let (ref mut state, ref keypairs, ref spec) =
            attestation_test_state::<MainnetEthSpec>(big_step_size);

        let op_pool = OperationPool::new();

        let slot = state.slot - 1;
        let committees = state
            .get_beacon_committees_at_slot(slot)
            .unwrap()
            .into_iter()
            .map(BeaconCommittee::into_owned)
            .collect::<Vec<_>>();

        let max_attestations = <MainnetEthSpec as EthSpec>::MaxAttestations::to_usize();
        let target_committee_size = spec.target_committee_size as usize;

        let insert_attestations = |bc: &OwnedBeaconCommittee, step_size| {
            for i in (0..target_committee_size).step_by(step_size) {
                let att = signed_attestation(
                    &bc.committee,
                    bc.index,
                    keypairs,
                    i..i + step_size,
                    slot,
                    state,
                    spec,
                    if i == 0 { None } else { Some(0) },
                );
                op_pool
                    .insert_attestation(att, &state.fork, state.genesis_validators_root, spec)
                    .unwrap();
            }
        };

        for committee in &committees {
            assert_eq!(committee.committee.len(), target_committee_size);
            // Attestations signed by only 2-3 validators
            insert_attestations(committee, small_step_size);
            // Attestations signed by 4+ validators
            insert_attestations(committee, big_step_size);
        }

        let num_small = target_committee_size / small_step_size;
        let num_big = target_committee_size / big_step_size;

        assert_eq!(op_pool.attestations.read().len(), committees.len());
        assert_eq!(
            op_pool.num_attestations(),
            (num_small + num_big) * committees.len()
        );
        assert!(op_pool.num_attestations() > max_attestations);

        state.slot += spec.min_attestation_inclusion_delay;
        let best_attestations = op_pool
            .get_attestations(state, |_| true, spec)
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

        let (ref mut state, ref keypairs, ref spec) =
            attestation_test_state::<MainnetEthSpec>(big_step_size);

        let op_pool = OperationPool::new();

        let slot = state.slot - 1;
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
        for i in 0..state.validators.len() {
            state.validators[i].effective_balance = 1_000_000_000 * i as u64;
        }

        let insert_attestations = |bc: &OwnedBeaconCommittee, step_size| {
            for i in (0..target_committee_size).step_by(step_size) {
                let att = signed_attestation(
                    &bc.committee,
                    bc.index,
                    keypairs,
                    i..i + step_size,
                    slot,
                    state,
                    spec,
                    if i == 0 { None } else { Some(0) },
                );
                op_pool
                    .insert_attestation(att, &state.fork, state.genesis_validators_root, spec)
                    .unwrap();
            }
        };

        for committee in &committees {
            assert_eq!(committee.committee.len(), target_committee_size);
            // Attestations signed by only 2-3 validators
            insert_attestations(committee, small_step_size);
            // Attestations signed by 4+ validators
            insert_attestations(committee, big_step_size);
        }

        let num_small = target_committee_size / small_step_size;
        let num_big = target_committee_size / big_step_size;

        assert_eq!(op_pool.attestations.read().len(), committees.len());
        assert_eq!(
            op_pool.num_attestations(),
            (num_small + num_big) * committees.len()
        );
        assert!(op_pool.num_attestations() > max_attestations);

        state.slot += spec.min_attestation_inclusion_delay;
        let best_attestations = op_pool
            .get_attestations(state, |_| true, spec)
            .expect("should have valid best attestations");
        assert_eq!(best_attestations.len(), max_attestations);

        let active_indices = state
            .get_cached_active_validator_indices(RelativeEpoch::Current)
            .unwrap();
        let total_active_balance = state.get_total_balance(&active_indices, spec).unwrap();

        // Set of indices covered by previous attestations in `best_attestations`.
        let mut seen_indices = BTreeSet::new();
        // Used for asserting that rewards are in decreasing order.
        let mut prev_reward = u64::max_value();

        for att in &best_attestations {
            let fresh_validators_bitlist = earliest_attestation_validators(att, state);
            let committee = state
                .get_beacon_committee(att.data.slot, att.data.index)
                .expect("should get beacon committee");

            let att_indices = BTreeSet::from_iter(
                get_attesting_indices::<MainnetEthSpec>(
                    committee.committee,
                    &fresh_validators_bitlist,
                )
                .unwrap(),
            );

            let fresh_indices = &att_indices - &seen_indices;

            let rewards = fresh_indices
                .iter()
                .map(|validator_index| {
                    get_base_reward(state, *validator_index as usize, total_active_balance, spec)
                        .unwrap()
                        / spec.proposer_reward_quotient
                })
                .sum();

            // Check that rewards are in decreasing order
            assert!(prev_reward >= rewards);

            prev_reward = rewards;
            seen_indices.extend(fresh_indices);
        }
    }

    struct TestContext {
        spec: ChainSpec,
        state: BeaconState<MainnetEthSpec>,
        keypairs: Vec<Keypair>,
        op_pool: OperationPool<MainnetEthSpec>,
    }

    impl TestContext {
        fn new() -> Self {
            let spec = MainnetEthSpec::default_spec();
            let num_validators = 32;
            let mut state_builder =
                TestingBeaconStateBuilder::<MainnetEthSpec>::from_deterministic_keypairs(
                    num_validators,
                    &spec,
                );
            state_builder.build_caches(&spec).unwrap();
            let (state, keypairs) = state_builder.build();
            let op_pool = OperationPool::new();

            TestContext {
                spec,
                state,
                keypairs,
                op_pool,
            }
        }

        fn proposer_slashing(&self, proposer_index: u64) -> ProposerSlashing {
            TestingProposerSlashingBuilder::double_vote::<MainnetEthSpec>(
                ProposerSlashingTestTask::Valid,
                proposer_index,
                &self.keypairs[proposer_index as usize].sk,
                &self.state.fork,
                self.state.genesis_validators_root,
                &self.spec,
            )
        }

        fn attester_slashing(&self, slashed_indices: &[u64]) -> AttesterSlashing<MainnetEthSpec> {
            let signer = |idx: u64, message: &[u8]| {
                self.keypairs[idx as usize]
                    .sk
                    .sign(Hash256::from_slice(&message))
            };
            TestingAttesterSlashingBuilder::double_vote(
                AttesterSlashingTestTask::Valid,
                slashed_indices,
                signer,
                &self.state.fork,
                self.state.genesis_validators_root,
                &self.spec,
            )
        }

        fn attester_slashing_two_indices(
            &self,
            slashed_indices_1: &[u64],
            slashed_indices_2: &[u64],
        ) -> AttesterSlashing<MainnetEthSpec> {
            let signer = |idx: u64, message: &[u8]| {
                self.keypairs[idx as usize]
                    .sk
                    .sign(Hash256::from_slice(&message))
            };
            TestingAttesterSlashingBuilder::double_vote_with_additional_indices(
                AttesterSlashingTestTask::Valid,
                slashed_indices_1,
                Some(slashed_indices_2),
                signer,
                &self.state.fork,
                self.state.genesis_validators_root,
                &self.spec,
            )
        }
    }

    /// Insert two slashings for the same proposer and ensure only one is returned.
    #[test]
    fn duplicate_proposer_slashing() {
        let ctxt = TestContext::new();
        let (op_pool, state, spec) = (&ctxt.op_pool, &ctxt.state, &ctxt.spec);
        let proposer_index = 0;
        let slashing1 = ctxt.proposer_slashing(proposer_index);
        let slashing2 = ProposerSlashing {
            signed_header_1: slashing1.signed_header_2.clone(),
            signed_header_2: slashing1.signed_header_1.clone(),
        };

        // Both slashings should be valid and accepted by the pool.
        op_pool.insert_proposer_slashing(slashing1.clone().validate(state, spec).unwrap());
        op_pool.insert_proposer_slashing(slashing2.clone().validate(state, spec).unwrap());

        // Should only get the second slashing back.
        assert_eq!(op_pool.get_slashings(state, spec).0, vec![slashing2]);
    }

    // Sanity check on the pruning of proposer slashings
    #[test]
    fn prune_proposer_slashing_noop() {
        let ctxt = TestContext::new();
        let (op_pool, state, spec) = (&ctxt.op_pool, &ctxt.state, &ctxt.spec);
        let slashing = ctxt.proposer_slashing(0);
        op_pool.insert_proposer_slashing(slashing.clone().validate(state, spec).unwrap());
        op_pool.prune_proposer_slashings(state);
        assert_eq!(op_pool.get_slashings(state, spec).0, vec![slashing]);
    }

    // Sanity check on the pruning of attester slashings
    #[test]
    fn prune_attester_slashing_noop() {
        let ctxt = TestContext::new();
        let (op_pool, state, spec) = (&ctxt.op_pool, &ctxt.state, &ctxt.spec);
        let slashing = ctxt.attester_slashing(&[1, 3, 5, 7, 9]);
        op_pool
            .insert_attester_slashing(slashing.clone().validate(state, spec).unwrap(), state.fork);
        op_pool.prune_attester_slashings(state, state.fork);
        assert_eq!(op_pool.get_slashings(state, spec).1, vec![slashing]);
    }

    // Check that we get maximum coverage for attester slashings (highest qty of validators slashed)
    #[test]
    fn simple_max_cover_attester_slashing() {
        let ctxt = TestContext::new();
        let (op_pool, state, spec) = (&ctxt.op_pool, &ctxt.state, &ctxt.spec);

        let slashing_1 = ctxt.attester_slashing(&[1]);
        let slashing_2 = ctxt.attester_slashing(&[2, 3]);
        let slashing_3 = ctxt.attester_slashing(&[4, 5, 6]);
        let slashing_4 = ctxt.attester_slashing(&[7, 8, 9, 10]);

        op_pool.insert_attester_slashing(
            slashing_1.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_2.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_3.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_4.clone().validate(state, spec).unwrap(),
            state.fork,
        );

        let best_slashings = op_pool.get_slashings(state, spec);
        assert_eq!(best_slashings.1, vec![slashing_4, slashing_3]);
    }

    // Check that we get maximum coverage for attester slashings with overlapping indices
    #[test]
    fn overlapping_max_cover_attester_slashing() {
        let ctxt = TestContext::new();
        let (op_pool, state, spec) = (&ctxt.op_pool, &ctxt.state, &ctxt.spec);

        let slashing_1 = ctxt.attester_slashing(&[1, 2, 3, 4]);
        let slashing_2 = ctxt.attester_slashing(&[1, 2, 5]);
        let slashing_3 = ctxt.attester_slashing(&[5, 6]);
        let slashing_4 = ctxt.attester_slashing(&[6]);

        op_pool.insert_attester_slashing(
            slashing_1.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_2.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_3.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_4.clone().validate(state, spec).unwrap(),
            state.fork,
        );

        let best_slashings = op_pool.get_slashings(state, spec);
        assert_eq!(best_slashings.1, vec![slashing_1, slashing_3]);
    }

    // Max coverage of attester slashings taking into account proposer slashings
    #[test]
    fn max_coverage_attester_proposer_slashings() {
        let ctxt = TestContext::new();
        let (op_pool, state, spec) = (&ctxt.op_pool, &ctxt.state, &ctxt.spec);

        let p_slashing = ctxt.proposer_slashing(1);
        let a_slashing_1 = ctxt.attester_slashing(&[1, 2, 3, 4]);
        let a_slashing_2 = ctxt.attester_slashing(&[1, 3, 4]);
        let a_slashing_3 = ctxt.attester_slashing(&[5, 6]);

        op_pool.insert_proposer_slashing(p_slashing.clone().validate(state, spec).unwrap());
        op_pool.insert_attester_slashing(
            a_slashing_1.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            a_slashing_2.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            a_slashing_3.clone().validate(state, spec).unwrap(),
            state.fork,
        );

        let best_slashings = op_pool.get_slashings(state, spec);
        assert_eq!(best_slashings.1, vec![a_slashing_1, a_slashing_3]);
    }

    //Max coverage checking that non overlapping indices are still recognized for their value
    #[test]
    fn max_coverage_different_indices_set() {
        let ctxt = TestContext::new();
        let (op_pool, state, spec) = (&ctxt.op_pool, &ctxt.state, &ctxt.spec);

        let slashing_1 =
            ctxt.attester_slashing_two_indices(&[1, 2, 3, 4, 5, 6], &[3, 4, 5, 6, 7, 8]);
        let slashing_2 = ctxt.attester_slashing(&[5, 6]);
        let slashing_3 = ctxt.attester_slashing(&[1, 2, 3]);

        op_pool.insert_attester_slashing(
            slashing_1.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_2.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_3.clone().validate(state, spec).unwrap(),
            state.fork,
        );

        let best_slashings = op_pool.get_slashings(state, spec);
        assert_eq!(best_slashings.1, vec![slashing_1, slashing_3]);
    }

    //Max coverage should be affected by the overall effective balances
    #[test]
    fn max_coverage_effective_balances() {
        let mut ctxt = TestContext::new();
        ctxt.state.validators[1].effective_balance = 17_000_000_000;
        ctxt.state.validators[2].effective_balance = 17_000_000_000;
        ctxt.state.validators[3].effective_balance = 17_000_000_000;

        let (op_pool, state, spec) = (&ctxt.op_pool, &ctxt.state, &ctxt.spec);

        let slashing_1 = ctxt.attester_slashing(&[1, 2, 3]);
        let slashing_2 = ctxt.attester_slashing(&[4, 5, 6]);
        let slashing_3 = ctxt.attester_slashing(&[7, 8]);

        op_pool.insert_attester_slashing(
            slashing_1.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_2.clone().validate(state, spec).unwrap(),
            state.fork,
        );
        op_pool.insert_attester_slashing(
            slashing_3.clone().validate(state, spec).unwrap(),
            state.fork,
        );

        let best_slashings = op_pool.get_slashings(state, spec);
        assert_eq!(best_slashings.1, vec![slashing_2, slashing_3]);
    }
}
