mod attestation;
mod attestation_id;
mod max_cover;
mod persistence;

pub use persistence::PersistedOperationPool;

use attestation::AttMaxCover;
use attestation_id::AttestationId;
use max_cover::maximum_cover;
use parking_lot::RwLock;
use state_processing::per_block_processing::errors::{
    AttestationValidationError, AttesterSlashingValidationError, ExitValidationError,
    ProposerSlashingValidationError,
};
use state_processing::per_block_processing::{
    get_slashable_indices_modular, verify_attestation_for_block_inclusion,
    verify_attester_slashing, verify_exit, verify_exit_time_independent_only,
    verify_proposer_slashing, VerifySignatures,
};
use std::collections::{hash_map, HashMap, HashSet};
use std::marker::PhantomData;
use types::{
    typenum::Unsigned, Attestation, AttesterSlashing, BeaconState, BeaconStateError, ChainSpec,
    EthSpec, Fork, Hash256, ProposerSlashing, RelativeEpoch, SignedVoluntaryExit, Validator,
};

#[derive(Default, Debug)]
pub struct OperationPool<T: EthSpec + Default> {
    /// Map from attestation ID (see below) to vectors of attestations.
    attestations: RwLock<HashMap<AttestationId, Vec<Attestation<T>>>>,
    /// Map from two attestation IDs to a slashing for those IDs.
    attester_slashings: RwLock<HashMap<(AttestationId, AttestationId), AttesterSlashing<T>>>,
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
    /// NOTE: Assumes that all attestations in the operation_pool are valid.
    pub fn get_attestations(
        &self,
        state: &BeaconState<T>,
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
            .flat_map(|att| AttMaxCover::new(att, state, total_active_balance, spec));

        Ok(maximum_cover(
            valid_attestations,
            T::MaxAttestations::to_usize(),
        ))
    }

    /// Remove attestations which are too old to be included in a block.
    pub fn prune_attestations(&self, finalized_state: &BeaconState<T>) {
        // We know we can include an attestation if:
        // state.slot <= attestation_slot + SLOTS_PER_EPOCH
        // We approximate this check using the attestation's epoch, to avoid computing
        // the slot or relying on the committee cache of the finalized state.
        self.attestations.write().retain(|_, attestations| {
            // All the attestations in this bucket have the same data, so we only need to
            // check the first one.
            attestations.first().map_or(false, |att| {
                finalized_state.current_epoch() <= att.data.target.epoch + 1
            })
        });
    }

    /// Insert a proposer slashing into the pool.
    pub fn insert_proposer_slashing(
        &self,
        slashing: ProposerSlashing,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<(), ProposerSlashingValidationError> {
        // TODO: should maybe insert anyway if the proposer is unknown in the validator index,
        // because they could *become* known later
        verify_proposer_slashing(&slashing, state, VerifySignatures::True, spec)?;
        self.proposer_slashings
            .write()
            .insert(slashing.signed_header_1.message.proposer_index, slashing);
        Ok(())
    }

    /// Compute the tuple ID that is used to identify an attester slashing.
    ///
    /// Depends on the fork field of the state, but not on the state's epoch.
    fn attester_slashing_id(
        slashing: &AttesterSlashing<T>,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> (AttestationId, AttestationId) {
        (
            AttestationId::from_data(
                &slashing.attestation_1.data,
                &state.fork,
                state.genesis_validators_root,
                spec,
            ),
            AttestationId::from_data(
                &slashing.attestation_2.data,
                &state.fork,
                state.genesis_validators_root,
                spec,
            ),
        )
    }

    /// Insert an attester slashing into the pool.
    pub fn insert_attester_slashing(
        &self,
        slashing: AttesterSlashing<T>,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<(), AttesterSlashingValidationError> {
        verify_attester_slashing(state, &slashing, true, VerifySignatures::True, spec)?;
        let id = Self::attester_slashing_id(&slashing, state, spec);
        self.attester_slashings.write().insert(id, slashing);
        Ok(())
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
        let mut to_be_slashed = proposer_slashings
            .iter()
            .map(|s| s.signed_header_1.message.proposer_index)
            .collect::<HashSet<_>>();

        let epoch = state.current_epoch();
        let attester_slashings = self
            .attester_slashings
            .read()
            .iter()
            .filter(|(id, slashing)| {
                // Check the fork.
                Self::attester_slashing_id(slashing, state, spec) == **id
            })
            .filter(|(_, slashing)| {
                // Take all slashings that will slash 1 or more validators.
                let slashed_validators =
                    get_slashable_indices_modular(state, slashing, |index, validator| {
                        validator.is_slashable_at(epoch) && !to_be_slashed.contains(&index)
                    });

                // Extend the `to_be_slashed` set so subsequent iterations don't try to include
                // useless slashings.
                if let Ok(validators) = slashed_validators {
                    to_be_slashed.extend(validators);
                    true
                } else {
                    false
                }
            })
            .take(T::MaxAttesterSlashings::to_usize())
            .map(|(_, slashing)| slashing.clone())
            .collect();

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
    pub fn prune_attester_slashings(&self, finalized_state: &BeaconState<T>, spec: &ChainSpec) {
        self.attester_slashings.write().retain(|id, slashing| {
            let fork_ok = &Self::attester_slashing_id(slashing, finalized_state, spec) == id;
            let curr_epoch = finalized_state.current_epoch();
            let slashing_ok =
                get_slashable_indices_modular(finalized_state, slashing, |_, validator| {
                    validator.slashed || validator.is_withdrawable_at(curr_epoch)
                })
                .is_ok();
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

    /// Insert a voluntary exit, validating it almost-entirely (future exits are permitted).
    pub fn insert_voluntary_exit(
        &self,
        exit: SignedVoluntaryExit,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<(), ExitValidationError> {
        verify_exit_time_independent_only(state, &exit, VerifySignatures::True, spec)?;
        self.voluntary_exits
            .write()
            .insert(exit.message.validator_index, exit);
        Ok(())
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
    pub fn prune_voluntary_exits(&self, finalized_state: &BeaconState<T>) {
        prune_validator_hash_map(
            &mut self.voluntary_exits.write(),
            |validator| validator.is_exited_at(finalized_state.current_epoch()),
            finalized_state,
        );
    }

    /// Prune all types of transactions given the latest finalized state.
    pub fn prune_all(&self, finalized_state: &BeaconState<T>, spec: &ChainSpec) {
        self.prune_attestations(finalized_state);
        self.prune_proposer_slashings(finalized_state);
        self.prune_attester_slashings(finalized_state, spec);
        self.prune_voluntary_exits(finalized_state);
    }

    /// Total number of voluntary exits in the pool.
    pub fn num_voluntary_exits(&self) -> usize {
        self.voluntary_exits.read().len()
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
    use state_processing::common::{get_attesting_indices, get_base_reward};
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
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(num_validators, &spec);
        let slot_offset = 1000 * E::slots_per_epoch() + E::slots_per_epoch() / 2;
        let slot = spec.genesis_slot + slot_offset;
        state_builder.teleport_to_slot(slot);
        state_builder.build_caches(&spec).unwrap();
        let (state, keypairs) = state_builder.build();
        (state, keypairs, MainnetEthSpec::default_spec())
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
                .get_attestations(state, spec)
                .expect("should have attestations")
                .len(),
            0
        );

        // Then once the delay has elapsed, we should get a single aggregated attestation.
        state.slot += spec.min_attestation_inclusion_delay;

        let block_attestations = op_pool
            .get_attestations(state, spec)
            .expect("Should have block attestations");
        assert_eq!(block_attestations.len(), committees.len());

        let agg_att = &block_attestations[0];
        assert_eq!(
            agg_att.aggregation_bits.num_set_bits(),
            spec.target_committee_size as usize
        );

        // Prune attestations shouldn't do anything at this point.
        op_pool.prune_attestations(state);
        assert_eq!(op_pool.num_attestations(), committees.len());

        // But once we advance to more than an epoch after the attestation, it should prune it
        // out of existence.
        state.slot += 2 * MainnetEthSpec::slots_per_epoch();
        op_pool.prune_attestations(state);
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
            .get_attestations(state, spec)
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
            .get_attestations(state, spec)
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
}
