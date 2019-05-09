use int_to_bytes::int_to_bytes8;
use itertools::Itertools;
use parking_lot::RwLock;
use ssz::ssz_encode;
use state_processing::per_block_processing::errors::{
    AttestationValidationError, AttesterSlashingValidationError, DepositValidationError,
    ExitValidationError, ProposerSlashingValidationError, TransferValidationError,
};
use state_processing::per_block_processing::{
    gather_attester_slashing_indices_modular, validate_attestation,
    validate_attestation_time_independent_only, verify_attester_slashing, verify_deposit,
    verify_exit, verify_exit_time_independent_only, verify_proposer_slashing, verify_transfer,
    verify_transfer_time_independent_only,
};
use std::collections::{btree_map::Entry, hash_map, BTreeMap, HashMap, HashSet};
use std::marker::PhantomData;
use types::chain_spec::Domain;
use types::{
    Attestation, AttestationData, AttesterSlashing, BeaconState, BeaconStateTypes, ChainSpec,
    Deposit, Epoch, ProposerSlashing, Transfer, Validator, VoluntaryExit,
};

#[cfg(test)]
const VERIFY_DEPOSIT_PROOFS: bool = false;
#[cfg(not(test))]
const VERIFY_DEPOSIT_PROOFS: bool = false; // TODO: enable this

#[derive(Default)]
pub struct OperationPool<T: BeaconStateTypes + Default> {
    /// Map from attestation ID (see below) to vectors of attestations.
    attestations: RwLock<HashMap<AttestationId, Vec<Attestation>>>,
    /// Map from deposit index to deposit data.
    // NOTE: We assume that there is only one deposit per index
    // because the Eth1 data is updated (at most) once per epoch,
    // and the spec doesn't seem to accomodate for re-orgs on a time-frame
    // longer than an epoch
    deposits: RwLock<BTreeMap<u64, Deposit>>,
    /// Map from two attestation IDs to a slashing for those IDs.
    attester_slashings: RwLock<HashMap<(AttestationId, AttestationId), AttesterSlashing>>,
    /// Map from proposer index to slashing.
    proposer_slashings: RwLock<HashMap<u64, ProposerSlashing>>,
    /// Map from exiting validator to their exit data.
    voluntary_exits: RwLock<HashMap<u64, VoluntaryExit>>,
    /// Set of transfers.
    transfers: RwLock<HashSet<Transfer>>,
    _phantom: PhantomData<T>,
}

/// Serialized `AttestationData` augmented with a domain to encode the fork info.
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
struct AttestationId(Vec<u8>);

/// Number of domain bytes that the end of an attestation ID is padded with.
const DOMAIN_BYTES_LEN: usize = 8;

impl AttestationId {
    fn from_data<T: BeaconStateTypes>(
        attestation: &AttestationData,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Self {
        let mut bytes = ssz_encode(attestation);
        let epoch = attestation.slot.epoch(spec.slots_per_epoch);
        bytes.extend_from_slice(&AttestationId::compute_domain_bytes(epoch, state, spec));
        AttestationId(bytes)
    }

    fn compute_domain_bytes<T: BeaconStateTypes>(
        epoch: Epoch,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Vec<u8> {
        int_to_bytes8(spec.get_domain(epoch, Domain::Attestation, &state.fork))
    }

    fn domain_bytes_match(&self, domain_bytes: &[u8]) -> bool {
        &self.0[self.0.len() - DOMAIN_BYTES_LEN..] == domain_bytes
    }
}

/// Compute a fitness score for an attestation.
///
/// The score is calculated by determining the number of *new* attestations that
/// the aggregate attestation introduces, and is proportional to the size of the reward we will
/// receive for including it in a block.
// TODO: this could be optimised with a map from validator index to whether that validator has
// attested in each of the current and previous epochs. Currently quadractic in number of validators.
fn attestation_score<T: BeaconStateTypes>(
    attestation: &Attestation,
    state: &BeaconState<T>,
    spec: &ChainSpec,
) -> usize {
    // Bitfield of validators whose attestations are new/fresh.
    let mut new_validators = attestation.aggregation_bitfield.clone();

    let attestation_epoch = attestation.data.slot.epoch(spec.slots_per_epoch);

    let state_attestations = if attestation_epoch == state.current_epoch(spec) {
        &state.current_epoch_attestations
    } else if attestation_epoch == state.previous_epoch(spec) {
        &state.previous_epoch_attestations
    } else {
        return 0;
    };

    state_attestations
        .iter()
        // In a single epoch, an attester should only be attesting for one shard.
        // TODO: we avoid including slashable attestations in the state here,
        // but maybe we should do something else with them (like construct slashings).
        .filter(|current_attestation| current_attestation.data.shard == attestation.data.shard)
        .for_each(|current_attestation| {
            // Remove the validators who have signed the existing attestation (they are not new)
            new_validators.difference_inplace(&current_attestation.aggregation_bitfield);
        });

    new_validators.num_set_bits()
}

#[derive(Debug, PartialEq, Clone)]
pub enum DepositInsertStatus {
    /// The deposit was not already in the pool.
    Fresh,
    /// The deposit already existed in the pool.
    Duplicate,
    /// The deposit conflicted with an existing deposit, which was replaced.
    Replaced(Box<Deposit>),
}

impl<T: BeaconStateTypes> OperationPool<T> {
    /// Create a new operation pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an attestation into the pool, aggregating it with existing attestations if possible.
    pub fn insert_attestation(
        &self,
        attestation: Attestation,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<(), AttestationValidationError> {
        // Check that attestation signatures are valid.
        validate_attestation_time_independent_only(state, &attestation, spec)?;

        let id = AttestationId::from_data(&attestation.data, state, spec);

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
    pub fn get_attestations(&self, state: &BeaconState<T>, spec: &ChainSpec) -> Vec<Attestation> {
        // Attestations for the current fork, which may be from the current or previous epoch.
        let prev_epoch = state.previous_epoch(spec);
        let current_epoch = state.current_epoch(spec);
        let prev_domain_bytes = AttestationId::compute_domain_bytes(prev_epoch, state, spec);
        let curr_domain_bytes = AttestationId::compute_domain_bytes(current_epoch, state, spec);
        self.attestations
            .read()
            .iter()
            .filter(|(key, _)| {
                key.domain_bytes_match(&prev_domain_bytes)
                    || key.domain_bytes_match(&curr_domain_bytes)
            })
            .flat_map(|(_, attestations)| attestations)
            // That are not superseded by an attestation included in the state...
            .filter(|attestation| !superior_attestation_exists_in_state(state, attestation))
            // That are valid...
            .filter(|attestation| validate_attestation(state, attestation, spec).is_ok())
            // Scored by the number of new attestations they introduce (descending)
            // TODO: need to consider attestations introduced in THIS block
            .map(|att| (att, attestation_score(att, state, spec)))
            // Don't include any useless attestations (score 0)
            .filter(|&(_, score)| score != 0)
            .sorted_by_key(|&(_, score)| std::cmp::Reverse(score))
            // Limited to the maximum number of attestations per block
            .take(spec.max_attestations as usize)
            .map(|(att, _)| att)
            .cloned()
            .collect()
    }

    /// Remove attestations which are too old to be included in a block.
    // TODO: we could probably prune other attestations here:
    // - ones that are completely covered by attestations included in the state
    // - maybe ones invalidated by the confirmation of one fork over another
    pub fn prune_attestations(&self, finalized_state: &BeaconState<T>, spec: &ChainSpec) {
        self.attestations.write().retain(|_, attestations| {
            // All the attestations in this bucket have the same data, so we only need to
            // check the first one.
            attestations.first().map_or(false, |att| {
                finalized_state.slot < att.data.slot + spec.slots_per_epoch
            })
        });
    }

    /// Add a deposit to the pool.
    ///
    /// No two distinct deposits should be added with the same index.
    pub fn insert_deposit(
        &self,
        deposit: Deposit,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<DepositInsertStatus, DepositValidationError> {
        use DepositInsertStatus::*;

        match self.deposits.write().entry(deposit.index) {
            Entry::Vacant(entry) => {
                verify_deposit(state, &deposit, VERIFY_DEPOSIT_PROOFS, spec)?;
                entry.insert(deposit);
                Ok(Fresh)
            }
            Entry::Occupied(mut entry) => {
                if entry.get() == &deposit {
                    Ok(Duplicate)
                } else {
                    verify_deposit(state, &deposit, VERIFY_DEPOSIT_PROOFS, spec)?;
                    Ok(Replaced(Box::new(entry.insert(deposit))))
                }
            }
        }
    }

    /// Get an ordered list of deposits for inclusion in a block.
    ///
    /// Take at most the maximum number of deposits, beginning from the current deposit index.
    pub fn get_deposits(&self, state: &BeaconState<T>, spec: &ChainSpec) -> Vec<Deposit> {
        let start_idx = state.deposit_index;
        (start_idx..start_idx + spec.max_deposits)
            .map(|idx| self.deposits.read().get(&idx).cloned())
            .take_while(Option::is_some)
            .flatten()
            .collect()
    }

    /// Remove all deposits with index less than the deposit index of the latest finalised block.
    pub fn prune_deposits(&self, state: &BeaconState<T>) -> BTreeMap<u64, Deposit> {
        let deposits_keep = self.deposits.write().split_off(&state.deposit_index);
        std::mem::replace(&mut self.deposits.write(), deposits_keep)
    }

    /// The number of deposits stored in the pool.
    pub fn num_deposits(&self) -> usize {
        self.deposits.read().len()
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
        verify_proposer_slashing(&slashing, state, spec)?;
        self.proposer_slashings
            .write()
            .insert(slashing.proposer_index, slashing);
        Ok(())
    }

    /// Compute the tuple ID that is used to identify an attester slashing.
    ///
    /// Depends on the fork field of the state, but not on the state's epoch.
    fn attester_slashing_id(
        slashing: &AttesterSlashing,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> (AttestationId, AttestationId) {
        (
            AttestationId::from_data(&slashing.slashable_attestation_1.data, state, spec),
            AttestationId::from_data(&slashing.slashable_attestation_2.data, state, spec),
        )
    }

    /// Insert an attester slashing into the pool.
    pub fn insert_attester_slashing(
        &self,
        slashing: AttesterSlashing,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<(), AttesterSlashingValidationError> {
        verify_attester_slashing(state, &slashing, true, spec)?;
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
    ) -> (Vec<ProposerSlashing>, Vec<AttesterSlashing>) {
        let proposer_slashings = filter_limit_operations(
            self.proposer_slashings.read().values(),
            |slashing| {
                state
                    .validator_registry
                    .get(slashing.proposer_index as usize)
                    .map_or(false, |validator| !validator.slashed)
            },
            spec.max_proposer_slashings,
        );

        // Set of validators to be slashed, so we don't attempt to construct invalid attester
        // slashings.
        let mut to_be_slashed = proposer_slashings
            .iter()
            .map(|s| s.proposer_index)
            .collect::<HashSet<_>>();

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
                let slashed_validators = gather_attester_slashing_indices_modular(
                    state,
                    slashing,
                    |index, validator| validator.slashed || to_be_slashed.contains(&index),
                    spec,
                );

                // Extend the `to_be_slashed` set so subsequent iterations don't try to include
                // useless slashings.
                if let Ok(validators) = slashed_validators {
                    to_be_slashed.extend(validators);
                    true
                } else {
                    false
                }
            })
            .take(spec.max_attester_slashings as usize)
            .map(|(_, slashing)| slashing.clone())
            .collect();

        (proposer_slashings, attester_slashings)
    }

    /// Prune proposer slashings for all slashed or withdrawn validators.
    pub fn prune_proposer_slashings(&self, finalized_state: &BeaconState<T>, spec: &ChainSpec) {
        prune_validator_hash_map(
            &mut self.proposer_slashings.write(),
            |validator| {
                validator.slashed
                    || validator.is_withdrawable_at(finalized_state.current_epoch(spec))
            },
            finalized_state,
        );
    }

    /// Prune attester slashings for all slashed or withdrawn validators, or attestations on another
    /// fork.
    pub fn prune_attester_slashings(&self, finalized_state: &BeaconState<T>, spec: &ChainSpec) {
        self.attester_slashings.write().retain(|id, slashing| {
            let fork_ok = &Self::attester_slashing_id(slashing, finalized_state, spec) == id;
            let curr_epoch = finalized_state.current_epoch(spec);
            let slashing_ok = gather_attester_slashing_indices_modular(
                finalized_state,
                slashing,
                |_, validator| validator.slashed || validator.is_withdrawable_at(curr_epoch),
                spec,
            )
            .is_ok();
            fork_ok && slashing_ok
        });
    }

    /// Insert a voluntary exit, validating it almost-entirely (future exits are permitted).
    pub fn insert_voluntary_exit(
        &self,
        exit: VoluntaryExit,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<(), ExitValidationError> {
        verify_exit_time_independent_only(state, &exit, spec)?;
        self.voluntary_exits
            .write()
            .insert(exit.validator_index, exit);
        Ok(())
    }

    /// Get a list of voluntary exits for inclusion in a block.
    pub fn get_voluntary_exits(
        &self,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Vec<VoluntaryExit> {
        filter_limit_operations(
            self.voluntary_exits.read().values(),
            |exit| verify_exit(state, exit, spec).is_ok(),
            spec.max_voluntary_exits,
        )
    }

    /// Prune if validator has already exited at the last finalized state.
    pub fn prune_voluntary_exits(&self, finalized_state: &BeaconState<T>, spec: &ChainSpec) {
        prune_validator_hash_map(
            &mut self.voluntary_exits.write(),
            |validator| validator.is_exited_at(finalized_state.current_epoch(spec)),
            finalized_state,
        );
    }

    /// Insert a transfer into the pool, checking it for validity in the process.
    pub fn insert_transfer(
        &self,
        transfer: Transfer,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<(), TransferValidationError> {
        // The signature of the transfer isn't hashed, but because we check
        // it before we insert into the HashSet, we can't end up with duplicate
        // transactions.
        verify_transfer_time_independent_only(state, &transfer, spec)?;
        self.transfers.write().insert(transfer);
        Ok(())
    }

    /// Get a list of transfers for inclusion in a block.
    // TODO: improve the economic optimality of this function by accounting for
    // dependencies between transfers in the same block e.g. A pays B, B pays C
    pub fn get_transfers(&self, state: &BeaconState<T>, spec: &ChainSpec) -> Vec<Transfer> {
        self.transfers
            .read()
            .iter()
            .filter(|transfer| verify_transfer(state, transfer, spec).is_ok())
            .sorted_by_key(|transfer| std::cmp::Reverse(transfer.fee))
            .take(spec.max_transfers as usize)
            .cloned()
            .collect()
    }

    /// Prune the set of transfers by removing all those whose slot has already passed.
    pub fn prune_transfers(&self, finalized_state: &BeaconState<T>) {
        self.transfers
            .write()
            .retain(|transfer| transfer.slot > finalized_state.slot)
    }

    /// Prune all types of transactions given the latest finalized state.
    pub fn prune_all(&self, finalized_state: &BeaconState<T>, spec: &ChainSpec) {
        self.prune_attestations(finalized_state, spec);
        self.prune_deposits(finalized_state);
        self.prune_proposer_slashings(finalized_state, spec);
        self.prune_attester_slashings(finalized_state, spec);
        self.prune_voluntary_exits(finalized_state, spec);
        self.prune_transfers(finalized_state);
    }
}

/// Returns `true` if the state already contains a `PendingAttestation` that is superior to the
/// given `attestation`.
///
/// A validator has nothing to gain from re-including an attestation and it adds load to the
/// network.
///
/// An existing `PendingAttestation` is superior to an existing `attestation` if:
///
/// - Their `AttestationData` is equal.
/// - `attestation` does not contain any signatures that `PendingAttestation` does not have.
fn superior_attestation_exists_in_state<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    attestation: &Attestation,
) -> bool {
    state
        .current_epoch_attestations
        .iter()
        .chain(state.previous_epoch_attestations.iter())
        .any(|existing_attestation| {
            let bitfield = &attestation.aggregation_bitfield;
            let existing_bitfield = &existing_attestation.aggregation_bitfield;

            existing_attestation.data == attestation.data
                && bitfield.intersection(existing_bitfield).num_set_bits()
                    == bitfield.num_set_bits()
        })
}

/// Filter up to a maximum number of operations out of an iterator.
fn filter_limit_operations<'a, T: 'a, I, F>(operations: I, filter: F, limit: u64) -> Vec<T>
where
    I: IntoIterator<Item = &'a T>,
    F: Fn(&T) -> bool,
    T: Clone,
{
    operations
        .into_iter()
        .filter(|x| filter(*x))
        .take(limit as usize)
        .cloned()
        .collect()
}

/// Remove all entries from the given hash map for which `prune_if` returns true.
///
/// The keys in the map should be validator indices, which will be looked up
/// in the state's validator registry and then passed to `prune_if`.
/// Entries for unknown validators will be kept.
fn prune_validator_hash_map<T, F, B: BeaconStateTypes>(
    map: &mut HashMap<u64, T>,
    prune_if: F,
    finalized_state: &BeaconState<B>,
) where
    F: Fn(&Validator) -> bool,
{
    map.retain(|&validator_index, _| {
        finalized_state
            .validator_registry
            .get(validator_index as usize)
            .map_or(true, |validator| !prune_if(validator))
    });
}

#[cfg(test)]
mod tests {
    use super::DepositInsertStatus::*;
    use super::*;
    use types::test_utils::*;
    use types::*;

    #[test]
    fn insert_deposit() {
        let rng = &mut XorShiftRng::from_seed([42; 16]);
        let (ref spec, ref state) = test_state(rng);
        let op_pool = OperationPool::new();
        let deposit1 = make_deposit(rng, state, spec);
        let mut deposit2 = make_deposit(rng, state, spec);
        deposit2.index = deposit1.index;

        assert_eq!(
            op_pool.insert_deposit(deposit1.clone(), state, spec),
            Ok(Fresh)
        );
        assert_eq!(
            op_pool.insert_deposit(deposit1.clone(), state, spec),
            Ok(Duplicate)
        );
        assert_eq!(
            op_pool.insert_deposit(deposit2, state, spec),
            Ok(Replaced(Box::new(deposit1)))
        );
    }

    #[test]
    fn get_deposits_max() {
        let rng = &mut XorShiftRng::from_seed([42; 16]);
        let (spec, mut state) = test_state(rng);
        let op_pool = OperationPool::new();
        let start = 10000;
        let max_deposits = spec.max_deposits;
        let extra = 5;
        let offset = 1;
        assert!(offset <= extra);

        let deposits = dummy_deposits(rng, &state, &spec, start, max_deposits + extra);

        for deposit in &deposits {
            assert_eq!(
                op_pool.insert_deposit(deposit.clone(), &state, &spec),
                Ok(Fresh)
            );
        }

        state.deposit_index = start + offset;
        let deposits_for_block = op_pool.get_deposits(&state, &spec);

        assert_eq!(deposits_for_block.len() as u64, max_deposits);
        assert_eq!(
            deposits_for_block[..],
            deposits[offset as usize..(offset + max_deposits) as usize]
        );
    }

    #[test]
    fn prune_deposits() {
        let rng = &mut XorShiftRng::from_seed([42; 16]);
        let (spec, state) = test_state(rng);
        let op_pool = OperationPool::new();

        let start1 = 100;
        // test is super slow in debug mode if this parameter is too high
        let count = 5;
        let gap = 25;
        let start2 = start1 + count + gap;

        let deposits1 = dummy_deposits(rng, &state, &spec, start1, count);
        let deposits2 = dummy_deposits(rng, &state, &spec, start2, count);

        for d in deposits1.into_iter().chain(deposits2) {
            assert!(op_pool.insert_deposit(d, &state, &spec).is_ok());
        }

        assert_eq!(op_pool.num_deposits(), 2 * count as usize);

        let mut state = BeaconState::random_for_test(rng);
        state.deposit_index = start1;

        // Pruning the first bunch of deposits in batches of 5 should work.
        let step = 5;
        let mut pool_size = step + 2 * count as usize;
        for i in (start1..=(start1 + count)).step_by(step) {
            state.deposit_index = i;
            op_pool.prune_deposits(&state);
            pool_size -= step;
            assert_eq!(op_pool.num_deposits(), pool_size);
        }
        assert_eq!(pool_size, count as usize);
        // Pruning in the gap should do nothing.
        for i in (start1 + count..start2).step_by(step) {
            state.deposit_index = i;
            op_pool.prune_deposits(&state);
            assert_eq!(op_pool.num_deposits(), count as usize);
        }
        // Same again for the later deposits.
        pool_size += step;
        for i in (start2..=(start2 + count)).step_by(step) {
            state.deposit_index = i;
            op_pool.prune_deposits(&state);
            pool_size -= step;
            assert_eq!(op_pool.num_deposits(), pool_size);
        }
        assert_eq!(op_pool.num_deposits(), 0);
    }

    // Create a random deposit (with a valid proof of posession)
    fn make_deposit<T: BeaconStateTypes>(
        rng: &mut XorShiftRng,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Deposit {
        let keypair = Keypair::random();
        let mut deposit = Deposit::random_for_test(rng);
        let mut deposit_input = DepositInput {
            pubkey: keypair.pk.clone(),
            withdrawal_credentials: Hash256::zero(),
            proof_of_possession: Signature::empty_signature(),
        };
        deposit_input.proof_of_possession = deposit_input.create_proof_of_possession(
            &keypair.sk,
            state.slot.epoch(spec.slots_per_epoch),
            &state.fork,
            spec,
        );
        deposit.deposit_data.deposit_input = deposit_input;
        deposit
    }

    // Create `count` dummy deposits with sequential deposit IDs beginning from `start`.
    fn dummy_deposits<T: BeaconStateTypes>(
        rng: &mut XorShiftRng,
        state: &BeaconState<T>,
        spec: &ChainSpec,
        start: u64,
        count: u64,
    ) -> Vec<Deposit> {
        let proto_deposit = make_deposit(rng, state, spec);
        (start..start + count)
            .map(|index| {
                let mut deposit = proto_deposit.clone();
                deposit.index = index;
                deposit
            })
            .collect()
    }

    fn test_state(rng: &mut XorShiftRng) -> (ChainSpec, BeaconState<FoundationStateTypes>) {
        let spec = FoundationStateTypes::spec();

        let mut state = BeaconState::random_for_test(rng);

        state.fork = Fork::genesis(&spec);

        (spec, state)
    }

    /// Create a signed attestation for use in tests.
    /// Signed by all validators in `committee[signing_range]` and `committee[extra_signer]`.
    #[cfg(not(debug_assertions))]
    fn signed_attestation<R: std::slice::SliceIndex<[usize], Output = [usize]>>(
        committee: &CrosslinkCommittee,
        keypairs: &[Keypair],
        signing_range: R,
        slot: Slot,
        state: &BeaconState,
        spec: &ChainSpec,
        extra_signer: Option<usize>,
    ) -> Attestation {
        let mut builder = TestingAttestationBuilder::new(
            state,
            &committee.committee,
            slot,
            committee.shard,
            spec,
        );
        let signers = &committee.committee[signing_range];
        let committee_keys = signers.iter().map(|&i| &keypairs[i].sk).collect::<Vec<_>>();
        builder.sign(signers, &committee_keys, &state.fork, spec);
        extra_signer.map(|c_idx| {
            let validator_index = committee.committee[c_idx];
            builder.sign(
                &[validator_index],
                &[&keypairs[validator_index].sk],
                &state.fork,
                spec,
            )
        });
        builder.build()
    }

    /// Test state for attestation-related tests.
    #[cfg(not(debug_assertions))]
    fn attestation_test_state(
        spec: &ChainSpec,
        num_committees: usize,
    ) -> (BeaconState, Vec<Keypair>) {
        let num_validators =
            num_committees * (spec.slots_per_epoch * spec.target_committee_size) as usize;
        let mut state_builder =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(num_validators, spec);
        let slot_offset = 1000 * spec.slots_per_epoch + spec.slots_per_epoch / 2;
        let slot = spec.genesis_slot + slot_offset;
        state_builder.teleport_to_slot(slot, spec);
        state_builder.build_caches(spec).unwrap();
        state_builder.build()
    }

    /// Set the latest crosslink in the state to match the attestation.
    #[cfg(not(debug_assertions))]
    fn fake_latest_crosslink(att: &Attestation, state: &mut BeaconState, spec: &ChainSpec) {
        state.latest_crosslinks[att.data.shard as usize] = Crosslink {
            crosslink_data_root: att.data.crosslink_data_root,
            epoch: att.data.slot.epoch(spec.slots_per_epoch),
        };
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_attestation_score() {
        let spec = &ChainSpec::foundation();
        let (ref mut state, ref keypairs) = attestation_test_state(spec, 1);
        let slot = state.slot - 1;
        let committees = state
            .get_crosslink_committees_at_slot(slot, spec)
            .unwrap()
            .clone();

        for committee in committees {
            let att1 = signed_attestation(&committee, keypairs, ..2, slot, state, spec, None);
            let att2 = signed_attestation(&committee, keypairs, .., slot, state, spec, None);

            assert_eq!(
                att1.aggregation_bitfield.num_set_bits(),
                attestation_score(&att1, state, spec)
            );

            state
                .current_epoch_attestations
                .push(PendingAttestation::from_attestation(&att1, state.slot));

            assert_eq!(
                committee.committee.len() - 2,
                attestation_score(&att2, state, spec)
            );
        }
    }

    /// End-to-end test of basic attestation handling.
    #[test]
    #[cfg(not(debug_assertions))]
    fn attestation_aggregation_insert_get_prune() {
        let spec = &ChainSpec::foundation();
        let (ref mut state, ref keypairs) = attestation_test_state(spec, 1);
        let op_pool = OperationPool::new();

        let slot = state.slot - 1;
        let committees = state
            .get_crosslink_committees_at_slot(slot, spec)
            .unwrap()
            .clone();

        assert_eq!(
            committees.len(),
            1,
            "we expect just one committee with this many validators"
        );

        for committee in &committees {
            let step_size = 2;
            for i in (0..committee.committee.len()).step_by(step_size) {
                let att = signed_attestation(
                    committee,
                    keypairs,
                    i..i + step_size,
                    slot,
                    state,
                    spec,
                    None,
                );
                fake_latest_crosslink(&att, state, spec);
                op_pool.insert_attestation(att, state, spec).unwrap();
            }
        }

        assert_eq!(op_pool.attestations.read().len(), committees.len());
        assert_eq!(op_pool.num_attestations(), committees.len());

        // Before the min attestation inclusion delay, get_attestations shouldn't return anything.
        assert_eq!(op_pool.get_attestations(state, spec).len(), 0);

        // Then once the delay has elapsed, we should get a single aggregated attestation.
        state.slot += spec.min_attestation_inclusion_delay;

        let block_attestations = op_pool.get_attestations(state, spec);
        assert_eq!(block_attestations.len(), committees.len());

        let agg_att = &block_attestations[0];
        assert_eq!(
            agg_att.aggregation_bitfield.num_set_bits(),
            spec.target_committee_size as usize
        );

        // Prune attestations shouldn't do anything at this point.
        op_pool.prune_attestations(state, spec);
        assert_eq!(op_pool.num_attestations(), committees.len());

        // But once we advance to an epoch after the attestation, it should prune it out of
        // existence.
        state.slot = slot + spec.slots_per_epoch;
        op_pool.prune_attestations(state, spec);
        assert_eq!(op_pool.num_attestations(), 0);
    }

    /// Adding an attestation already in the pool should not increase the size of the pool.
    #[test]
    #[cfg(not(debug_assertions))]
    fn attestation_duplicate() {
        let spec = &ChainSpec::foundation();
        let (ref mut state, ref keypairs) = attestation_test_state(spec, 1);
        let op_pool = OperationPool::new();

        let slot = state.slot - 1;
        let committees = state
            .get_crosslink_committees_at_slot(slot, spec)
            .unwrap()
            .clone();

        for committee in &committees {
            let att = signed_attestation(committee, keypairs, .., slot, state, spec, None);
            fake_latest_crosslink(&att, state, spec);
            op_pool
                .insert_attestation(att.clone(), state, spec)
                .unwrap();
            op_pool.insert_attestation(att, state, spec).unwrap();
        }

        assert_eq!(op_pool.num_attestations(), committees.len());
    }

    /// Adding lots of attestations that only intersect pairwise should lead to two aggregate
    /// attestations.
    #[test]
    #[cfg(not(debug_assertions))]
    fn attestation_pairwise_overlapping() {
        let spec = &ChainSpec::foundation();
        let (ref mut state, ref keypairs) = attestation_test_state(spec, 1);
        let op_pool = OperationPool::new();

        let slot = state.slot - 1;
        let committees = state
            .get_crosslink_committees_at_slot(slot, spec)
            .unwrap()
            .clone();

        let step_size = 2;
        for committee in &committees {
            // Create attestations that overlap on `step_size` validators, like:
            // {0,1,2,3}, {2,3,4,5}, {4,5,6,7}, ...
            for i in (0..committee.committee.len() - step_size).step_by(step_size) {
                let att = signed_attestation(
                    committee,
                    keypairs,
                    i..i + 2 * step_size,
                    slot,
                    state,
                    spec,
                    None,
                );
                fake_latest_crosslink(&att, state, spec);
                op_pool.insert_attestation(att, state, spec).unwrap();
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
    #[cfg(not(debug_assertions))]
    fn attestation_get_max() {
        let spec = &ChainSpec::foundation();
        let small_step_size = 2;
        let big_step_size = 4;
        let (ref mut state, ref keypairs) = attestation_test_state(spec, big_step_size);
        let op_pool = OperationPool::new();

        let slot = state.slot - 1;
        let committees = state
            .get_crosslink_committees_at_slot(slot, spec)
            .unwrap()
            .clone();

        let max_attestations = spec.max_attestations as usize;
        let target_committee_size = spec.target_committee_size as usize;

        let mut insert_attestations = |committee, step_size| {
            for i in (0..target_committee_size).step_by(step_size) {
                let att = signed_attestation(
                    committee,
                    keypairs,
                    i..i + step_size,
                    slot,
                    state,
                    spec,
                    if i == 0 { None } else { Some(0) },
                );
                fake_latest_crosslink(&att, state, spec);
                op_pool.insert_attestation(att, state, spec).unwrap();
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
        let best_attestations = op_pool.get_attestations(state, spec);
        assert_eq!(best_attestations.len(), max_attestations);

        // All the best attestations should be signed by at least `big_step_size` (4) validators.
        for att in &best_attestations {
            assert!(att.aggregation_bitfield.num_set_bits() >= big_step_size);
        }
    }

    // TODO: more tests
}
