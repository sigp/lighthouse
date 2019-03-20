use int_to_bytes::int_to_bytes8;
use itertools::Itertools;
use ssz::ssz_encode;
use state_processing::per_block_processing::errors::{
    AttestationValidationError, DepositValidationError, ExitValidationError,
    ProposerSlashingValidationError, TransferValidationError,
};
use state_processing::per_block_processing::{
    validate_attestation, validate_attestation_time_independent_only, verify_deposit, verify_exit,
    verify_exit_time_independent_only, verify_proposer_slashing, verify_transfer,
    verify_transfer_time_independent_only,
};
use std::collections::{btree_map::Entry, hash_map, BTreeMap, HashMap, HashSet};
use types::chain_spec::Domain;
use types::{
    Attestation, AttestationData, AttesterSlashing, BeaconState, ChainSpec, Deposit, Epoch,
    ProposerSlashing, Transfer, Validator, VoluntaryExit,
};

#[cfg(test)]
const VERIFY_DEPOSIT_PROOFS: bool = false;
#[cfg(not(test))]
const VERIFY_DEPOSIT_PROOFS: bool = true;

#[derive(Default)]
pub struct OperationPool {
    /// Map from attestation ID (see below) to vectors of attestations.
    attestations: HashMap<AttestationId, Vec<Attestation>>,
    /// Map from deposit index to deposit data.
    // NOTE: We assume that there is only one deposit per index
    // because the Eth1 data is updated (at most) once per epoch,
    // and the spec doesn't seem to accomodate for re-orgs on a time-frame
    // longer than an epoch
    deposits: BTreeMap<u64, Deposit>,
    /// Map from attester index to slashing.
    attester_slashings: HashMap<u64, AttesterSlashing>,
    /// Map from proposer index to slashing.
    proposer_slashings: HashMap<u64, ProposerSlashing>,
    /// Map from exiting validator to their exit data.
    voluntary_exits: HashMap<u64, VoluntaryExit>,
    /// Set of transfers.
    transfers: HashSet<Transfer>,
}

/// Serialized `AttestationData` augmented with a domain to encode the fork info.
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
struct AttestationId(Vec<u8>);

/// Number of domain bytes that the end of an attestation ID is padded with.
const DOMAIN_BYTES_LEN: usize = 8;

impl AttestationId {
    fn from_data(attestation: &AttestationData, state: &BeaconState, spec: &ChainSpec) -> Self {
        let mut bytes = ssz_encode(attestation);
        let epoch = attestation.slot.epoch(spec.slots_per_epoch);
        bytes.extend_from_slice(&AttestationId::compute_domain_bytes(epoch, state, spec));
        AttestationId(bytes)
    }

    fn compute_domain_bytes(epoch: Epoch, state: &BeaconState, spec: &ChainSpec) -> Vec<u8> {
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
// attested in the *current* epoch. Alternatively, we could cache an index that allows us to
// quickly look up the attestations in the current epoch for a given shard.
fn attestation_score(attestation: &Attestation, state: &BeaconState) -> usize {
    // Bitfield of validators whose attestations are new/fresh.
    let mut new_validators = attestation.aggregation_bitfield.clone();

    state
        .current_epoch_attestations
        .iter()
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

impl OperationPool {
    /// Create a new operation pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an attestation into the pool, aggregating it with existing attestations if possible.
    pub fn insert_attestation(
        &mut self,
        attestation: Attestation,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Result<(), AttestationValidationError> {
        // Check that attestation signatures are valid.
        validate_attestation_time_independent_only(state, &attestation, spec)?;

        let id = AttestationId::from_data(&attestation.data, state, spec);

        let existing_attestations = match self.attestations.entry(id) {
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

    /// Get a list of attestations for inclusion in a block.
    pub fn get_attestations(&self, state: &BeaconState, spec: &ChainSpec) -> Vec<Attestation> {
        // Attestations for the current fork...
        // FIXME: should we also check domain bytes for the previous epoch?
        let current_epoch = state.slot.epoch(spec.slots_per_epoch);
        let domain_bytes = AttestationId::compute_domain_bytes(current_epoch, state, spec);
        self.attestations
            .iter()
            .filter(|(key, _)| key.domain_bytes_match(&domain_bytes))
            .flat_map(|(_, attestations)| attestations)
            // That are valid...
            .filter(|attestation| validate_attestation(state, attestation, spec).is_ok())
            // Scored by the number of new attestations they introduce (descending)
            .map(|att| (att, attestation_score(att, state)))
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
    pub fn prune_attestations(&mut self, finalized_state: &BeaconState, spec: &ChainSpec) {
        self.attestations.retain(|_, attestations| {
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
        &mut self,
        deposit: Deposit,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Result<DepositInsertStatus, DepositValidationError> {
        use DepositInsertStatus::*;

        match self.deposits.entry(deposit.index) {
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
    pub fn get_deposits(&self, state: &BeaconState, spec: &ChainSpec) -> Vec<Deposit> {
        let start_idx = state.deposit_index;
        (start_idx..start_idx + spec.max_deposits)
            .map(|idx| self.deposits.get(&idx))
            .take_while(Option::is_some)
            .flatten()
            .cloned()
            .collect()
    }

    /// Remove all deposits with index less than the deposit index of the latest finalised block.
    pub fn prune_deposits(&mut self, state: &BeaconState) -> BTreeMap<u64, Deposit> {
        let deposits_keep = self.deposits.split_off(&state.deposit_index);
        std::mem::replace(&mut self.deposits, deposits_keep)
    }

    /// The number of deposits stored in the pool.
    pub fn num_deposits(&self) -> usize {
        self.deposits.len()
    }

    /// Insert a proposer slashing into the pool.
    pub fn insert_proposer_slashing(
        &mut self,
        slashing: ProposerSlashing,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Result<(), ProposerSlashingValidationError> {
        // TODO: should maybe insert anyway if the proposer is unknown in the validator index,
        // because they could *become* known later
        verify_proposer_slashing(&slashing, state, spec)?;
        self.proposer_slashings
            .insert(slashing.proposer_index, slashing);
        Ok(())
    }

    /// Only check whether the implicated validator has already been slashed, because
    /// all slashings in the pool were validated upon insertion.
    // TODO: we need a mechanism to avoid including a proposer slashing and an attester
    // slashing for the same validator in the same block
    pub fn get_proposer_slashings(
        &self,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Vec<ProposerSlashing> {
        // We sort by validator index, which is safe, because a validator can only supply
        // so many valid slashings for lower-indexed validators (and even that is unlikely)
        filter_limit_operations(
            self.proposer_slashings.values(),
            |slashing| {
                state
                    .validator_registry
                    .get(slashing.proposer_index as usize)
                    .map_or(false, |validator| !validator.slashed)
            },
            spec.max_proposer_slashings,
        )
    }

    /// Prune slashings for all slashed or withdrawn validators.
    pub fn prune_proposer_slashings(&mut self, finalized_state: &BeaconState, spec: &ChainSpec) {
        prune_validator_hash_map(
            &mut self.proposer_slashings,
            |validator| {
                validator.slashed
                    || validator.is_withdrawable_at(finalized_state.current_epoch(spec))
            },
            finalized_state,
        );
    }

    // FIXME: copy ProposerSlashing code for AttesterSlashing

    /// Insert a voluntary exit, validating it almost-entirely (future exits are permitted).
    pub fn insert_voluntary_exit(
        &mut self,
        exit: VoluntaryExit,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Result<(), ExitValidationError> {
        verify_exit_time_independent_only(state, &exit, spec)?;
        self.voluntary_exits.insert(exit.validator_index, exit);
        Ok(())
    }

    /// Get a list of voluntary exits for inclusion in a block.
    pub fn get_voluntary_exits(&self, state: &BeaconState, spec: &ChainSpec) -> Vec<VoluntaryExit> {
        filter_limit_operations(
            self.voluntary_exits.values(),
            |exit| verify_exit(state, exit, spec).is_ok(),
            spec.max_voluntary_exits,
        )
    }

    /// Prune if validator has already exited at the last finalized state.
    pub fn prune_voluntary_exits(&mut self, finalized_state: &BeaconState, spec: &ChainSpec) {
        prune_validator_hash_map(
            &mut self.voluntary_exits,
            |validator| validator.is_exited_at(finalized_state.current_epoch(spec)),
            finalized_state,
        );
    }

    /// Insert a transfer into the pool, checking it for validity in the process.
    pub fn insert_transfer(
        &mut self,
        transfer: Transfer,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Result<(), TransferValidationError> {
        // The signature of the transfer isn't hashed, but because we check
        // it before we insert into the HashSet, we can't end up with duplicate
        // transactions.
        verify_transfer_time_independent_only(state, &transfer, spec)?;
        self.transfers.insert(transfer);
        Ok(())
    }

    /// Get a list of transfers for inclusion in a block.
    // TODO: improve the economic optimality of this function by accounting for
    // dependencies between transfers in the same block e.g. A pays B, B pays C
    pub fn get_transfers(&self, state: &BeaconState, spec: &ChainSpec) -> Vec<Transfer> {
        self.transfers
            .iter()
            .filter(|transfer| verify_transfer(state, transfer, spec).is_ok())
            .sorted_by_key(|transfer| std::cmp::Reverse(transfer.fee))
            .take(spec.max_transfers as usize)
            .cloned()
            .collect()
    }

    /// Prune the set of transfers by removing all those whose slot has already passed.
    pub fn prune_transfers(&mut self, finalized_state: &BeaconState) {
        self.transfers = self
            .transfers
            .drain()
            .filter(|transfer| transfer.slot > finalized_state.slot)
            .collect();
    }

    /// Prune all types of transactions given the latest finalized state.
    pub fn prune_all(&mut self, finalized_state: &BeaconState, spec: &ChainSpec) {
        self.prune_attestations(finalized_state, spec);
        self.prune_deposits(finalized_state);
        self.prune_proposer_slashings(finalized_state, spec);
        // FIXME: add attester slashings
        self.prune_voluntary_exits(finalized_state, spec);
        self.prune_transfers(finalized_state);
    }
}

/// Filter up to a maximum number of operations out of a slice.
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
fn prune_validator_hash_map<T, F>(
    map: &mut HashMap<u64, T>,
    prune_if: F,
    finalized_state: &BeaconState,
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
    use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use types::*;

    #[test]
    fn insert_deposit() {
        let rng = &mut XorShiftRng::from_seed([42; 16]);
        let (ref spec, ref state) = test_state(rng);
        let mut op_pool = OperationPool::new();
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
        let mut op_pool = OperationPool::new();
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
        let mut op_pool = OperationPool::new();

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
    fn make_deposit(rng: &mut XorShiftRng, state: &BeaconState, spec: &ChainSpec) -> Deposit {
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
    fn dummy_deposits(
        rng: &mut XorShiftRng,
        state: &BeaconState,
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

    fn test_state(rng: &mut XorShiftRng) -> (ChainSpec, BeaconState) {
        let spec = ChainSpec::foundation();
        let mut state = BeaconState::random_for_test(rng);
        state.fork = Fork::genesis(&spec);

        (spec, state)
    }

    // TODO: more tests
}
