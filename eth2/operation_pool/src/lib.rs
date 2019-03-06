use std::collections::{btree_map::Entry, BTreeMap, HashSet};

use state_processing::per_block_processing::{
    verify_deposit_merkle_proof, verify_exit, verify_proposer_slashing, verify_transfer,
    verify_transfer_partial,
};
use types::{
    AttesterSlashing, BeaconState, ChainSpec, Deposit, ProposerSlashing, Transfer, VoluntaryExit,
};

#[cfg(test)]
const VERIFY_DEPOSIT_PROOFS: bool = false;
#[cfg(not(test))]
const VERIFY_DEPOSIT_PROOFS: bool = true;

#[derive(Default)]
pub struct OperationPool {
    /// Map from deposit index to deposit data.
    // NOTE: We assume that there is only one deposit per index
    // because the Eth1 data is updated (at most) once per epoch,
    // and the spec doesn't seem to accomodate for re-orgs on a time-frame
    // longer than an epoch
    deposits: BTreeMap<u64, Deposit>,
    /// Map from attester index to slashing.
    attester_slashings: BTreeMap<u64, AttesterSlashing>,
    /// Map from proposer index to slashing.
    proposer_slashings: BTreeMap<u64, ProposerSlashing>,
    /// Map from exiting validator to their exit data.
    voluntary_exits: BTreeMap<u64, VoluntaryExit>,
    /// Set of transfers.
    transfers: HashSet<Transfer>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum DepositInsertStatus {
    /// The deposit was not already in the pool.
    Fresh,
    /// The deposit already existed in the pool.
    Duplicate,
    /// The deposit conflicted with an existing deposit, which was replaced.
    Replaced(Deposit),
}

impl OperationPool {
    /// Create a new operation pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a deposit to the pool.
    ///
    /// No two distinct deposits should be added with the same index.
    pub fn insert_deposit(&mut self, deposit: Deposit) -> DepositInsertStatus {
        use DepositInsertStatus::*;

        match self.deposits.entry(deposit.index) {
            Entry::Vacant(entry) => {
                entry.insert(deposit);
                Fresh
            }
            Entry::Occupied(mut entry) => {
                if entry.get() == &deposit {
                    Duplicate
                } else {
                    Replaced(entry.insert(deposit))
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
            .take_while(|deposit| {
                // NOTE: we don't use verify_deposit, because it requires the
                // deposit's index to match the state's, and we would like to return
                // a batch with increasing indices
                deposit.map_or(false, |deposit| {
                    !VERIFY_DEPOSIT_PROOFS || verify_deposit_merkle_proof(state, deposit, spec)
                })
            })
            .flatten()
            .cloned()
            .collect()
    }

    /// Remove all deposits with index less than the deposit index of the latest finalised block.
    pub fn prune_deposits(&mut self, state: &BeaconState) -> BTreeMap<u64, Deposit> {
        let deposits_keep = self.deposits.split_off(&state.deposit_index);
        std::mem::replace(&mut self.deposits, deposits_keep)
    }

    /// Insert a proposer slashing into the pool.
    pub fn insert_proposer_slashing(
        &mut self,
        slashing: ProposerSlashing,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Result<(), ()> {
        // TODO: should maybe insert anyway if the proposer is unknown in the validator index,
        // because they could *become* known later
        // FIXME: error handling
        verify_proposer_slashing(&slashing, state, spec).map_err(|_| ())?;
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
        let to_prune = self
            .proposer_slashings
            .keys()
            .flat_map(|&validator_index| {
                finalized_state
                    .validator_registry
                    .get(validator_index as usize)
                    .filter(|validator| {
                        validator.slashed
                            || validator.is_withdrawable_at(finalized_state.current_epoch(spec))
                    })
                    .map(|_| validator_index)
            })
            .collect::<Vec<_>>();

        for validator_index in to_prune {
            self.proposer_slashings.remove(&validator_index);
        }
    }

    // TODO: copy ProposerSlashing code for AttesterSlashing

    /// Insert a voluntary exit, validating it almost-entirely (future exits are permitted).
    pub fn insert_voluntary_exit(
        &mut self,
        exit: VoluntaryExit,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Result<(), ()> {
        verify_exit(state, &exit, spec, false).map_err(|_| ())?;
        self.voluntary_exits.insert(exit.validator_index, exit);
        Ok(())
    }

    /// Get a list of voluntary exits for inclusion in a block.
    // TODO: could optimise this by eliding the checks that have already been done on insert
    pub fn get_voluntary_exits(&self, state: &BeaconState, spec: &ChainSpec) -> Vec<VoluntaryExit> {
        filter_limit_operations(
            self.voluntary_exits.values(),
            |exit| verify_exit(state, exit, spec, true).is_ok(),
            spec.max_voluntary_exits,
        )
    }

    /// Prune if validator has already exited at the last finalized state.
    pub fn prune_voluntary_exits(&mut self, finalized_state: &BeaconState, spec: &ChainSpec) {
        let to_prune = self
            .voluntary_exits
            .keys()
            .flat_map(|&validator_index| {
                finalized_state
                    .validator_registry
                    .get(validator_index as usize)
                    .filter(|validator| validator.is_exited_at(finalized_state.current_epoch(spec)))
                    .map(|_| validator_index)
            })
            .collect::<Vec<_>>();

        for validator_index in to_prune {
            self.voluntary_exits.remove(&validator_index);
        }
    }

    /// Insert a transfer into the pool, checking it for validity in the process.
    pub fn insert_transfer(
        &mut self,
        transfer: Transfer,
        state: &BeaconState,
        spec: &ChainSpec,
    ) -> Result<(), ()> {
        // The signature of the transfer isn't hashed, but because we check
        // it before we insert into the HashSet, we can't end up with duplicate
        // transactions.
        verify_transfer_partial(state, &transfer, spec, true).map_err(|_| ())?;
        self.transfers.insert(transfer);
        Ok(())
    }

    /// Get a list of transfers for inclusion in a block.
    // TODO: improve the economic optimality of this function by taking the transfer
    // fees into account, and dependencies between transfers in the same block
    // e.g. A pays B, B pays C
    pub fn get_transfers(&self, state: &BeaconState, spec: &ChainSpec) -> Vec<Transfer> {
        filter_limit_operations(
            &self.transfers,
            |transfer| verify_transfer(state, transfer, spec).is_ok(),
            spec.max_transfers,
        )
    }

    /// Prune the set of transfers by removing all those whose slot has already passed.
    pub fn prune_transfers(&mut self, finalized_state: &BeaconState) {
        self.transfers = self
            .transfers
            .drain()
            .filter(|transfer| transfer.slot > finalized_state.slot)
            .collect();
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

#[cfg(test)]
mod tests {
    use super::DepositInsertStatus::*;
    use super::*;
    use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    fn insert_deposit() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut op_pool = OperationPool::new();
        let deposit1 = Deposit::random_for_test(&mut rng);
        let mut deposit2 = Deposit::random_for_test(&mut rng);
        deposit2.index = deposit1.index;

        assert_eq!(op_pool.insert_deposit(deposit1.clone()), Fresh);
        assert_eq!(op_pool.insert_deposit(deposit1.clone()), Duplicate);
        assert_eq!(op_pool.insert_deposit(deposit2), Replaced(deposit1));
    }

    #[test]
    fn get_deposits_max() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut op_pool = OperationPool::new();
        let spec = ChainSpec::foundation();
        let start = 10000;
        let max_deposits = spec.max_deposits;
        let extra = 5;
        let offset = 1;
        assert!(offset <= extra);

        let proto_deposit = Deposit::random_for_test(&mut rng);
        let deposits = (start..start + max_deposits + extra)
            .map(|index| {
                let mut deposit = proto_deposit.clone();
                deposit.index = index;
                deposit
            })
            .collect::<Vec<_>>();

        for deposit in &deposits {
            assert_eq!(op_pool.insert_deposit(deposit.clone()), Fresh);
        }

        let mut state = BeaconState::random_for_test(&mut rng);
        state.deposit_index = start + offset;
        let deposits_for_block = op_pool.get_deposits(&state, &spec);

        assert_eq!(deposits_for_block.len() as u64, max_deposits);
        assert_eq!(
            deposits_for_block[..],
            deposits[offset as usize..(offset + max_deposits) as usize]
        );
    }

    // TODO: more tests
}
