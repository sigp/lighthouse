use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use types::{BeaconCommittee, BeaconState, Epoch, EthSpec, ForkName, Slot};

// Max number of epochs this cache will store data for
pub const EFFECTIVE_BALANCE_CACHE_SIZE: usize = 8;

#[derive(Debug)]
pub enum Error {
    StateUnavailable(Epoch),
    CacheMiss(Epoch),
    ValidatorIndexUnknown(usize),
    EpochOutOfBounds(Epoch),
}

type CommitteeBalancesCache = HashMap<(Slot, u64), u64>;

#[derive(Clone)]
pub struct EffectiveBalancesCache {
    pub effective_balances: Arc<RwLock<BTreeMap<Epoch, Arc<Vec<u64>>>>>,
    pub committee_balances: Arc<RwLock<BTreeMap<Epoch, CommitteeBalancesCache>>>,
}

impl Default for EffectiveBalancesCache {
    fn default() -> Self {
        Self {
            effective_balances: Arc::new(RwLock::new(BTreeMap::new())),
            committee_balances: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
}

impl EffectiveBalancesCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn load_balances<E: EthSpec>(&self, state: &BeaconState<E>) {
        let state_epoch = state.current_epoch();
        let read_lock = self.effective_balances.upgradable_read();
        if read_lock.contains_key(&state_epoch) {
            return;
        }

        let mut write_lock = RwLockUpgradableReadGuard::upgrade(read_lock);

        // remove the oldest epoch if the cache is full
        while write_lock.len() >= EFFECTIVE_BALANCE_CACHE_SIZE {
            write_lock.pop_first();
        }

        let validators = state.validators();
        let mut balances = Vec::with_capacity(validators.len());
        for validator in validators {
            balances.push(validator.effective_balance);
        }

        write_lock.insert(state_epoch, Arc::new(balances));
    }

    pub fn load_epoch<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
        epoch: Epoch,
    ) -> Result<(), BeaconChainError> {
        if chain.spec.fork_name_at_epoch(epoch.saturating_add(1u64)) <= ForkName::Deneb {
            // the cache isn't necessary before electra
            return Ok(());
        }
        // ensure requested epoch is within range
        let current_epoch = chain.head().snapshot.beacon_state.current_epoch();
        if epoch.saturating_add(EFFECTIVE_BALANCE_CACHE_SIZE as u64) < current_epoch
            || epoch > current_epoch
        {
            return Err(Error::EpochOutOfBounds(epoch).into());
        }

        // quick check to see if the epoch is already loaded before loading a state from disk
        let read_lock = self.effective_balances.read();
        if read_lock.contains_key(&epoch) {
            return Ok(());
        }
        // loading the state from disk is slow so we don't want to be holding the lock
        drop(read_lock);

        if epoch == current_epoch {
            self.load_balances(&chain.head().snapshot.beacon_state);
            return Ok(());
        }

        // load state from disk
        let state_slot = epoch.start_slot(T::EthSpec::slots_per_epoch());
        let state_root = *chain
            .head()
            .snapshot
            .beacon_state
            .get_state_root(state_slot)?;

        let state = chain
            .get_state(&state_root, Some(state_slot))?
            .ok_or(Error::StateUnavailable(epoch))?;

        self.load_balances(&state);

        Ok(())
    }

    // will return the committee balance if the epoch is already loaded
    pub fn get_committee_balance<E: EthSpec>(
        &self,
        beacon_committee: &BeaconCommittee,
    ) -> Result<u64, BeaconChainError> {
        // We need the previous epoch to calculate the committee balance
        let balances_epoch = beacon_committee
            .slot
            .epoch(E::slots_per_epoch())
            .saturating_sub(1u64);

        // see if the value is cached in the committee_balances
        let read_lock = self.committee_balances.read();
        if let Some(committee_balance) = read_lock
            .get(&balances_epoch)
            .and_then(|map| map.get(&(beacon_committee.slot, beacon_committee.index)))
            .cloned()
        {
            return Ok(committee_balance);
        }
        drop(read_lock);

        // grab the epoch balances to calculate the committee balance
        let read_lock = self.effective_balances.read();
        let effective_balances = read_lock
            .get(&balances_epoch)
            .ok_or(Error::CacheMiss(balances_epoch))?
            // this clone is cheap because of the Arc
            .clone();
        drop(read_lock);

        let mut committee_balance = 0;
        for index in beacon_committee.committee {
            let balance = effective_balances
                .get(*index)
                .ok_or(Error::ValidatorIndexUnknown(*index))?;
            committee_balance += balance;
        }

        // cache the committee balance
        let mut write_lock = self.committee_balances.write();

        write_lock.entry(balances_epoch).or_default().insert(
            (beacon_committee.slot, beacon_committee.index),
            committee_balance,
        );

        // remove the oldest epoch if the cache is full
        while write_lock.len() > EFFECTIVE_BALANCE_CACHE_SIZE {
            write_lock.pop_first();
        }

        Ok(committee_balance)
    }

    pub fn get_effective_balance(
        &self,
        epoch: Epoch,
        validator_index: usize,
    ) -> Result<u64, BeaconChainError> {
        self.effective_balances
            .read()
            .get(&epoch)
            .ok_or(Error::CacheMiss(epoch))?
            .get(validator_index)
            .cloned()
            .ok_or(Error::ValidatorIndexUnknown(validator_index).into())
    }
}
