use crate::BeaconSnapshot;
use fork_choice::ForkChoiceStore as ForkChoiceStoreTrait;
use slot_clock::SlotClock;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::iter;
use std::marker::PhantomData;
use std::sync::Arc;
use store::iter::BlockRootsIterator;
use store::{DBColumn, Error as StoreError, Store, StoreItem};
use types::{
    BeaconBlock, BeaconState, BeaconStateError, ChainSpec, Checkpoint, EthSpec, Hash256,
    SignedBeaconBlock, Slot,
};

#[derive(Debug)]
pub enum Error {
    UnableToReadSlot,
    UnableToReadTime,
    InvalidGenesisSnapshot(Slot),
    AncestorUnknown(Hash256),
    UninitializedBestJustifiedBalances,
    FailedToReadBlock(StoreError),
    MissingBlock(Hash256),
    FailedToReadState(StoreError),
    MissingState(Hash256),
    InvalidPersistedBytes(ssz::DecodeError),
    BeaconStateError(BeaconStateError),
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconStateError(e)
    }
}

const MAX_BALANCE_CACHE_SIZE: usize = 4;

/// Returns the effective balances for every validator in the given `state`.
///
/// Any validator who is not active in the epoch of the given `state` is assigned a balance of
/// zero.
pub fn get_effective_balances<T: EthSpec>(state: &BeaconState<T>) -> Vec<u64> {
    state
        .validators
        .iter()
        .map(|validator| {
            if validator.is_active_at(state.current_epoch()) {
                validator.effective_balance
            } else {
                0
            }
        })
        .collect()
}

/// An item that is stored in the `BalancesCache`.
#[derive(PartialEq, Clone, Debug, Encode, Decode)]
struct CacheItem {
    /// The block root at which `self.balances` are valid.
    block_root: Hash256,
    /// The `state.balances` list.
    balances: Vec<u64>,
}

/// Provides a cache to avoid reading `BeaconState` from disk when updating the current justified
/// checkpoint.
///
/// It should store a mapping of `epoch_boundary_block_root -> state.balances`.
#[derive(PartialEq, Clone, Default, Debug, Encode, Decode)]
struct BalancesCache {
    items: Vec<CacheItem>,
}

impl BalancesCache {
    /// Inspect the given `state` and determine the root of the block at the first slot of
    /// `state.current_epoch`. If there is not already some entry for the given block root, then
    /// add `state.balances` to the cache.
    pub fn process_state<E: EthSpec>(
        &mut self,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        // We are only interested in balances from states that are at the start of an epoch,
        // because this is where the `current_justified_checkpoint.root` will point.
        if !Self::is_first_block_in_epoch(block_root, state)? {
            return Ok(());
        }

        let epoch_boundary_slot = state.current_epoch().start_slot(E::slots_per_epoch());
        let epoch_boundary_root = if epoch_boundary_slot == state.slot {
            block_root
        } else {
            // This call remains sensible as long as `state.block_roots` is larger than a single
            // epoch.
            *state.get_block_root(epoch_boundary_slot)?
        };

        if self.position(epoch_boundary_root).is_none() {
            let item = CacheItem {
                block_root: epoch_boundary_root,
                balances: get_effective_balances(state),
            };

            if self.items.len() == MAX_BALANCE_CACHE_SIZE {
                self.items.remove(0);
            }

            self.items.push(item);
        }

        Ok(())
    }

    /// Returns `true` if the given `block_root` is the first/only block to have been processed in
    /// the epoch of the given `state`.
    ///
    /// We can determine if it is the first block by looking back through `state.block_roots` to
    /// see if there is a block in the current epoch with a different root.
    fn is_first_block_in_epoch<E: EthSpec>(
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<bool, Error> {
        let mut prior_block_found = false;

        for slot in state.current_epoch().slot_iter(E::slots_per_epoch()) {
            if slot < state.slot {
                if *state.get_block_root(slot)? != block_root {
                    prior_block_found = true;
                    break;
                }
            } else {
                break;
            }
        }

        Ok(!prior_block_found)
    }

    fn position(&self, block_root: Hash256) -> Option<usize> {
        self.items
            .iter()
            .position(|item| item.block_root == block_root)
    }

    /// Get the balances for the given `block_root`, if any.
    ///
    /// If some balances are found, they are removed from the cache.
    pub fn get(&mut self, block_root: Hash256) -> Option<Vec<u64>> {
        let i = self.position(block_root)?;
        Some(self.items.remove(i).balances)
    }
}

#[derive(Debug)]
pub struct ForkChoiceStore<S, E> {
    store: Arc<S>,
    balances_cache: BalancesCache,
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: Vec<u64>,
    best_justified_checkpoint: Checkpoint,
    best_justified_balances: Option<Vec<u64>>,
    _phantom: PhantomData<E>,
}

impl<S, E> PartialEq for ForkChoiceStore<S, E> {
    /// This implementation ignores the `store` and `slot_clock`.
    fn eq(&self, other: &Self) -> bool {
        self.balances_cache == other.balances_cache
            && self.time == other.time
            && self.finalized_checkpoint == other.finalized_checkpoint
            && self.justified_checkpoint == other.justified_checkpoint
            && self.justified_balances == other.justified_balances
            && self.best_justified_checkpoint == other.best_justified_checkpoint
            && self.best_justified_balances == other.best_justified_balances
    }
}

impl<S: Store<E>, E: EthSpec> ForkChoiceStore<S, E> {
    pub fn from_genesis<C: SlotClock>(
        store: Arc<S>,
        slot_clock: &C,
        genesis: &BeaconSnapshot<E>,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let time = if slot_clock
            .is_prior_to_genesis()
            .ok_or_else(|| Error::UnableToReadTime)?
        {
            spec.genesis_slot
        } else {
            slot_clock.now().ok_or_else(|| Error::UnableToReadSlot)?
        };

        if genesis.beacon_state.slot != spec.genesis_slot {
            return Err(Error::InvalidGenesisSnapshot(genesis.beacon_state.slot));
        }

        Ok(Self {
            store,
            balances_cache: <_>::default(),
            time,
            finalized_checkpoint: genesis.beacon_state.finalized_checkpoint,
            justified_checkpoint: genesis.beacon_state.current_justified_checkpoint,
            justified_balances: genesis.beacon_state.balances.clone().into(),
            best_justified_checkpoint: genesis.beacon_state.current_justified_checkpoint,
            best_justified_balances: None,
            _phantom: PhantomData,
        })
    }

    pub fn to_persisted(&self) -> PersistedForkChoiceStore {
        PersistedForkChoiceStore {
            balances_cache: self.balances_cache.clone(),
            time: self.time,
            finalized_checkpoint: self.finalized_checkpoint,
            justified_checkpoint: self.justified_checkpoint,
            justified_balances: self.justified_balances.clone(),
            best_justified_checkpoint: self.best_justified_checkpoint,
            best_justified_balances: self.best_justified_balances.clone(),
        }
    }

    pub fn from_persisted(
        persisted: PersistedForkChoiceStore,
        store: Arc<S>,
    ) -> Result<Self, Error> {
        Ok(Self {
            store,
            balances_cache: persisted.balances_cache,
            time: persisted.time,
            finalized_checkpoint: persisted.finalized_checkpoint,
            justified_checkpoint: persisted.justified_checkpoint,
            justified_balances: persisted.justified_balances,
            best_justified_checkpoint: persisted.best_justified_checkpoint,
            best_justified_balances: persisted.best_justified_balances,
            _phantom: PhantomData,
        })
    }
}

impl<S: Store<E>, E: EthSpec> ForkChoiceStoreTrait<E> for ForkChoiceStore<S, E> {
    type Error = Error;

    fn get_current_slot(&self) -> Slot {
        self.time
    }

    fn set_current_slot(&mut self, slot: Slot) {
        self.time = slot
    }

    fn after_block(
        &mut self,
        _block: &BeaconBlock<E>,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Self::Error> {
        self.balances_cache.process_state(block_root, state)
    }

    fn set_justified_checkpoint_to_best_justified_checkpoint(&mut self) -> Result<(), Error> {
        if self.best_justified_balances.is_some() {
            self.justified_checkpoint = self.best_justified_checkpoint;
            self.justified_balances = self
                .best_justified_balances
                .take()
                .expect("protected by prior if statement");

            Ok(())
        } else {
            Err(Error::UninitializedBestJustifiedBalances)
        }
    }

    fn justified_checkpoint(&self) -> &Checkpoint {
        &self.justified_checkpoint
    }

    fn justified_balances(&self) -> &[u64] {
        &self.justified_balances
    }

    fn best_justified_checkpoint(&self) -> &Checkpoint {
        &self.best_justified_checkpoint
    }

    fn finalized_checkpoint(&self) -> &Checkpoint {
        &self.finalized_checkpoint
    }

    fn set_finalized_checkpoint(&mut self, c: Checkpoint) {
        self.finalized_checkpoint = c
    }

    fn set_justified_checkpoint(&mut self, state: &BeaconState<E>) -> Result<(), Error> {
        self.justified_checkpoint = state.current_justified_checkpoint;

        if let Some(balances) = self.balances_cache.get(self.justified_checkpoint.root) {
            self.justified_balances = balances;
        } else {
            let justified_block = self
                .store
                .get_item::<SignedBeaconBlock<E>>(&self.justified_checkpoint.root)
                .map_err(Error::FailedToReadBlock)?
                .ok_or_else(|| Error::MissingBlock(self.justified_checkpoint.root))?
                .message;

            self.justified_balances = self
                .store
                .get_state(&justified_block.state_root, Some(justified_block.slot))
                .map_err(Error::FailedToReadState)?
                .ok_or_else(|| Error::MissingState(justified_block.state_root))?
                .balances
                .into();
        }

        Ok(())
    }

    fn set_best_justified_checkpoint(&mut self, state: &BeaconState<E>) {
        self.best_justified_checkpoint = state.current_justified_checkpoint;
        self.best_justified_balances = Some(state.balances.clone().into());
    }

    fn ancestor_at_slot(
        &self,
        state: &BeaconState<E>,
        root: Hash256,
        ancestor_slot: Slot,
    ) -> Result<Hash256, Error> {
        let root = match state.get_block_root(ancestor_slot) {
            Ok(root) => *root,
            Err(_) => {
                let start_slot = state.slot;

                let iter = BlockRootsIterator::owned(self.store.clone(), state.clone());

                iter::once((root, start_slot))
                    .chain(iter)
                    .find(|(_, slot)| ancestor_slot == *slot)
                    .map(|(ancestor_block_root, _)| ancestor_block_root)
                    .ok_or_else(|| Error::AncestorUnknown(root))?
            }
        };

        Ok(root)
    }
}

#[derive(Encode, Decode)]
pub struct PersistedForkChoiceStore {
    balances_cache: BalancesCache,
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: Vec<u64>,
    best_justified_checkpoint: Checkpoint,
    best_justified_balances: Option<Vec<u64>>,
}

impl<S: Store<E>, E: EthSpec> From<&ForkChoiceStore<S, E>> for PersistedForkChoiceStore {
    fn from(store: &ForkChoiceStore<S, E>) -> Self {
        Self {
            balances_cache: store.balances_cache.clone(),
            time: store.time,
            finalized_checkpoint: store.finalized_checkpoint,
            justified_checkpoint: store.justified_checkpoint,
            justified_balances: store.justified_balances.clone(),
            best_justified_checkpoint: store.best_justified_checkpoint,
            best_justified_balances: store.best_justified_balances.clone(),
        }
    }
}

impl StoreItem for PersistedForkChoiceStore {
    fn db_column() -> DBColumn {
        DBColumn::ForkChoiceStore
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> std::result::Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
