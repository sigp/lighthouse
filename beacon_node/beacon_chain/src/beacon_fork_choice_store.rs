//! Defines the `BeaconForkChoiceStore` which provides the persistent storage for the `ForkChoice`
//! struct.
//!
//! Additionally, the private `BalancesCache` struct is defined; a cache designed to avoid database
//! reads when fork choice requires the validator balances of the justified state.

use crate::{metrics, BeaconSnapshot};
use fork_choice::ForkChoiceStore;
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use std::sync::Arc;
use store::{Error as StoreError, HotColdDB, ItemStore};
use types::{BeaconBlock, BeaconState, BeaconStateError, Checkpoint, EthSpec, Hash256, Slot};

#[derive(Debug)]
pub enum Error {
    UnableToReadSlot,
    UnableToReadTime,
    InvalidGenesisSnapshot(Slot),
    AncestorUnknown { ancestor_slot: Slot },
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

/// The number of validator balance sets that are cached within `BalancesCache`.
const MAX_BALANCE_CACHE_SIZE: usize = 4;

/// Returns the effective balances for every validator in the given `state`.
///
/// Any validator who is not active in the epoch of the given `state` is assigned a balance of
/// zero.
pub fn get_effective_balances<T: EthSpec>(state: &BeaconState<T>) -> Vec<u64> {
    state
        .validators()
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
    /// The effective balances from a `BeaconState` validator registry.
    balances: Vec<u64>,
}

/// Provides a cache to avoid reading `BeaconState` from disk when updating the current justified
/// checkpoint.
///
/// It is effectively a mapping of `epoch_boundary_block_root -> state.balances`.
#[derive(PartialEq, Clone, Default, Debug, Encode, Decode)]
struct BalancesCache {
    items: Vec<CacheItem>,
}

impl BalancesCache {
    /// Inspect the given `state` and determine the root of the block at the first slot of
    /// `state.current_epoch`. If there is not already some entry for the given block root, then
    /// add the effective balances from the `state` to the cache.
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
        let epoch_boundary_root = if epoch_boundary_slot == state.slot() {
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
            if slot < state.slot() {
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

/// Implements `fork_choice::ForkChoiceStore` in order to provide a persistent backing to the
/// `fork_choice::ForkChoice` struct.
#[derive(Debug)]
pub struct BeaconForkChoiceStore<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    store: Arc<HotColdDB<E, Hot, Cold>>,
    balances_cache: BalancesCache,
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: Vec<u64>,
    best_justified_checkpoint: Checkpoint,
    _phantom: PhantomData<E>,
}

impl<E, Hot, Cold> PartialEq for BeaconForkChoiceStore<E, Hot, Cold>
where
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    /// This implementation ignores the `store` and `slot_clock`.
    fn eq(&self, other: &Self) -> bool {
        self.balances_cache == other.balances_cache
            && self.time == other.time
            && self.finalized_checkpoint == other.finalized_checkpoint
            && self.justified_checkpoint == other.justified_checkpoint
            && self.justified_balances == other.justified_balances
            && self.best_justified_checkpoint == other.best_justified_checkpoint
    }
}

impl<E, Hot, Cold> BeaconForkChoiceStore<E, Hot, Cold>
where
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    /// Initialize `Self` from some `anchor` checkpoint which may or may not be the genesis state.
    ///
    /// ## Specification
    ///
    /// Equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#get_forkchoice_store
    ///
    /// ## Notes:
    ///
    /// It is assumed that `anchor` is already persisted in `store`.
    pub fn get_forkchoice_store(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        anchor: &BeaconSnapshot<E>,
    ) -> Self {
        let anchor_state = &anchor.beacon_state;
        let mut anchor_block_header = anchor_state.latest_block_header().clone();
        if anchor_block_header.state_root == Hash256::zero() {
            anchor_block_header.state_root = anchor.beacon_state_root();
        }
        let anchor_root = anchor_block_header.canonical_root();
        let anchor_epoch = anchor_state.current_epoch();
        let justified_checkpoint = Checkpoint {
            epoch: anchor_epoch,
            root: anchor_root,
        };
        let finalized_checkpoint = justified_checkpoint;

        Self {
            store,
            balances_cache: <_>::default(),
            time: anchor_state.slot(),
            justified_checkpoint,
            justified_balances: anchor_state.balances().clone().into(),
            finalized_checkpoint,
            best_justified_checkpoint: justified_checkpoint,
            _phantom: PhantomData,
        }
    }

    /// Save the current state of `Self` to a `PersistedForkChoiceStore` which can be stored to the
    /// on-disk database.
    pub fn to_persisted(&self) -> PersistedForkChoiceStore {
        PersistedForkChoiceStore {
            balances_cache: self.balances_cache.clone(),
            time: self.time,
            finalized_checkpoint: self.finalized_checkpoint,
            justified_checkpoint: self.justified_checkpoint,
            justified_balances: self.justified_balances.clone(),
            best_justified_checkpoint: self.best_justified_checkpoint,
        }
    }

    /// Restore `Self` from a previously-generated `PersistedForkChoiceStore`.
    pub fn from_persisted(
        persisted: PersistedForkChoiceStore,
        store: Arc<HotColdDB<E, Hot, Cold>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            store,
            balances_cache: persisted.balances_cache,
            time: persisted.time,
            finalized_checkpoint: persisted.finalized_checkpoint,
            justified_checkpoint: persisted.justified_checkpoint,
            justified_balances: persisted.justified_balances,
            best_justified_checkpoint: persisted.best_justified_checkpoint,
            _phantom: PhantomData,
        })
    }
}

impl<E, Hot, Cold> ForkChoiceStore<E> for BeaconForkChoiceStore<E, Hot, Cold>
where
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    type Error = Error;

    fn get_current_slot(&self) -> Slot {
        self.time
    }

    fn set_current_slot(&mut self, slot: Slot) {
        self.time = slot
    }

    fn on_verified_block(
        &mut self,
        _block: &BeaconBlock<E>,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Self::Error> {
        self.balances_cache.process_state(block_root, state)
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

    fn set_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.finalized_checkpoint = checkpoint
    }

    fn set_justified_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<(), Error> {
        self.justified_checkpoint = checkpoint;

        if let Some(balances) = self.balances_cache.get(self.justified_checkpoint.root) {
            metrics::inc_counter(&metrics::BALANCES_CACHE_HITS);
            self.justified_balances = balances;
        } else {
            metrics::inc_counter(&metrics::BALANCES_CACHE_MISSES);
            let justified_block = self
                .store
                .get_block(&self.justified_checkpoint.root)
                .map_err(Error::FailedToReadBlock)?
                .ok_or(Error::MissingBlock(self.justified_checkpoint.root))?
                .deconstruct()
                .0;

            self.justified_balances = self
                .store
                .get_state(&justified_block.state_root(), Some(justified_block.slot()))
                .map_err(Error::FailedToReadState)?
                .ok_or_else(|| Error::MissingState(justified_block.state_root()))?
                .balances()
                .clone()
                .into();
        }

        Ok(())
    }

    fn set_best_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.best_justified_checkpoint = checkpoint
    }
}

/// A container which allows persisting the `BeaconForkChoiceStore` to the on-disk database.
#[derive(Encode, Decode)]
pub struct PersistedForkChoiceStore {
    balances_cache: BalancesCache,
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: Vec<u64>,
    best_justified_checkpoint: Checkpoint,
}
