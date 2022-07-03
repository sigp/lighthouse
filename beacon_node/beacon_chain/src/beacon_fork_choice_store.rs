//! Defines the `BeaconForkChoiceStore` which provides the persistent storage for the `ForkChoice`
//! struct.
//!
//! Additionally, the `BalancesCache` struct is defined; a cache designed to avoid database
//! reads when fork choice requires the validator balances of the justified state.

use crate::{metrics, BeaconSnapshot};
use derivative::Derivative;
use fork_choice::ForkChoiceStore;
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use std::sync::Arc;
use store::{Error as StoreError, HotColdDB, ItemStore};
use superstruct::superstruct;
use types::{
    BeaconBlockRef, BeaconState, BeaconStateError, Checkpoint, Epoch, EthSpec, ExecPayload,
    Hash256, Slot,
};

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

#[superstruct(
    variants(V1, V8),
    variant_attributes(derive(PartialEq, Clone, Debug, Encode, Decode)),
    no_enum
)]
pub(crate) struct CacheItem {
    pub(crate) block_root: Hash256,
    #[superstruct(only(V8))]
    pub(crate) epoch: Epoch,
    pub(crate) balances: Vec<u64>,
}

pub(crate) type CacheItem = CacheItemV8;

#[superstruct(
    variants(V1, V8),
    variant_attributes(derive(PartialEq, Clone, Default, Debug, Encode, Decode)),
    no_enum
)]
pub struct BalancesCache {
    #[superstruct(only(V1))]
    pub(crate) items: Vec<CacheItemV1>,
    #[superstruct(only(V8))]
    pub(crate) items: Vec<CacheItemV8>,
}

pub type BalancesCache = BalancesCacheV8;

impl BalancesCache {
    /// Inspect the given `state` and determine the root of the block at the first slot of
    /// `state.current_epoch`. If there is not already some entry for the given block root, then
    /// add the effective balances from the `state` to the cache.
    pub fn process_state<E: EthSpec>(
        &mut self,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        let epoch = state.current_epoch();
        let epoch_boundary_slot = epoch.start_slot(E::slots_per_epoch());
        let epoch_boundary_root = if epoch_boundary_slot == state.slot() {
            block_root
        } else {
            // This call remains sensible as long as `state.block_roots` is larger than a single
            // epoch.
            *state.get_block_root(epoch_boundary_slot)?
        };

        // Check if there already exists a cache entry for the epoch boundary block of the current
        // epoch. We rely on the invariant that effective balances do not change for the duration
        // of a single epoch, so even if the block on the epoch boundary itself is skipped we can
        // still update its cache entry from any subsequent state in that epoch.
        if self.position(epoch_boundary_root, epoch).is_none() {
            let item = CacheItem {
                block_root: epoch_boundary_root,
                epoch,
                balances: get_effective_balances(state),
            };

            if self.items.len() == MAX_BALANCE_CACHE_SIZE {
                self.items.remove(0);
            }

            self.items.push(item);
        }

        Ok(())
    }

    fn position(&self, block_root: Hash256, epoch: Epoch) -> Option<usize> {
        self.items
            .iter()
            .position(|item| item.block_root == block_root && item.epoch == epoch)
    }

    /// Get the balances for the given `block_root`, if any.
    ///
    /// If some balances are found, they are cloned from the cache.
    pub fn get(&mut self, block_root: Hash256, epoch: Epoch) -> Option<Vec<u64>> {
        let i = self.position(block_root, epoch)?;
        Some(self.items[i].balances.clone())
    }
}

/// Implements `fork_choice::ForkChoiceStore` in order to provide a persistent backing to the
/// `fork_choice::ForkChoice` struct.
#[derive(Debug, Derivative)]
#[derivative(PartialEq(bound = "E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>"))]
pub struct BeaconForkChoiceStore<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    #[derivative(PartialEq = "ignore")]
    store: Arc<HotColdDB<E, Hot, Cold>>,
    balances_cache: BalancesCache,
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: Vec<u64>,
    best_justified_checkpoint: Checkpoint,
    proposer_boost_root: Hash256,
    _phantom: PhantomData<E>,
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
            proposer_boost_root: Hash256::zero(),
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
            proposer_boost_root: self.proposer_boost_root,
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
            proposer_boost_root: persisted.proposer_boost_root,
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

    fn on_verified_block<Payload: ExecPayload<E>>(
        &mut self,
        _block: BeaconBlockRef<E, Payload>,
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

    fn proposer_boost_root(&self) -> Hash256 {
        self.proposer_boost_root
    }

    fn set_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.finalized_checkpoint = checkpoint
    }

    fn set_justified_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<(), Error> {
        self.justified_checkpoint = checkpoint;

        if let Some(balances) = self.balances_cache.get(
            self.justified_checkpoint.root,
            self.justified_checkpoint.epoch,
        ) {
            metrics::inc_counter(&metrics::BALANCES_CACHE_HITS);
            self.justified_balances = balances;
        } else {
            metrics::inc_counter(&metrics::BALANCES_CACHE_MISSES);
            let justified_block = self
                .store
                .get_blinded_block(&self.justified_checkpoint.root)
                .map_err(Error::FailedToReadBlock)?
                .ok_or(Error::MissingBlock(self.justified_checkpoint.root))?
                .deconstruct()
                .0;

            let state = self
                .store
                .get_state(&justified_block.state_root(), Some(justified_block.slot()))
                .map_err(Error::FailedToReadState)?
                .ok_or_else(|| Error::MissingState(justified_block.state_root()))?;

            self.justified_balances = get_effective_balances(&state);
        }

        Ok(())
    }

    fn set_best_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.best_justified_checkpoint = checkpoint
    }

    fn set_proposer_boost_root(&mut self, proposer_boost_root: Hash256) {
        self.proposer_boost_root = proposer_boost_root;
    }
}

/// A container which allows persisting the `BeaconForkChoiceStore` to the on-disk database.
#[superstruct(
    variants(V1, V7, V8),
    variant_attributes(derive(Encode, Decode)),
    no_enum
)]
pub struct PersistedForkChoiceStore {
    #[superstruct(only(V1, V7))]
    pub balances_cache: BalancesCacheV1,
    #[superstruct(only(V8))]
    pub balances_cache: BalancesCacheV8,
    pub time: Slot,
    pub finalized_checkpoint: Checkpoint,
    pub justified_checkpoint: Checkpoint,
    pub justified_balances: Vec<u64>,
    pub best_justified_checkpoint: Checkpoint,
    #[superstruct(only(V7, V8))]
    pub proposer_boost_root: Hash256,
}

pub type PersistedForkChoiceStore = PersistedForkChoiceStoreV8;
