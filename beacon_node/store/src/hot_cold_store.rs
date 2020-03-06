use crate::chunked_vector::{
    store_updated_vector, BlockRoots, HistoricalRoots, RandaoMixes, StateRoots,
};
use crate::config::StoreConfig;
use crate::forwards_iter::HybridForwardsBlockRootsIterator;
use crate::impls::beacon_state::store_full_state;
use crate::iter::{ParentRootBlockIterator, StateRootsIterator};
use crate::metrics;
use crate::{
    leveldb_store::LevelDB, DBColumn, Error, PartialBeaconState, SimpleStoreItem, Store, StoreItem,
};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use slog::{debug, trace, warn, Logger};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
    SlotProcessingError,
};
use std::convert::TryInto;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use types::*;

/// 32-byte key for accessing the `split` of the freezer DB.
pub const SPLIT_DB_KEY: &str = "FREEZERDBSPLITFREEZERDBSPLITFREE";

/// On-disk database that stores finalized states efficiently.
///
/// Stores vector fields like the `block_roots` and `state_roots` separately, and only stores
/// intermittent "restore point" states pre-finalization.
pub struct HotColdDB<E: EthSpec> {
    /// The slot and state root at the point where the database is split between hot and cold.
    ///
    /// States with slots less than `split.slot` are in the cold DB, while states with slots
    /// greater than or equal are in the hot DB.
    split: RwLock<Split>,
    config: StoreConfig,
    /// Cold database containing compact historical data.
    pub(crate) cold_db: LevelDB<E>,
    /// Hot database containing duplicated but quick-to-access recent data.
    ///
    /// The hot database also contains all blocks.
    pub(crate) hot_db: LevelDB<E>,
    /// LRU cache of deserialized blocks. Updated whenever a block is loaded.
    block_cache: Mutex<LruCache<Hash256, SignedBeaconBlock<E>>>,
    /// Chain spec.
    spec: ChainSpec,
    /// Logger.
    pub(crate) log: Logger,
    /// Mere vessel for E.
    _phantom: PhantomData<E>,
}

#[derive(Debug, PartialEq)]
pub enum HotColdDBError {
    /// Recoverable error indicating that the database freeze point couldn't be updated
    /// due to the finalized block not lying on an epoch boundary (should be infrequent).
    FreezeSlotUnaligned(Slot),
    FreezeSlotError {
        current_split_slot: Slot,
        proposed_split_slot: Slot,
    },
    MissingStateToFreeze(Hash256),
    MissingRestorePointHash(u64),
    MissingRestorePoint(Hash256),
    MissingColdStateSummary(Hash256),
    MissingHotStateSummary(Hash256),
    MissingEpochBoundaryState(Hash256),
    MissingSplitState(Hash256, Slot),
    HotStateSummaryError(BeaconStateError),
    RestorePointDecodeError(ssz::DecodeError),
    BlockReplayBeaconError(BeaconStateError),
    BlockReplaySlotError(SlotProcessingError),
    BlockReplayBlockError(BlockProcessingError),
    InvalidSlotsPerRestorePoint {
        slots_per_restore_point: u64,
        slots_per_historical_root: u64,
        slots_per_epoch: u64,
    },
    RestorePointBlockHashError(BeaconStateError),
}

impl<E: EthSpec> Store<E> for HotColdDB<E> {
    type ForwardsBlockRootsIterator = HybridForwardsBlockRootsIterator<E>;

    // Defer to the hot database for basic operations (including blocks for now)
    fn get_bytes(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.hot_db.get_bytes(column, key)
    }

    fn put_bytes(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.hot_db.put_bytes(column, key, value)
    }

    fn key_exists(&self, column: &str, key: &[u8]) -> Result<bool, Error> {
        self.hot_db.key_exists(column, key)
    }

    fn key_delete(&self, column: &str, key: &[u8]) -> Result<(), Error> {
        self.hot_db.key_delete(column, key)
    }

    /// Store a block and update the LRU cache.
    fn put_block(&self, block_root: &Hash256, block: SignedBeaconBlock<E>) -> Result<(), Error> {
        // Store on disk.
        self.put(block_root, &block)?;

        // Update cache.
        self.block_cache.lock().put(*block_root, block);

        Ok(())
    }

    /// Fetch a block from the store.
    fn get_block(&self, block_root: &Hash256) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_BLOCK_GET_COUNT);

        // Check the cache.
        if let Some(block) = self.block_cache.lock().get(block_root) {
            metrics::inc_counter(&metrics::BEACON_BLOCK_CACHE_HIT_COUNT);
            return Ok(Some(block.clone()));
        }

        // Fetch from database.
        match self.get::<SignedBeaconBlock<E>>(block_root)? {
            Some(block) => {
                // Add to cache.
                self.block_cache.lock().put(*block_root, block.clone());
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Delete a block from the store and the block cache.
    fn delete_block(&self, block_root: &Hash256) -> Result<(), Error> {
        self.block_cache.lock().pop(block_root);
        self.delete::<SignedBeaconBlock<E>>(block_root)
    }

    /// Store a state in the store.
    fn put_state(&self, state_root: &Hash256, state: &BeaconState<E>) -> Result<(), Error> {
        if state.slot < self.get_split_slot() {
            self.store_cold_state(state_root, &state)
        } else {
            self.store_hot_state(state_root, state)
        }
    }

    /// Fetch a state from the store.
    fn get_state(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<E>>, Error> {
        self.get_state_with(state_root, slot)
    }

    /// Get a state from the store.
    ///
    /// Fetch a state from the store, controlling which cache fields are cloned.
    fn get_state_with(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_STATE_GET_COUNT);

        if let Some(slot) = slot {
            if slot < self.get_split_slot() {
                self.load_cold_state_by_slot(slot).map(Some)
            } else {
                self.load_hot_state(state_root)
            }
        } else {
            match self.load_hot_state(state_root)? {
                Some(state) => Ok(Some(state)),
                None => self.load_cold_state(state_root),
            }
        }
    }

    /// Delete a state, ensuring it is removed from the LRU cache, as well as from on-disk.
    ///
    /// It is assumed that all states being deleted reside in the hot DB, even if their slot is less
    /// than the split point. You shouldn't delete states from the finalized portion of the chain
    /// (which are frozen, and won't be deleted), or valid descendents of the finalized checkpoint
    /// (which will be deleted by this function but shouldn't be).
    fn delete_state(&self, state_root: &Hash256, slot: Slot) -> Result<(), Error> {
        // Delete the state summary.
        self.hot_db
            .key_delete(DBColumn::BeaconStateSummary.into(), state_root.as_bytes())?;

        // Delete the full state if it lies on an epoch boundary.
        if slot % E::slots_per_epoch() == 0 {
            self.hot_db
                .key_delete(DBColumn::BeaconState.into(), state_root.as_bytes())?;
        }

        Ok(())
    }

    /// Advance the split point of the store, moving new finalized states to the freezer.
    fn freeze_to_state(
        store: Arc<Self>,
        frozen_head_root: Hash256,
        frozen_head: &BeaconState<E>,
    ) -> Result<(), Error> {
        debug!(
            store.log,
            "Freezer migration started";
            "slot" => frozen_head.slot
        );

        // 0. Check that the migration is sensible.
        // The new frozen head must increase the current split slot, and lie on an epoch
        // boundary (in order for the hot state summary scheme to work).
        let current_split_slot = store.get_split_slot();

        if frozen_head.slot < current_split_slot {
            return Err(HotColdDBError::FreezeSlotError {
                current_split_slot,
                proposed_split_slot: frozen_head.slot,
            }
            .into());
        }

        if frozen_head.slot % E::slots_per_epoch() != 0 {
            return Err(HotColdDBError::FreezeSlotUnaligned(frozen_head.slot).into());
        }

        // 1. Copy all of the states between the head and the split slot, from the hot DB
        // to the cold DB.
        let state_root_iter = StateRootsIterator::new(store.clone(), frozen_head);

        let mut to_delete = vec![];
        for (state_root, slot) in
            state_root_iter.take_while(|&(_, slot)| slot >= current_split_slot)
        {
            if slot % store.config.slots_per_restore_point == 0 {
                let state: BeaconState<E> = store
                    .hot_db
                    .get_state(&state_root, None)?
                    .ok_or_else(|| HotColdDBError::MissingStateToFreeze(state_root))?;

                store.store_cold_state(&state_root, &state)?;
            }

            // Store a pointer from this state root to its slot, so we can later reconstruct states
            // from their state root alone.
            store.store_cold_state_slot(&state_root, slot)?;

            // Delete the old summary, and the full state if we lie on an epoch boundary.
            to_delete.push((state_root, slot));
        }

        // 2. Update the split slot
        *store.split.write() = Split {
            slot: frozen_head.slot,
            state_root: frozen_head_root,
        };
        store.store_split()?;

        // 3. Delete from the hot DB
        for (state_root, slot) in to_delete {
            store.delete_state(&state_root, slot)?;
        }

        debug!(
            store.log,
            "Freezer migration complete";
            "slot" => frozen_head.slot
        );

        Ok(())
    }

    fn forwards_block_roots_iterator(
        store: Arc<Self>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Self::ForwardsBlockRootsIterator {
        HybridForwardsBlockRootsIterator::new(store, start_slot, end_state, end_block_root, spec)
    }

    /// Load an epoch boundary state by using the hot state summary look-up.
    ///
    /// Will fall back to the cold DB if a hot state summary is not found.
    fn load_epoch_boundary_state(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<BeaconState<E>>, Error> {
        if let Some(HotStateSummary {
            epoch_boundary_state_root,
            ..
        }) = self.load_hot_state_summary(state_root)?
        {
            // NOTE: minor inefficiency here because we load an unnecessary hot state summary
            let state = self
                .load_hot_state(&epoch_boundary_state_root)?
                .ok_or_else(|| {
                    HotColdDBError::MissingEpochBoundaryState(epoch_boundary_state_root)
                })?;
            Ok(Some(state))
        } else {
            // Try the cold DB
            match self.load_cold_state_slot(state_root)? {
                Some(state_slot) => {
                    let epoch_boundary_slot =
                        state_slot / E::slots_per_epoch() * E::slots_per_epoch();
                    self.load_cold_state_by_slot(epoch_boundary_slot).map(Some)
                }
                None => Ok(None),
            }
        }
    }
}

impl<E: EthSpec> HotColdDB<E> {
    /// Open a new or existing database, with the given paths to the hot and cold DBs.
    ///
    /// The `slots_per_restore_point` parameter must be a divisor of `SLOTS_PER_HISTORICAL_ROOT`.
    pub fn open(
        hot_path: &Path,
        cold_path: &Path,
        config: StoreConfig,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<Self, Error> {
        Self::verify_slots_per_restore_point(config.slots_per_restore_point)?;

        let db = HotColdDB {
            split: RwLock::new(Split::default()),
            cold_db: LevelDB::open(cold_path)?,
            hot_db: LevelDB::open(hot_path)?,
            block_cache: Mutex::new(LruCache::new(config.block_cache_size)),
            config,
            spec,
            log,
            _phantom: PhantomData,
        };

        // Load the previous split slot from the database (if any). This ensures we can
        // stop and restart correctly.
        if let Some(split) = db.load_split()? {
            *db.split.write() = split;
        }
        Ok(db)
    }

    /// Store a post-finalization state efficiently in the hot database.
    ///
    /// On an epoch boundary, store a full state. On an intermediate slot, store
    /// just a backpointer to the nearest epoch boundary.
    pub fn store_hot_state(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        // On the epoch boundary, store the full state.
        if state.slot % E::slots_per_epoch() == 0 {
            trace!(
                self.log,
                "Storing full state on epoch boundary";
                "slot" => state.slot.as_u64(),
                "state_root" => format!("{:?}", state_root)
            );
            store_full_state(&self.hot_db, state_root, &state)?;
        }

        // Store a summary of the state.
        // We store one even for the epoch boundary states, as we may need their slots
        // when doing a look up by state root.
        self.put_state_summary(state_root, HotStateSummary::new(state_root, state)?)?;

        Ok(())
    }

    /// Load a post-finalization state from the hot database.
    ///
    /// Will replay blocks from the nearest epoch boundary.
    pub fn load_hot_state(&self, state_root: &Hash256) -> Result<Option<BeaconState<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_STATE_HOT_GET_COUNT);

        if let Some(HotStateSummary {
            slot,
            latest_block_root,
            epoch_boundary_state_root,
        }) = self.load_hot_state_summary(state_root)?
        {
            let boundary_state = self
                .hot_db
                .get_state(&epoch_boundary_state_root, None)?
                .ok_or_else(|| {
                    HotColdDBError::MissingEpochBoundaryState(epoch_boundary_state_root)
                })?;

            // Optimization to avoid even *thinking* about replaying blocks if we're already
            // on an epoch boundary.
            let state = if slot % E::slots_per_epoch() == 0 {
                boundary_state
            } else {
                let blocks =
                    self.load_blocks_to_replay(boundary_state.slot, slot, latest_block_root)?;
                self.replay_blocks(boundary_state, blocks, slot)?
            };

            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    /// Store a pre-finalization state in the freezer database.
    ///
    /// Will log a warning and not store anything if the state does not lie on a restore point
    /// boundary.
    pub fn store_cold_state(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        if state.slot % self.config.slots_per_restore_point != 0 {
            warn!(
                self.log,
                "Not storing non-restore point state in freezer";
                "slot" => state.slot.as_u64(),
                "state_root" => format!("{:?}", state_root)
            );
            return Ok(());
        }

        trace!(
            self.log,
            "Creating restore point";
            "slot" => state.slot,
            "state_root" => format!("{:?}", state_root)
        );

        // 1. Convert to PartialBeaconState and store that in the DB.
        let partial_state = PartialBeaconState::from_state_forgetful(state);
        partial_state.db_put(&self.cold_db, state_root)?;

        // 2. Store updated vector entries.
        let db = &self.cold_db;
        store_updated_vector(BlockRoots, db, state, &self.spec)?;
        store_updated_vector(StateRoots, db, state, &self.spec)?;
        store_updated_vector(HistoricalRoots, db, state, &self.spec)?;
        store_updated_vector(RandaoMixes, db, state, &self.spec)?;

        // 3. Store restore point.
        let restore_point_index = state.slot.as_u64() / self.config.slots_per_restore_point;
        self.store_restore_point_hash(restore_point_index, *state_root)?;

        Ok(())
    }

    /// Try to load a pre-finalization state from the freezer database.
    ///
    /// Return `None` if no state with `state_root` lies in the freezer.
    pub fn load_cold_state(&self, state_root: &Hash256) -> Result<Option<BeaconState<E>>, Error> {
        match self.load_cold_state_slot(state_root)? {
            Some(slot) => self.load_cold_state_by_slot(slot).map(Some),
            None => Ok(None),
        }
    }

    /// Load a pre-finalization state from the freezer database.
    ///
    /// Will reconstruct the state if it lies between restore points.
    pub fn load_cold_state_by_slot(&self, slot: Slot) -> Result<BeaconState<E>, Error> {
        if slot % self.config.slots_per_restore_point == 0 {
            let restore_point_idx = slot.as_u64() / self.config.slots_per_restore_point;
            self.load_restore_point_by_index(restore_point_idx)
        } else {
            self.load_cold_intermediate_state(slot)
        }
    }

    /// Load a restore point state by its `state_root`.
    fn load_restore_point(&self, state_root: &Hash256) -> Result<BeaconState<E>, Error> {
        let mut partial_state = PartialBeaconState::db_get(&self.cold_db, state_root)?
            .ok_or_else(|| HotColdDBError::MissingRestorePoint(*state_root))?;

        // Fill in the fields of the partial state.
        partial_state.load_block_roots(&self.cold_db, &self.spec)?;
        partial_state.load_state_roots(&self.cold_db, &self.spec)?;
        partial_state.load_historical_roots(&self.cold_db, &self.spec)?;
        partial_state.load_randao_mixes(&self.cold_db, &self.spec)?;

        Ok(partial_state.try_into()?)
    }

    /// Load a restore point state by its `restore_point_index`.
    fn load_restore_point_by_index(
        &self,
        restore_point_index: u64,
    ) -> Result<BeaconState<E>, Error> {
        let state_root = self.load_restore_point_hash(restore_point_index)?;
        self.load_restore_point(&state_root)
    }

    /// Load a frozen state that lies between restore points.
    fn load_cold_intermediate_state(&self, slot: Slot) -> Result<BeaconState<E>, Error> {
        // 1. Load the restore points either side of the intermediate state.
        let low_restore_point_idx = slot.as_u64() / self.config.slots_per_restore_point;
        let high_restore_point_idx = low_restore_point_idx + 1;

        // Acquire the read lock, so that the split can't change while this is happening.
        let split = self.split.read();

        let low_restore_point = self.load_restore_point_by_index(low_restore_point_idx)?;
        // If the slot of the high point lies outside the freezer, use the split state
        // as the upper restore point.
        let high_restore_point = if high_restore_point_idx * self.config.slots_per_restore_point
            >= split.slot.as_u64()
        {
            self.get_state(&split.state_root, Some(split.slot))?
                .ok_or_else(|| HotColdDBError::MissingSplitState(split.state_root, split.slot))?
        } else {
            self.load_restore_point_by_index(high_restore_point_idx)?
        };

        // 2. Load the blocks from the high restore point back to the low restore point.
        let blocks = self.load_blocks_to_replay(
            low_restore_point.slot,
            slot,
            self.get_high_restore_point_block_root(&high_restore_point, slot)?,
        )?;

        // 3. Replay the blocks on top of the low restore point.
        self.replay_blocks(low_restore_point, blocks, slot)
    }

    /// Get a suitable block root for backtracking from `high_restore_point` to the state at `slot`.
    ///
    /// Defaults to the block root for `slot`, which *should* be in range.
    fn get_high_restore_point_block_root(
        &self,
        high_restore_point: &BeaconState<E>,
        slot: Slot,
    ) -> Result<Hash256, HotColdDBError> {
        high_restore_point
            .get_block_root(slot)
            .or_else(|_| high_restore_point.get_oldest_block_root())
            .map(|x| *x)
            .map_err(HotColdDBError::RestorePointBlockHashError)
    }

    /// Load the blocks between `start_slot` and `end_slot` by backtracking from `end_block_hash`.
    ///
    /// Blocks are returned in slot-ascending order, suitable for replaying on a state with slot
    /// equal to `start_slot`, to reach a state with slot equal to `end_slot`.
    fn load_blocks_to_replay(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        end_block_hash: Hash256,
    ) -> Result<Vec<SignedBeaconBlock<E>>, Error> {
        let mut blocks = ParentRootBlockIterator::new(self, end_block_hash)
            .map(|(_, block)| block)
            // Include the block at the end slot (if any), it needs to be
            // replayed in order to construct the canonical state at `end_slot`.
            .filter(|block| block.message.slot <= end_slot)
            // Include the block at the start slot (if any). Whilst it doesn't need to be applied
            // to the state, it contains a potentially useful state root.
            .take_while(|block| block.message.slot >= start_slot)
            .collect::<Vec<_>>();
        blocks.reverse();
        Ok(blocks)
    }

    /// Replay `blocks` on top of `state` until `target_slot` is reached.
    ///
    /// Will skip slots as necessary. The returned state is not guaranteed
    /// to have any caches built, beyond those immediately required by block processing.
    fn replay_blocks(
        &self,
        mut state: BeaconState<E>,
        blocks: Vec<SignedBeaconBlock<E>>,
        target_slot: Slot,
    ) -> Result<BeaconState<E>, Error> {
        let state_root_from_prev_block = |i: usize, state: &BeaconState<E>| {
            if i > 0 {
                let prev_block = &blocks[i - 1].message;
                if prev_block.slot == state.slot {
                    Some(prev_block.state_root)
                } else {
                    None
                }
            } else {
                None
            }
        };

        for (i, block) in blocks.iter().enumerate() {
            if block.message.slot <= state.slot {
                continue;
            }

            while state.slot < block.message.slot {
                let state_root = state_root_from_prev_block(i, &state);
                per_slot_processing(&mut state, state_root, &self.spec)
                    .map_err(HotColdDBError::BlockReplaySlotError)?;
            }
            per_block_processing(
                &mut state,
                &block,
                None,
                BlockSignatureStrategy::NoVerification,
                &self.spec,
            )
            .map_err(HotColdDBError::BlockReplayBlockError)?;
        }

        while state.slot < target_slot {
            let state_root = state_root_from_prev_block(blocks.len(), &state);
            per_slot_processing(&mut state, state_root, &self.spec)
                .map_err(HotColdDBError::BlockReplaySlotError)?;
        }

        Ok(state)
    }

    /// Fetch a copy of the current split slot from memory.
    pub fn get_split_slot(&self) -> Slot {
        self.split.read().slot
    }

    /// Fetch the slot of the most recently stored restore point.
    pub fn get_latest_restore_point_slot(&self) -> Slot {
        (self.get_split_slot() - 1) / self.config.slots_per_restore_point
            * self.config.slots_per_restore_point
    }

    /// Load the split point from disk.
    fn load_split(&self) -> Result<Option<Split>, Error> {
        let key = Hash256::from_slice(SPLIT_DB_KEY.as_bytes());
        let split: Option<Split> = self.hot_db.get(&key)?;
        Ok(split)
    }

    /// Store the split point on disk.
    fn store_split(&self) -> Result<(), Error> {
        let key = Hash256::from_slice(SPLIT_DB_KEY.as_bytes());
        self.hot_db.put(&key, &*self.split.read())?;
        Ok(())
    }

    /// Load the state root of a restore point.
    fn load_restore_point_hash(&self, restore_point_index: u64) -> Result<Hash256, Error> {
        let key = Self::restore_point_key(restore_point_index);
        RestorePointHash::db_get(&self.cold_db, &key)?
            .map(|r| r.state_root)
            .ok_or_else(|| HotColdDBError::MissingRestorePointHash(restore_point_index).into())
    }

    /// Store the state root of a restore point.
    fn store_restore_point_hash(
        &self,
        restore_point_index: u64,
        state_root: Hash256,
    ) -> Result<(), Error> {
        let key = Self::restore_point_key(restore_point_index);
        RestorePointHash { state_root }
            .db_put(&self.cold_db, &key)
            .map_err(Into::into)
    }

    /// Convert a `restore_point_index` into a database key.
    fn restore_point_key(restore_point_index: u64) -> Hash256 {
        Hash256::from_low_u64_be(restore_point_index)
    }

    /// Load a frozen state's slot, given its root.
    fn load_cold_state_slot(&self, state_root: &Hash256) -> Result<Option<Slot>, Error> {
        Ok(ColdStateSummary::db_get(&self.cold_db, state_root)?.map(|s| s.slot))
    }

    /// Store the slot of a frozen state.
    fn store_cold_state_slot(&self, state_root: &Hash256, slot: Slot) -> Result<(), Error> {
        ColdStateSummary { slot }
            .db_put(&self.cold_db, state_root)
            .map_err(Into::into)
    }

    /// Load a hot state's summary, given its root.
    pub fn load_hot_state_summary(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<HotStateSummary>, Error> {
        HotStateSummary::db_get(&self.hot_db, state_root)
    }

    /// Check that the restore point frequency is valid.
    ///
    /// Specifically, check that it is:
    /// (1) A divisor of the number of slots per historical root, and
    /// (2) Divisible by the number of slots per epoch
    ///
    ///
    /// (1) ensures that we have at least one restore point within range of our state
    /// root history when iterating backwards (and allows for more frequent restore points if
    /// desired).
    ///
    /// (2) ensures that restore points align with hot state summaries, making it
    /// quick to migrate hot to cold.
    fn verify_slots_per_restore_point(slots_per_restore_point: u64) -> Result<(), HotColdDBError> {
        let slots_per_historical_root = E::SlotsPerHistoricalRoot::to_u64();
        let slots_per_epoch = E::slots_per_epoch();
        if slots_per_restore_point > 0
            && slots_per_historical_root % slots_per_restore_point == 0
            && slots_per_restore_point % slots_per_epoch == 0
        {
            Ok(())
        } else {
            Err(HotColdDBError::InvalidSlotsPerRestorePoint {
                slots_per_restore_point,
                slots_per_historical_root,
                slots_per_epoch,
            })
        }
    }
}

/// Struct for storing the split slot and state root in the database.
#[derive(Debug, Clone, Copy, Default, Encode, Decode)]
struct Split {
    slot: Slot,
    state_root: Hash256,
}

impl SimpleStoreItem for Split {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

/// Struct for summarising a state in the hot database.
///
/// Allows full reconstruction by replaying blocks.
#[derive(Debug, Clone, Copy, Default, Encode, Decode)]
pub struct HotStateSummary {
    slot: Slot,
    latest_block_root: Hash256,
    epoch_boundary_state_root: Hash256,
}

impl SimpleStoreItem for HotStateSummary {
    fn db_column() -> DBColumn {
        DBColumn::BeaconStateSummary
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

impl HotStateSummary {
    /// Construct a new summary of the given state.
    pub fn new<E: EthSpec>(state_root: &Hash256, state: &BeaconState<E>) -> Result<Self, Error> {
        // Fill in the state root on the latest block header if necessary (this happens on all
        // slots where there isn't a skip).
        let latest_block_root = state.get_latest_block_root(*state_root);
        let epoch_boundary_slot = state.slot / E::slots_per_epoch() * E::slots_per_epoch();
        let epoch_boundary_state_root = if epoch_boundary_slot == state.slot {
            *state_root
        } else {
            *state
                .get_state_root(epoch_boundary_slot)
                .map_err(HotColdDBError::HotStateSummaryError)?
        };

        Ok(HotStateSummary {
            slot: state.slot,
            latest_block_root,
            epoch_boundary_state_root,
        })
    }
}

/// Struct for summarising a state in the freezer database.
#[derive(Debug, Clone, Copy, Default, Encode, Decode)]
struct ColdStateSummary {
    slot: Slot,
}

impl SimpleStoreItem for ColdStateSummary {
    fn db_column() -> DBColumn {
        DBColumn::BeaconStateSummary
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

/// Struct for storing the state root of a restore point in the database.
#[derive(Debug, Clone, Copy, Default, Encode, Decode)]
struct RestorePointHash {
    state_root: Hash256,
}

impl SimpleStoreItem for RestorePointHash {
    fn db_column() -> DBColumn {
        DBColumn::BeaconRestorePoint
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}
