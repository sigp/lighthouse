use crate::chunked_vector::{
    store_updated_vector, BlockRoots, HistoricalRoots, RandaoMixes, StateRoots,
};
use crate::config::StoreConfig;
use crate::forwards_iter::HybridForwardsBlockRootsIterator;
use crate::impls::beacon_state::{get_full_state, store_full_state};
use crate::iter::{ParentRootBlockIterator, StateRootsIterator};
use crate::leveldb_store::LevelDB;
use crate::memory_store::MemoryStore;
use crate::metrics;
use crate::{
    get_key_for_col, DBColumn, Error, ItemStore, KeyValueStoreOp, PartialBeaconState, StoreItem,
    StoreOp,
};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use slog::{debug, error, trace, warn, Logger};
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
#[derive(Debug)]
pub struct HotColdDB<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    /// The slot and state root at the point where the database is split between hot and cold.
    ///
    /// States with slots less than `split.slot` are in the cold DB, while states with slots
    /// greater than or equal are in the hot DB.
    split: RwLock<Split>,
    config: StoreConfig,
    /// Cold database containing compact historical data.
    pub(crate) cold_db: Cold,
    /// Hot database containing duplicated but quick-to-access recent data.
    ///
    /// The hot database also contains all blocks.
    pub(crate) hot_db: Hot,
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

impl<E: EthSpec> HotColdDB<E, MemoryStore<E>, MemoryStore<E>> {
    pub fn open_ephemeral(
        config: StoreConfig,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<HotColdDB<E, MemoryStore<E>, MemoryStore<E>>, Error> {
        Self::verify_slots_per_restore_point(config.slots_per_restore_point)?;

        let db = HotColdDB {
            split: RwLock::new(Split::default()),
            cold_db: MemoryStore::open(),
            hot_db: MemoryStore::open(),
            block_cache: Mutex::new(LruCache::new(config.block_cache_size)),
            config,
            spec,
            log,
            _phantom: PhantomData,
        };

        Ok(db)
    }
}

impl<E: EthSpec> HotColdDB<E, LevelDB<E>, LevelDB<E>> {
    /// Open a new or existing database, with the given paths to the hot and cold DBs.
    ///
    /// The `slots_per_restore_point` parameter must be a divisor of `SLOTS_PER_HISTORICAL_ROOT`.
    pub fn open(
        hot_path: &Path,
        cold_path: &Path,
        config: StoreConfig,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<HotColdDB<E, LevelDB<E>, LevelDB<E>>, Error> {
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
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> HotColdDB<E, Hot, Cold> {
    /// Store a block and update the LRU cache.
    pub fn put_block(
        &self,
        block_root: &Hash256,
        block: SignedBeaconBlock<E>,
    ) -> Result<(), Error> {
        // Store on disk.
        self.hot_db.put(block_root, &block)?;

        // Update cache.
        self.block_cache.lock().put(*block_root, block);

        Ok(())
    }

    /// Fetch a block from the store.
    pub fn get_block(&self, block_root: &Hash256) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_BLOCK_GET_COUNT);

        // Check the cache.
        if let Some(block) = self.block_cache.lock().get(block_root) {
            metrics::inc_counter(&metrics::BEACON_BLOCK_CACHE_HIT_COUNT);
            return Ok(Some(block.clone()));
        }

        // Fetch from database.
        match self.hot_db.get::<SignedBeaconBlock<E>>(block_root)? {
            Some(block) => {
                // Add to cache.
                self.block_cache.lock().put(*block_root, block.clone());
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Delete a block from the store and the block cache.
    pub fn delete_block(&self, block_root: &Hash256) -> Result<(), Error> {
        self.block_cache.lock().pop(block_root);
        self.hot_db.delete::<SignedBeaconBlock<E>>(block_root)
    }

    pub fn put_state_summary(
        &self,
        state_root: &Hash256,
        summary: HotStateSummary,
    ) -> Result<(), Error> {
        self.hot_db.put(state_root, &summary).map_err(Into::into)
    }

    /// Store a state in the store.
    pub fn put_state(&self, state_root: &Hash256, state: &BeaconState<E>) -> Result<(), Error> {
        if state.slot < self.get_split_slot() {
            let mut ops: Vec<KeyValueStoreOp> = Vec::new();
            self.store_cold_state(state_root, &state, &mut ops)?;
            self.cold_db.do_atomically(ops)
        } else {
            let mut ops: Vec<KeyValueStoreOp> = Vec::new();
            self.store_hot_state(state_root, state, &mut ops)?;
            self.hot_db.do_atomically(ops)
        }
    }

    /// Fetch a state from the store.
    ///
    /// If `slot` is provided then it will be used as a hint as to which database should
    /// be checked. Importantly, if the slot hint is provided and indicates a slot that lies
    /// in the freezer database, then only the freezer database will be accessed and `Ok(None)`
    /// will be returned if the provided `state_root` doesn't match the state root of the
    /// frozen state at `slot`. Consequently, if a state from a non-canonical chain is desired, it's
    /// best to set `slot` to `None`, or call `load_hot_state` directly.
    pub fn get_state(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_STATE_GET_COUNT);

        if let Some(slot) = slot {
            if slot < self.get_split_slot() {
                // Although we could avoid a DB lookup by shooting straight for the
                // frozen state using `load_cold_state_by_slot`, that would be incorrect
                // in the case where the caller provides a `state_root` that's off the canonical
                // chain. This way we avoid returning a state that doesn't match `state_root`.
                self.load_cold_state(state_root)
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
    pub fn delete_state(&self, state_root: &Hash256, slot: Slot) -> Result<(), Error> {
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

    pub fn forwards_block_roots_iterator(
        store: Arc<Self>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>>, Error> {
        HybridForwardsBlockRootsIterator::new(store, start_slot, end_state, end_block_root, spec)
    }

    /// Load an epoch boundary state by using the hot state summary look-up.
    ///
    /// Will fall back to the cold DB if a hot state summary is not found.
    pub fn load_epoch_boundary_state(
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

    pub fn put_item<I: StoreItem>(&self, key: &Hash256, item: &I) -> Result<(), Error> {
        self.hot_db.put(key, item)
    }

    pub fn get_item<I: StoreItem>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        self.hot_db.get(key)
    }

    pub fn item_exists<I: StoreItem>(&self, key: &Hash256) -> Result<bool, Error> {
        self.hot_db.exists::<I>(key)
    }

    pub fn do_atomically(&self, batch: Vec<StoreOp<E>>) -> Result<(), Error> {
        let mut guard = self.block_cache.lock();

        let mut key_value_batch: Vec<KeyValueStoreOp> = Vec::with_capacity(batch.len());
        for op in &batch {
            match op {
                StoreOp::PutBlock(block_hash, block) => {
                    let untyped_hash: Hash256 = (*block_hash).into();
                    key_value_batch.push(block.as_kv_store_op(untyped_hash));
                }

                StoreOp::PutState(state_hash, state) => {
                    let untyped_hash: Hash256 = (*state_hash).into();
                    self.store_hot_state(&untyped_hash, state, &mut key_value_batch)?;
                }

                StoreOp::PutStateSummary(state_hash, summary) => {
                    let untyped_hash: Hash256 = (*state_hash).into();
                    key_value_batch.push(summary.as_kv_store_op(untyped_hash));
                }

                StoreOp::DeleteBlock(block_hash) => {
                    let untyped_hash: Hash256 = (*block_hash).into();
                    let key =
                        get_key_for_col(DBColumn::BeaconBlock.into(), untyped_hash.as_bytes());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(key));
                }

                StoreOp::DeleteState(state_hash, slot) => {
                    let untyped_hash: Hash256 = (*state_hash).into();
                    let state_summary_key = get_key_for_col(
                        DBColumn::BeaconStateSummary.into(),
                        untyped_hash.as_bytes(),
                    );
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(state_summary_key));

                    if *slot % E::slots_per_epoch() == 0 {
                        let state_key =
                            get_key_for_col(DBColumn::BeaconState.into(), untyped_hash.as_bytes());
                        key_value_batch.push(KeyValueStoreOp::DeleteKey(state_key));
                    }
                }
            }
        }
        self.hot_db.do_atomically(key_value_batch)?;

        for op in &batch {
            match op {
                StoreOp::PutBlock(block_hash, block) => {
                    let untyped_hash: Hash256 = (*block_hash).into();
                    guard.put(untyped_hash, block.clone());
                }

                StoreOp::PutState(_, _) => (),

                StoreOp::PutStateSummary(_, _) => (),

                StoreOp::DeleteBlock(block_hash) => {
                    let untyped_hash: Hash256 = (*block_hash).into();
                    guard.pop(&untyped_hash);
                }

                StoreOp::DeleteState(_, _) => (),
            }
        }
        Ok(())
    }
    /// Store a post-finalization state efficiently in the hot database.
    ///
    /// On an epoch boundary, store a full state. On an intermediate slot, store
    /// just a backpointer to the nearest epoch boundary.
    pub fn store_hot_state(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        // On the epoch boundary, store the full state.
        if state.slot % E::slots_per_epoch() == 0 {
            trace!(
                self.log,
                "Storing full state on epoch boundary";
                "slot" => state.slot.as_u64(),
                "state_root" => format!("{:?}", state_root)
            );
            store_full_state(state_root, &state, ops)?;
        }

        // Store a summary of the state.
        // We store one even for the epoch boundary states, as we may need their slots
        // when doing a look up by state root.
        let hot_state_summary = HotStateSummary::new(state_root, state)?;
        let op = hot_state_summary.as_kv_store_op(*state_root);
        ops.push(op);

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
            let boundary_state = get_full_state(&self.hot_db, &epoch_boundary_state_root)?
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
        ops: &mut Vec<KeyValueStoreOp>,
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
        let op = partial_state.as_kv_store_op(*state_root);
        ops.push(op);

        // 2. Store updated vector entries.
        let db = &self.cold_db;
        store_updated_vector(BlockRoots, db, state, &self.spec, ops)?;
        store_updated_vector(StateRoots, db, state, &self.spec, ops)?;
        store_updated_vector(HistoricalRoots, db, state, &self.spec, ops)?;
        store_updated_vector(RandaoMixes, db, state, &self.spec, ops)?;

        // 3. Store restore point.
        let restore_point_index = state.slot.as_u64() / self.config.slots_per_restore_point;
        self.store_restore_point_hash(restore_point_index, *state_root, ops);

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
        let mut partial_state: PartialBeaconState<E> = self
            .cold_db
            .get(state_root)?
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
        let mut blocks: Vec<SignedBeaconBlock<E>> =
            ParentRootBlockIterator::new(self, end_block_hash)
                .map(|result| result.map(|(_, block)| block))
                // Include the block at the end slot (if any), it needs to be
                // replayed in order to construct the canonical state at `end_slot`.
                .filter(|result| {
                    result
                        .as_ref()
                        .map_or(true, |block| block.message.slot <= end_slot)
                })
                // Include the block at the start slot (if any). Whilst it doesn't need to be applied
                // to the state, it contains a potentially useful state root.
                .take_while(|result| {
                    result
                        .as_ref()
                        .map_or(true, |block| block.message.slot >= start_slot)
                })
                .collect::<Result<_, _>>()?;
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

    /// Load the state root of a restore point.
    fn load_restore_point_hash(&self, restore_point_index: u64) -> Result<Hash256, Error> {
        let key = Self::restore_point_key(restore_point_index);
        self.cold_db
            .get(&key)?
            .map(|r: RestorePointHash| r.state_root)
            .ok_or_else(|| HotColdDBError::MissingRestorePointHash(restore_point_index).into())
    }

    /// Store the state root of a restore point.
    fn store_restore_point_hash(
        &self,
        restore_point_index: u64,
        state_root: Hash256,
        ops: &mut Vec<KeyValueStoreOp>,
    ) {
        let value = &RestorePointHash { state_root };
        let op = value.as_kv_store_op(Self::restore_point_key(restore_point_index));
        ops.push(op);
    }

    /// Convert a `restore_point_index` into a database key.
    fn restore_point_key(restore_point_index: u64) -> Hash256 {
        Hash256::from_low_u64_be(restore_point_index)
    }

    /// Load a frozen state's slot, given its root.
    fn load_cold_state_slot(&self, state_root: &Hash256) -> Result<Option<Slot>, Error> {
        Ok(self
            .cold_db
            .get(state_root)?
            .map(|s: ColdStateSummary| s.slot))
    }

    /// Load a hot state's summary, given its root.
    pub fn load_hot_state_summary(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<HotStateSummary>, Error> {
        self.hot_db.get(state_root)
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

/// Advance the split point of the store, moving new finalized states to the freezer.
pub fn process_finalization<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: Arc<HotColdDB<E, Hot, Cold>>,
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
    let current_split_slot = store.split.read().slot;

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

    let mut hot_db_ops: Vec<StoreOp<E>> = Vec::new();

    // 1. Copy all of the states between the head and the split slot, from the hot DB
    // to the cold DB.
    let state_root_iter = StateRootsIterator::new(store.clone(), frozen_head);
    for maybe_pair in state_root_iter.take_while(|result| match result {
        Ok((_, slot)) => slot >= &current_split_slot,
        Err(_) => true,
    }) {
        let (state_root, slot) = maybe_pair?;

        let mut cold_db_ops: Vec<KeyValueStoreOp> = Vec::new();

        if slot % store.config.slots_per_restore_point == 0 {
            let state: BeaconState<E> = get_full_state(&store.hot_db, &state_root)?
                .ok_or_else(|| HotColdDBError::MissingStateToFreeze(state_root))?;

            store.store_cold_state(&state_root, &state, &mut cold_db_ops)?;
        }

        // Store a pointer from this state root to its slot, so we can later reconstruct states
        // from their state root alone.
        let cold_state_summary = ColdStateSummary { slot };
        let op = cold_state_summary.as_kv_store_op(state_root);
        cold_db_ops.push(op);

        // There are data dependencies between calls to `store_cold_state()` that prevent us from
        // doing one big call to `store.cold_db.do_atomically()` at end of the loop.
        store.cold_db.do_atomically(cold_db_ops)?;

        // Delete the old summary, and the full state if we lie on an epoch boundary.
        hot_db_ops.push(StoreOp::DeleteState(state_root.into(), slot));
    }

    // Warning: Critical section.  We have to take care not to put any of the two databases in an
    //          inconsistent state if the OS process dies at any point during the freezeing
    //          procedure.
    //
    // Since it is pretty much impossible to be atomic across more than one database, we trade
    // losing track of states to delete, for consistency.  In other words: We should be safe to die
    // at any point below but it may happen that some states won't be deleted from the hot database
    // and will remain there forever.  Since dying in these particular few lines should be an
    // exceedingly rare event, this should be an acceptable tradeoff.

    // Flush to disk all the states that have just been migrated to the cold store.
    store.cold_db.sync()?;

    {
        let mut split_guard = store.split.write();
        let latest_split_slot = split_guard.slot;

        // Detect a sitation where the split point is (erroneously) changed from more than one
        // place in code.
        if latest_split_slot != current_split_slot {
            error!(
                store.log,
                "Race condition detected: Split point changed while moving states to the freezer";
                "previous split slot" => current_split_slot,
                "current split slot" => latest_split_slot,
            );

            // Assume the freezing procedure will be retried in case this happens.
            return Err(Error::SplitPointModified(
                current_split_slot,
                latest_split_slot,
            ));
        }

        // Before updating the in-memory split value, we flush it to disk first, so that should the
        // OS process die at this point, we pick up from the right place after a restart.
        let split = Split {
            slot: frozen_head.slot,
            state_root: frozen_head_root,
        };
        store
            .hot_db
            .put_sync(&Hash256::from_slice(SPLIT_DB_KEY.as_bytes()), &split)?;

        // Split point is now persisted in the hot database on disk.  The in-memory split point
        // hasn't been modified elsewhere since we keep a write lock on it.  It's safe to update
        // the in-memory split point now.
        *split_guard = split;
    }

    // Delete the states from the hot database if we got this far.
    store.do_atomically(hot_db_ops)?;

    debug!(
        store.log,
        "Freezer migration complete";
        "slot" => frozen_head.slot
    );

    Ok(())
}

/// Struct for storing the split slot and state root in the database.
#[derive(Debug, Clone, Copy, Default, Encode, Decode)]
pub struct Split {
    slot: Slot,
    state_root: Hash256,
}

impl StoreItem for Split {
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

impl StoreItem for HotStateSummary {
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

impl StoreItem for ColdStateSummary {
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

impl StoreItem for RestorePointHash {
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
