use crate::chunked_vector::{
    store_updated_vector, BlockRoots, HistoricalRoots, RandaoMixes, StateRoots,
};
use crate::config::{OnDiskStoreConfig, StoreConfig};
use crate::forwards_iter::{HybridForwardsBlockRootsIterator, HybridForwardsStateRootsIterator};
use crate::impls::beacon_state::{get_full_state, store_full_state};
use crate::iter::{ParentRootBlockIterator, StateRootsIterator};
use crate::leveldb_store::BytesKey;
use crate::leveldb_store::LevelDB;
use crate::memory_store::MemoryStore;
use crate::metadata::{
    AnchorInfo, CompactionTimestamp, PruningCheckpoint, SchemaVersion, ANCHOR_INFO_KEY,
    COMPACTION_TIMESTAMP_KEY, CONFIG_KEY, CURRENT_SCHEMA_VERSION, PRUNING_CHECKPOINT_KEY,
    SCHEMA_VERSION_KEY, SPLIT_KEY,
};
use crate::metrics;
use crate::{
    get_key_for_col, DBColumn, Error, ItemStore, KeyValueStoreOp, PartialBeaconState, StoreItem,
    StoreOp,
};
use leveldb::iterator::LevelDBIterator;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use serde_derive::{Deserialize, Serialize};
use slog::{debug, error, info, trace, Logger};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
    SlotProcessingError,
};
use std::cmp::min;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use types::*;

/// Defines how blocks should be replayed on states.
#[derive(PartialEq)]
pub enum BlockReplay {
    /// Perform all transitions faithfully to the specification.
    Accurate,
    /// Don't compute state roots, eventually computing an invalid beacon state that can only be
    /// used for obtaining shuffling.
    InconsistentStateRoots,
}

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
    pub(crate) split: RwLock<Split>,
    /// The starting slots for the range of blocks & states stored in the database.
    anchor_info: RwLock<Option<AnchorInfo>>,
    pub(crate) config: StoreConfig,
    /// Cold database containing compact historical data.
    pub cold_db: Cold,
    /// Hot database containing duplicated but quick-to-access recent data.
    ///
    /// The hot database also contains all blocks.
    pub hot_db: Hot,
    /// LRU cache of deserialized blocks. Updated whenever a block is loaded.
    block_cache: Mutex<LruCache<Hash256, SignedBeaconBlock<E>>>,
    /// Chain spec.
    pub(crate) spec: ChainSpec,
    /// Logger.
    pub(crate) log: Logger,
    /// Mere vessel for E.
    _phantom: PhantomData<E>,
}

#[derive(Debug, PartialEq)]
pub enum HotColdDBError {
    UnsupportedSchemaVersion {
        target_version: SchemaVersion,
        current_version: SchemaVersion,
    },
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
    MissingAnchorInfo,
    HotStateSummaryError(BeaconStateError),
    RestorePointDecodeError(ssz::DecodeError),
    BlockReplayBeaconError(BeaconStateError),
    BlockReplaySlotError(SlotProcessingError),
    BlockReplayBlockError(BlockProcessingError),
    MissingLowerLimitState(Slot),
    InvalidSlotsPerRestorePoint {
        slots_per_restore_point: u64,
        slots_per_historical_root: u64,
        slots_per_epoch: u64,
    },
    RestorePointBlockHashError(BeaconStateError),
    IterationError {
        unexpected_key: BytesKey,
    },
    AttestationStateIsFinalized {
        split_slot: Slot,
        request_slot: Option<Slot>,
        state_root: Hash256,
    },
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
            anchor_info: RwLock::new(None),
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
    ///
    /// The `migrate_schema` function is passed in so that the parent `BeaconChain` can provide
    /// context and access `BeaconChain`-level code without creating a circular dependency.
    pub fn open(
        hot_path: &Path,
        cold_path: &Path,
        migrate_schema: impl FnOnce(Arc<Self>, SchemaVersion, SchemaVersion) -> Result<(), Error>,
        config: StoreConfig,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<Arc<Self>, Error> {
        Self::verify_slots_per_restore_point(config.slots_per_restore_point)?;

        let db = Arc::new(HotColdDB {
            split: RwLock::new(Split::default()),
            anchor_info: RwLock::new(None),
            cold_db: LevelDB::open(cold_path)?,
            hot_db: LevelDB::open(hot_path)?,
            block_cache: Mutex::new(LruCache::new(config.block_cache_size)),
            config,
            spec,
            log,
            _phantom: PhantomData,
        });

        // Ensure that the schema version of the on-disk database matches the software.
        // If the version is mismatched, an automatic migration will be attempted.
        if let Some(schema_version) = db.load_schema_version()? {
            debug!(
                db.log,
                "Attempting schema migration";
                "from_version" => schema_version.as_u64(),
                "to_version" => CURRENT_SCHEMA_VERSION.as_u64(),
            );
            migrate_schema(db.clone(), schema_version, CURRENT_SCHEMA_VERSION)?;
        } else {
            db.store_schema_version(CURRENT_SCHEMA_VERSION)?;
        }

        // Ensure that any on-disk config is compatible with the supplied config.
        if let Some(disk_config) = db.load_config()? {
            db.config.check_compatibility(&disk_config)?;
        }
        db.store_config()?;

        // Load the previous split slot from the database (if any). This ensures we can
        // stop and restart correctly.
        if let Some(split) = db.load_split()? {
            *db.split.write() = split;
            *db.anchor_info.write() = db.load_anchor_info()?;

            info!(
                db.log,
                "Hot-Cold DB initialized";
                "version" => CURRENT_SCHEMA_VERSION.as_u64(),
                "split_slot" => split.slot,
                "split_state" => format!("{:?}", split.state_root)
            );
        }

        // Run a garbage collection pass.
        db.remove_garbage()?;

        // If configured, run a foreground compaction pass.
        if db.config.compact_on_init {
            info!(db.log, "Running foreground compaction");
            db.compact()?;
            info!(db.log, "Foreground compaction complete");
        }

        Ok(db)
    }

    /// Return an iterator over the state roots of all temporary states.
    pub fn iter_temporary_state_roots(&self) -> impl Iterator<Item = Result<Hash256, Error>> + '_ {
        let column = DBColumn::BeaconStateTemporary;
        let start_key =
            BytesKey::from_vec(get_key_for_col(column.into(), Hash256::zero().as_bytes()));

        let keys_iter = self.hot_db.keys_iter();
        keys_iter.seek(&start_key);

        keys_iter
            .take_while(move |key| key.matches_column(column))
            .map(move |bytes_key| {
                bytes_key.remove_column(column).ok_or_else(|| {
                    HotColdDBError::IterationError {
                        unexpected_key: bytes_key,
                    }
                    .into()
                })
            })
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
        let op = self.block_as_kv_store_op(block_root, &block);
        self.hot_db.do_atomically(vec![op])?;

        // Update cache.
        self.block_cache.lock().put(*block_root, block);

        Ok(())
    }

    /// Prepare a signed beacon block for storage in the database.
    pub fn block_as_kv_store_op(
        &self,
        key: &Hash256,
        block: &SignedBeaconBlock<E>,
    ) -> KeyValueStoreOp {
        // FIXME(altair): re-add block write/overhead metrics, or remove them
        let db_key = get_key_for_col(DBColumn::BeaconBlock.into(), key.as_bytes());
        KeyValueStoreOp::PutKeyValue(db_key, block.as_ssz_bytes())
    }

    /// Fetch a block from the store.
    pub fn get_block(&self, block_root: &Hash256) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_BLOCK_GET_COUNT);

        // Check the cache.
        if let Some(block) = self.block_cache.lock().get(block_root) {
            metrics::inc_counter(&metrics::BEACON_BLOCK_CACHE_HIT_COUNT);
            return Ok(Some(block.clone()));
        }

        let block = self.get_block_with(block_root, |bytes| {
            SignedBeaconBlock::from_ssz_bytes(bytes, &self.spec)
        })?;

        // Add to cache.
        if let Some(ref block) = block {
            self.block_cache.lock().put(*block_root, block.clone());
        }

        Ok(block)
    }

    /// Fetch a block from the store, ignoring which fork variant it *should* be for.
    pub fn get_block_any_variant(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        self.get_block_with(block_root, SignedBeaconBlock::any_from_ssz_bytes)
    }

    /// Fetch a block from the store using a custom decode function.
    ///
    /// This is useful for e.g. ignoring the slot-indicated fork to forcefully load a block as if it
    /// were for a different fork.
    pub fn get_block_with(
        &self,
        block_root: &Hash256,
        decoder: impl FnOnce(&[u8]) -> Result<SignedBeaconBlock<E>, ssz::DecodeError>,
    ) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        self.hot_db
            .get_bytes(DBColumn::BeaconBlock.into(), block_root.as_bytes())?
            .map(|block_bytes| decoder(&block_bytes))
            .transpose()
            .map_err(|e| e.into())
    }

    /// Determine whether a block exists in the database.
    pub fn block_exists(&self, block_root: &Hash256) -> Result<bool, Error> {
        self.hot_db
            .key_exists(DBColumn::BeaconBlock.into(), block_root.as_bytes())
    }

    /// Delete a block from the store and the block cache.
    pub fn delete_block(&self, block_root: &Hash256) -> Result<(), Error> {
        self.block_cache.lock().pop(block_root);
        self.hot_db
            .key_delete(DBColumn::BeaconBlock.into(), block_root.as_bytes())
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
        let mut ops: Vec<KeyValueStoreOp> = Vec::new();
        if state.slot() < self.get_split_slot() {
            self.store_cold_state(state_root, state, &mut ops)?;
            self.cold_db.do_atomically(ops)
        } else {
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
                self.load_hot_state(state_root, BlockReplay::Accurate)
            }
        } else {
            match self.load_hot_state(state_root, BlockReplay::Accurate)? {
                Some(state) => Ok(Some(state)),
                None => self.load_cold_state(state_root),
            }
        }
    }

    /// Fetch a state from the store, but don't compute all of the values when replaying blocks
    /// upon that state (e.g., state roots). Additionally, only states from the hot store are
    /// returned.
    ///
    /// See `Self::get_state` for information about `slot`.
    ///
    /// ## Warning
    ///
    /// The returned state **is not a valid beacon state**, it can only be used for obtaining
    /// shuffling to process attestations. At least the following components of the state will be
    /// broken/invalid:
    ///
    /// - `state.state_roots`
    /// - `state.block_roots`
    pub fn get_inconsistent_state_for_attestation_verification_only(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_STATE_GET_COUNT);

        let split_slot = self.get_split_slot();

        if slot.map_or(false, |slot| slot < split_slot) {
            Err(HotColdDBError::AttestationStateIsFinalized {
                split_slot,
                request_slot: slot,
                state_root: *state_root,
            }
            .into())
        } else {
            self.load_hot_state(state_root, BlockReplay::InconsistentStateRoots)
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

    pub fn forwards_state_roots_iterator(
        store: Arc<Self>,
        start_slot: Slot,
        end_state_root: Hash256,
        end_state: BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>>, Error> {
        HybridForwardsStateRootsIterator::new(store, start_slot, end_state, end_state_root, spec)
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
            //
            // `BlockReplay` should be irrelevant here since we never replay blocks for an epoch
            // boundary state in the hot DB.
            let state = self
                .load_hot_state(&epoch_boundary_state_root, BlockReplay::Accurate)?
                .ok_or(HotColdDBError::MissingEpochBoundaryState(
                    epoch_boundary_state_root,
                ))?;
            Ok(Some(state))
        } else {
            // Try the cold DB
            match self.load_cold_state_slot(state_root)? {
                Some(state_slot) => {
                    let epoch_boundary_slot =
                        state_slot / E::slots_per_epoch() * E::slots_per_epoch();
                    self.load_cold_state_by_slot(epoch_boundary_slot)
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

    /// Convert a batch of `StoreOp` to a batch of `KeyValueStoreOp`.
    pub fn convert_to_kv_batch(&self, batch: &[StoreOp<E>]) -> Result<Vec<KeyValueStoreOp>, Error> {
        let mut key_value_batch = Vec::with_capacity(batch.len());
        for op in batch {
            match op {
                StoreOp::PutBlock(block_root, block) => {
                    key_value_batch.push(self.block_as_kv_store_op(block_root, block));
                }

                StoreOp::PutState(state_root, state) => {
                    self.store_hot_state(state_root, state, &mut key_value_batch)?;
                }

                StoreOp::PutStateSummary(state_root, summary) => {
                    key_value_batch.push(summary.as_kv_store_op(*state_root));
                }

                StoreOp::PutStateTemporaryFlag(state_root) => {
                    key_value_batch.push(TemporaryFlag.as_kv_store_op(*state_root));
                }

                StoreOp::DeleteStateTemporaryFlag(state_root) => {
                    let db_key =
                        get_key_for_col(TemporaryFlag::db_column().into(), state_root.as_bytes());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(db_key));
                }

                StoreOp::DeleteBlock(block_root) => {
                    let key = get_key_for_col(DBColumn::BeaconBlock.into(), block_root.as_bytes());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(key));
                }

                StoreOp::DeleteState(state_root, slot) => {
                    let state_summary_key =
                        get_key_for_col(DBColumn::BeaconStateSummary.into(), state_root.as_bytes());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(state_summary_key));

                    if slot.map_or(true, |slot| slot % E::slots_per_epoch() == 0) {
                        let state_key =
                            get_key_for_col(DBColumn::BeaconState.into(), state_root.as_bytes());
                        key_value_batch.push(KeyValueStoreOp::DeleteKey(state_key));
                    }
                }
            }
        }
        Ok(key_value_batch)
    }

    pub fn do_atomically(&self, batch: Vec<StoreOp<E>>) -> Result<(), Error> {
        let mut guard = self.block_cache.lock();

        self.hot_db
            .do_atomically(self.convert_to_kv_batch(&batch)?)?;

        for op in &batch {
            match op {
                StoreOp::PutBlock(block_root, block) => {
                    guard.put(*block_root, (**block).clone());
                }

                StoreOp::PutState(_, _) => (),

                StoreOp::PutStateSummary(_, _) => (),

                StoreOp::PutStateTemporaryFlag(_) => (),

                StoreOp::DeleteStateTemporaryFlag(_) => (),

                StoreOp::DeleteBlock(block_root) => {
                    guard.pop(block_root);
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
        if state.slot() % E::slots_per_epoch() == 0 {
            trace!(
                self.log,
                "Storing full state on epoch boundary";
                "slot" => state.slot().as_u64(),
                "state_root" => format!("{:?}", state_root)
            );
            store_full_state(state_root, state, ops)?;
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
    pub fn load_hot_state(
        &self,
        state_root: &Hash256,
        block_replay: BlockReplay,
    ) -> Result<Option<BeaconState<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_STATE_HOT_GET_COUNT);

        // If the state is marked as temporary, do not return it. It will become visible
        // only once its transaction commits and deletes its temporary flag.
        if self.load_state_temporary_flag(state_root)?.is_some() {
            return Ok(None);
        }

        if let Some(HotStateSummary {
            slot,
            latest_block_root,
            epoch_boundary_state_root,
        }) = self.load_hot_state_summary(state_root)?
        {
            let boundary_state =
                get_full_state(&self.hot_db, &epoch_boundary_state_root, &self.spec)?.ok_or(
                    HotColdDBError::MissingEpochBoundaryState(epoch_boundary_state_root),
                )?;

            // Optimization to avoid even *thinking* about replaying blocks if we're already
            // on an epoch boundary.
            let state = if slot % E::slots_per_epoch() == 0 {
                boundary_state
            } else {
                let blocks =
                    self.load_blocks_to_replay(boundary_state.slot(), slot, latest_block_root)?;
                self.replay_blocks(boundary_state, blocks, slot, block_replay)?
            };

            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    /// Store a pre-finalization state in the freezer database.
    ///
    /// If the state doesn't lie on a restore point boundary then just its summary will be stored.
    pub fn store_cold_state(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        ops.push(ColdStateSummary { slot: state.slot() }.as_kv_store_op(*state_root));

        if state.slot() % self.config.slots_per_restore_point != 0 {
            return Ok(());
        }

        trace!(
            self.log,
            "Creating restore point";
            "slot" => state.slot(),
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
        let restore_point_index = state.slot().as_u64() / self.config.slots_per_restore_point;
        self.store_restore_point_hash(restore_point_index, *state_root, ops);

        Ok(())
    }

    /// Try to load a pre-finalization state from the freezer database.
    ///
    /// Return `None` if no state with `state_root` lies in the freezer.
    pub fn load_cold_state(&self, state_root: &Hash256) -> Result<Option<BeaconState<E>>, Error> {
        match self.load_cold_state_slot(state_root)? {
            Some(slot) => self.load_cold_state_by_slot(slot),
            None => Ok(None),
        }
    }

    /// Load a pre-finalization state from the freezer database.
    ///
    /// Will reconstruct the state if it lies between restore points.
    pub fn load_cold_state_by_slot(&self, slot: Slot) -> Result<Option<BeaconState<E>>, Error> {
        // Guard against fetching states that do not exist due to gaps in the historic state
        // database, which can occur due to checkpoint sync or re-indexing.
        // See the comments in `get_historic_state_limits` for more information.
        let (lower_limit, upper_limit) = self.get_historic_state_limits();

        if slot <= lower_limit || slot >= upper_limit {
            if slot % self.config.slots_per_restore_point == 0 {
                let restore_point_idx = slot.as_u64() / self.config.slots_per_restore_point;
                self.load_restore_point_by_index(restore_point_idx)
            } else {
                self.load_cold_intermediate_state(slot)
            }
            .map(Some)
        } else {
            Ok(None)
        }
    }

    /// Load a restore point state by its `state_root`.
    fn load_restore_point(&self, state_root: &Hash256) -> Result<BeaconState<E>, Error> {
        let partial_state_bytes = self
            .cold_db
            .get_bytes(DBColumn::BeaconState.into(), state_root.as_bytes())?
            .ok_or_else(|| HotColdDBError::MissingRestorePoint(*state_root))?;
        let mut partial_state: PartialBeaconState<E> =
            PartialBeaconState::from_ssz_bytes(&partial_state_bytes, &self.spec)?;

        // Fill in the fields of the partial state.
        partial_state.load_block_roots(&self.cold_db, &self.spec)?;
        partial_state.load_state_roots(&self.cold_db, &self.spec)?;
        partial_state.load_historical_roots(&self.cold_db, &self.spec)?;
        partial_state.load_randao_mixes(&self.cold_db, &self.spec)?;

        partial_state.try_into()
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
        let split = self.split.read_recursive();

        let low_restore_point = self.load_restore_point_by_index(low_restore_point_idx)?;
        let high_restore_point = self.get_restore_point(high_restore_point_idx, &split)?;

        // 2. Load the blocks from the high restore point back to the low restore point.
        let blocks = self.load_blocks_to_replay(
            low_restore_point.slot(),
            slot,
            self.get_high_restore_point_block_root(&high_restore_point, slot)?,
        )?;

        // 3. Replay the blocks on top of the low restore point.
        self.replay_blocks(low_restore_point, blocks, slot, BlockReplay::Accurate)
    }

    /// Get the restore point with the given index, or if it is out of bounds, the split state.
    pub(crate) fn get_restore_point(
        &self,
        restore_point_idx: u64,
        split: &Split,
    ) -> Result<BeaconState<E>, Error> {
        if restore_point_idx * self.config.slots_per_restore_point >= split.slot.as_u64() {
            self.get_state(&split.state_root, Some(split.slot))?
                .ok_or(HotColdDBError::MissingSplitState(
                    split.state_root,
                    split.slot,
                ))
                .map_err(Into::into)
        } else {
            self.load_restore_point_by_index(restore_point_idx)
        }
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
    pub fn load_blocks_to_replay(
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
                        .map_or(true, |block| block.slot() <= end_slot)
                })
                // Include the block at the start slot (if any). Whilst it doesn't need to be
                // applied to the state, it contains a potentially useful state root.
                //
                // Return `true` on an `Err` so that the `collect` fails, unless the error is a
                // `BlockNotFound` error and some blocks are intentionally missing from the DB.
                // This complexity is unfortunately necessary to avoid loading the parent of the
                // oldest known block -- we can't know that we have all the required blocks until we
                // load a block with slot less than the start slot, which is impossible if there are
                // no blocks with slot less than the start slot.
                .take_while(|result| match result {
                    Ok(block) => block.slot() >= start_slot,
                    Err(Error::BlockNotFound(_)) => {
                        self.get_oldest_block_slot() == self.spec.genesis_slot
                    }
                    Err(_) => true,
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
        mut blocks: Vec<SignedBeaconBlock<E>>,
        target_slot: Slot,
        block_replay: BlockReplay,
    ) -> Result<BeaconState<E>, Error> {
        if block_replay == BlockReplay::InconsistentStateRoots {
            for i in 0..blocks.len() {
                let prev_block_root = if i > 0 {
                    blocks[i - 1].canonical_root()
                } else {
                    // Not read.
                    Hash256::zero()
                };

                let (state_root, parent_root) = match &mut blocks[i] {
                    SignedBeaconBlock::Base(block) => (
                        &mut block.message.state_root,
                        &mut block.message.parent_root,
                    ),
                    SignedBeaconBlock::Altair(block) => (
                        &mut block.message.state_root,
                        &mut block.message.parent_root,
                    ),
                };

                *state_root = Hash256::zero();
                if i > 0 {
                    *parent_root = prev_block_root;
                }
            }
        }

        let state_root_from_prev_block = |i: usize, state: &BeaconState<E>| {
            if i > 0 {
                let prev_block = blocks[i - 1].message();
                if prev_block.slot() == state.slot() {
                    Some(prev_block.state_root())
                } else {
                    None
                }
            } else {
                None
            }
        };

        for (i, block) in blocks.iter().enumerate() {
            if block.slot() <= state.slot() {
                continue;
            }

            while state.slot() < block.slot() {
                let state_root = match block_replay {
                    BlockReplay::Accurate => state_root_from_prev_block(i, &state),
                    BlockReplay::InconsistentStateRoots => Some(Hash256::zero()),
                };
                per_slot_processing(&mut state, state_root, &self.spec)
                    .map_err(HotColdDBError::BlockReplaySlotError)?;
            }

            per_block_processing(
                &mut state,
                block,
                None,
                BlockSignatureStrategy::NoVerification,
                &self.spec,
            )
            .map_err(HotColdDBError::BlockReplayBlockError)?;
        }

        while state.slot() < target_slot {
            let state_root = match block_replay {
                BlockReplay::Accurate => state_root_from_prev_block(blocks.len(), &state),
                BlockReplay::InconsistentStateRoots => Some(Hash256::zero()),
            };
            per_slot_processing(&mut state, state_root, &self.spec)
                .map_err(HotColdDBError::BlockReplaySlotError)?;
        }

        Ok(state)
    }

    /// Fetch a copy of the current split slot from memory.
    pub fn get_split_slot(&self) -> Slot {
        self.split.read_recursive().slot
    }

    /// Fetch a copy of the current split slot from memory.
    pub fn get_split_info(&self) -> Split {
        *self.split.read_recursive()
    }

    pub fn set_split(&self, slot: Slot, state_root: Hash256) {
        *self.split.write() = Split { slot, state_root };
    }

    /// Fetch the slot of the most recently stored restore point.
    pub fn get_latest_restore_point_slot(&self) -> Slot {
        (self.get_split_slot() - 1) / self.config.slots_per_restore_point
            * self.config.slots_per_restore_point
    }

    /// Load the database schema version from disk.
    fn load_schema_version(&self) -> Result<Option<SchemaVersion>, Error> {
        self.hot_db.get(&SCHEMA_VERSION_KEY)
    }

    /// Store the database schema version.
    pub fn store_schema_version(&self, schema_version: SchemaVersion) -> Result<(), Error> {
        self.hot_db.put(&SCHEMA_VERSION_KEY, &schema_version)
    }

    /// Initialise the anchor info for checkpoint sync starting from `block`.
    pub fn init_anchor_info(&self, block: BeaconBlockRef<'_, E>) -> Result<KeyValueStoreOp, Error> {
        let anchor_slot = block.slot();
        let slots_per_restore_point = self.config.slots_per_restore_point;

        // Set the `state_upper_limit` to the slot of the *next* restore point.
        // See `get_state_upper_limit` for rationale.
        let next_restore_point_slot = if anchor_slot % slots_per_restore_point == 0 {
            anchor_slot
        } else {
            (anchor_slot / slots_per_restore_point + 1) * slots_per_restore_point
        };
        let anchor_info = AnchorInfo {
            anchor_slot,
            oldest_block_slot: anchor_slot,
            oldest_block_parent: block.parent_root(),
            state_upper_limit: next_restore_point_slot,
            state_lower_limit: self.spec.genesis_slot,
        };
        self.compare_and_set_anchor_info(None, Some(anchor_info))
    }

    /// Get a clone of the store's anchor info.
    ///
    /// To do mutations, use `compare_and_set_anchor_info`.
    pub fn get_anchor_info(&self) -> Option<AnchorInfo> {
        self.anchor_info.read_recursive().clone()
    }

    /// Atomically update the anchor info from `prev_value` to `new_value`.
    ///
    /// Return a `KeyValueStoreOp` which should be written to disk, possibly atomically with other
    /// values.
    ///
    /// Return an `AnchorInfoConcurrentMutation` error if the `prev_value` provided
    /// is not correct.
    pub fn compare_and_set_anchor_info(
        &self,
        prev_value: Option<AnchorInfo>,
        new_value: Option<AnchorInfo>,
    ) -> Result<KeyValueStoreOp, Error> {
        let mut anchor_info = self.anchor_info.write();
        if *anchor_info == prev_value {
            let kv_op = self.store_anchor_info_in_batch(&new_value);
            *anchor_info = new_value;
            Ok(kv_op)
        } else {
            Err(Error::AnchorInfoConcurrentMutation)
        }
    }

    /// As for `compare_and_set_anchor_info`, but also writes the anchor to disk immediately.
    pub fn compare_and_set_anchor_info_with_write(
        &self,
        prev_value: Option<AnchorInfo>,
        new_value: Option<AnchorInfo>,
    ) -> Result<(), Error> {
        let kv_store_op = self.compare_and_set_anchor_info(prev_value, new_value)?;
        self.hot_db.do_atomically(vec![kv_store_op])
    }

    /// Load the anchor info from disk, but do not set `self.anchor_info`.
    fn load_anchor_info(&self) -> Result<Option<AnchorInfo>, Error> {
        self.hot_db.get(&ANCHOR_INFO_KEY)
    }

    /// Store the given `anchor_info` to disk.
    ///
    /// The argument is intended to be `self.anchor_info`, but is passed manually to avoid issues
    /// with recursive locking.
    fn store_anchor_info_in_batch(&self, anchor_info: &Option<AnchorInfo>) -> KeyValueStoreOp {
        if let Some(ref anchor_info) = anchor_info {
            anchor_info.as_kv_store_op(ANCHOR_INFO_KEY)
        } else {
            KeyValueStoreOp::DeleteKey(get_key_for_col(
                DBColumn::BeaconMeta.into(),
                ANCHOR_INFO_KEY.as_bytes(),
            ))
        }
    }

    /// If an anchor exists, return its `anchor_slot` field.
    pub fn get_anchor_slot(&self) -> Option<Slot> {
        self.anchor_info
            .read_recursive()
            .as_ref()
            .map(|a| a.anchor_slot)
    }

    /// Return the slot-window describing the available historic states.
    ///
    /// Returns `(lower_limit, upper_limit)`.
    ///
    /// The lower limit is the maximum slot such that frozen states are available for all
    /// previous slots (<=).
    ///
    /// The upper limit is the minimum slot such that frozen states are available for all
    /// subsequent slots (>=).
    ///
    /// If `lower_limit >= upper_limit` then all states are available. This will be true
    /// if the database is completely filled in, as we'll return `(split_slot, 0)` in this
    /// instance.
    pub fn get_historic_state_limits(&self) -> (Slot, Slot) {
        // If checkpoint sync is used then states in the hot DB will always be available, but may
        // become unavailable as finalisation advances due to the lack of a restore point in the
        // database. For this reason we take the minimum of the split slot and the
        // restore-point-aligned `state_upper_limit`, which should be set _ahead_ of the checkpoint
        // slot during initialisation.
        //
        // E.g. if we start from a checkpoint at slot 2048+1024=3072 with SPRP=2048, then states
        // with slots 3072-4095 will be available only while they are in the hot database, and this
        // function will return the current split slot as the upper limit. Once slot 4096 is reached
        // a new restore point will be created at that slot, making all states from 4096 onwards
        // permanently available.
        let split_slot = self.get_split_slot();
        self.anchor_info
            .read_recursive()
            .as_ref()
            .map_or((split_slot, self.spec.genesis_slot), |a| {
                (a.state_lower_limit, min(a.state_upper_limit, split_slot))
            })
    }

    /// Return the minimum slot such that blocks are available for all subsequent slots.
    pub fn get_oldest_block_slot(&self) -> Slot {
        self.anchor_info
            .read_recursive()
            .as_ref()
            .map_or(self.spec.genesis_slot, |anchor| anchor.oldest_block_slot)
    }

    /// Load previously-stored config from disk.
    fn load_config(&self) -> Result<Option<OnDiskStoreConfig>, Error> {
        self.hot_db.get(&CONFIG_KEY)
    }

    /// Write the config to disk.
    fn store_config(&self) -> Result<(), Error> {
        self.hot_db.put(&CONFIG_KEY, &self.config.as_disk_config())
    }

    /// Load the split point from disk.
    fn load_split(&self) -> Result<Option<Split>, Error> {
        self.hot_db.get(&SPLIT_KEY)
    }

    /// Stage the split for storage to disk.
    pub fn store_split_in_batch(&self) -> KeyValueStoreOp {
        self.split.read_recursive().as_kv_store_op(SPLIT_KEY)
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

    /// Load the temporary flag for a state root, if one exists.
    ///
    /// Returns `Some` if the state is temporary, or `None` if the state is permanent or does not
    /// exist -- you should call `load_hot_state_summary` to find out which.
    pub fn load_state_temporary_flag(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<TemporaryFlag>, Error> {
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

    /// Run a compaction pass to free up space used by deleted states.
    pub fn compact(&self) -> Result<(), Error> {
        self.hot_db.compact()?;
        Ok(())
    }

    /// Return `true` if compaction on finalization/pruning is enabled.
    pub fn compact_on_prune(&self) -> bool {
        self.config.compact_on_prune
    }

    /// Load the checkpoint to begin pruning from (the "old finalized checkpoint").
    pub fn load_pruning_checkpoint(&self) -> Result<Option<Checkpoint>, Error> {
        Ok(self
            .hot_db
            .get(&PRUNING_CHECKPOINT_KEY)?
            .map(|pc: PruningCheckpoint| pc.checkpoint))
    }

    /// Store the checkpoint to begin pruning from (the "old finalized checkpoint").
    pub fn store_pruning_checkpoint(&self, checkpoint: Checkpoint) -> Result<(), Error> {
        self.hot_db
            .do_atomically(vec![self.pruning_checkpoint_store_op(checkpoint)])
    }

    /// Create a staged store for the pruning checkpoint.
    pub fn pruning_checkpoint_store_op(&self, checkpoint: Checkpoint) -> KeyValueStoreOp {
        PruningCheckpoint { checkpoint }.as_kv_store_op(PRUNING_CHECKPOINT_KEY)
    }

    /// Load the timestamp of the last compaction as a `Duration` since the UNIX epoch.
    pub fn load_compaction_timestamp(&self) -> Result<Option<Duration>, Error> {
        Ok(self
            .hot_db
            .get(&COMPACTION_TIMESTAMP_KEY)?
            .map(|c: CompactionTimestamp| Duration::from_secs(c.0)))
    }

    /// Store the timestamp of the last compaction as a `Duration` since the UNIX epoch.
    pub fn store_compaction_timestamp(&self, compaction_timestamp: Duration) -> Result<(), Error> {
        self.hot_db.put(
            &COMPACTION_TIMESTAMP_KEY,
            &CompactionTimestamp(compaction_timestamp.as_secs()),
        )
    }
}

/// Advance the split point of the store, moving new finalized states to the freezer.
pub fn migrate_database<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: Arc<HotColdDB<E, Hot, Cold>>,
    frozen_head_root: Hash256,
    frozen_head: &BeaconState<E>,
) -> Result<(), Error> {
    debug!(
        store.log,
        "Freezer migration started";
        "slot" => frozen_head.slot()
    );

    // 0. Check that the migration is sensible.
    // The new frozen head must increase the current split slot, and lie on an epoch
    // boundary (in order for the hot state summary scheme to work).
    let current_split_slot = store.split.read_recursive().slot;
    let anchor_slot = store
        .anchor_info
        .read_recursive()
        .as_ref()
        .map(|a| a.anchor_slot);

    if frozen_head.slot() < current_split_slot {
        return Err(HotColdDBError::FreezeSlotError {
            current_split_slot,
            proposed_split_slot: frozen_head.slot(),
        }
        .into());
    }

    if frozen_head.slot() % E::slots_per_epoch() != 0 {
        return Err(HotColdDBError::FreezeSlotUnaligned(frozen_head.slot()).into());
    }

    let mut hot_db_ops: Vec<StoreOp<E>> = Vec::new();

    // 1. Copy all of the states between the head and the split slot, from the hot DB
    // to the cold DB.
    let state_root_iter = StateRootsIterator::new(store.clone(), frozen_head);
    for maybe_pair in state_root_iter.take_while(|result| match result {
        Ok((_, slot)) => {
            slot >= &current_split_slot
                && anchor_slot.map_or(true, |anchor_slot| slot >= &anchor_slot)
        }
        Err(_) => true,
    }) {
        let (state_root, slot) = maybe_pair?;

        let mut cold_db_ops: Vec<KeyValueStoreOp> = Vec::new();

        if slot % store.config.slots_per_restore_point == 0 {
            let state: BeaconState<E> = get_full_state(&store.hot_db, &state_root, &store.spec)?
                .ok_or(HotColdDBError::MissingStateToFreeze(state_root))?;

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
        hot_db_ops.push(StoreOp::DeleteState(state_root, Some(slot)));
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
            slot: frozen_head.slot(),
            state_root: frozen_head_root,
        };
        store.hot_db.put_sync(&SPLIT_KEY, &split)?;

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
        "slot" => frozen_head.slot()
    );

    Ok(())
}

/// Struct for storing the split slot and state root in the database.
#[derive(Debug, Clone, Copy, PartialEq, Default, Encode, Decode, Deserialize, Serialize)]
pub struct Split {
    pub(crate) slot: Slot,
    pub(crate) state_root: Hash256,
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
        let epoch_boundary_slot = state.slot() / E::slots_per_epoch() * E::slots_per_epoch();
        let epoch_boundary_state_root = if epoch_boundary_slot == state.slot() {
            *state_root
        } else {
            *state
                .get_state_root(epoch_boundary_slot)
                .map_err(HotColdDBError::HotStateSummaryError)?
        };

        Ok(HotStateSummary {
            slot: state.slot(),
            latest_block_root,
            epoch_boundary_state_root,
        })
    }
}

/// Struct for summarising a state in the freezer database.
#[derive(Debug, Clone, Copy, Default, Encode, Decode)]
pub(crate) struct ColdStateSummary {
    pub slot: Slot,
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

#[derive(Debug, Clone, Copy, Default)]
pub struct TemporaryFlag;

impl StoreItem for TemporaryFlag {
    fn db_column() -> DBColumn {
        DBColumn::BeaconStateTemporary
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        vec![]
    }

    fn from_store_bytes(_: &[u8]) -> Result<Self, Error> {
        Ok(TemporaryFlag)
    }
}
