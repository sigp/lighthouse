use crate::chunked_vector::{
    store_updated_vector, BlockRoots, HistoricalRoots, RandaoMixes, StateRoots,
};
use crate::config::{
    OnDiskStoreConfig, StoreConfig, DEFAULT_SLOTS_PER_RESTORE_POINT,
    PREV_DEFAULT_SLOTS_PER_RESTORE_POINT,
};
use crate::forwards_iter::{HybridForwardsBlockRootsIterator, HybridForwardsStateRootsIterator};
use crate::hot_state_iter::HotStateRootIter;
use crate::impls::{
    beacon_state::{get_full_state, store_full_state},
    frozen_block_slot::FrozenBlockSlot,
};
use crate::iter::{BlockRootsIterator, ParentRootBlockIterator, RootsIterator};
use crate::leveldb_store::{BytesKey, LevelDB};
use crate::memory_store::MemoryStore;
use crate::metadata::{
    AnchorInfo, CompactionTimestamp, PruningCheckpoint, SchemaVersion, ANCHOR_INFO_KEY,
    COMPACTION_TIMESTAMP_KEY, CONFIG_KEY, CURRENT_SCHEMA_VERSION, PRUNING_CHECKPOINT_KEY,
    SCHEMA_VERSION_KEY, SPLIT_KEY,
};
use crate::metrics;
use crate::state_cache::{PutStateOutcome, StateCache};
use crate::{
    get_key_for_col, DBColumn, DatabaseBlock, Error, ItemStore, KeyValueStoreOp,
    PartialBeaconState, StoreItem, StoreOp, ValidatorPubkeyCache,
};
use itertools::process_results;
use leveldb::iterator::LevelDBIterator;
use lru::LruCache;
use milhouse::Diff;
use parking_lot::{Mutex, RwLock};
use safe_arith::SafeArith;
use serde_derive::{Deserialize, Serialize};
use slog::{debug, error, info, trace, warn, Logger};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    block_replayer::PreSlotHook, BlockProcessingError, BlockReplayer, SlotProcessingError,
};
use std::cmp::min;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use types::*;
use types::{beacon_state::BeaconStateDiff, EthSpec};
use zstd::{Decoder, Encoder};

pub const MAX_PARENT_STATES_TO_CACHE: u64 = 1;

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
    /// Cache of beacon states.
    state_cache: Mutex<StateCache<E>>,
    /// Immutable validator cache.
    pub immutable_validators: Arc<RwLock<ValidatorPubkeyCache<E, Hot, Cold>>>,
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
    MissingRestorePointState(Slot),
    MissingRestorePoint(Hash256),
    MissingColdStateSummary(Hash256),
    MissingHotStateSummary(Hash256),
    MissingEpochBoundaryState(Hash256),
    MissingPrevState(Hash256),
    MissingSplitState(Hash256, Slot),
    MissingStateDiff(Hash256),
    MissingExecutionPayload(Hash256),
    MissingFullBlockExecutionPayloadPruned(Hash256, Slot),
    MissingAnchorInfo,
    MissingFrozenBlockSlot(Hash256),
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
        config.verify_compression_level()?;

        let db = HotColdDB {
            split: RwLock::new(Split::default()),
            anchor_info: RwLock::new(None),
            cold_db: MemoryStore::open(),
            hot_db: MemoryStore::open(),
            block_cache: Mutex::new(LruCache::new(config.block_cache_size)),
            state_cache: Mutex::new(StateCache::new(config.state_cache_size)),
            immutable_validators: Arc::new(RwLock::new(Default::default())),
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
        config.verify_compression_level()?;

        let mut db = HotColdDB {
            split: RwLock::new(Split::default()),
            anchor_info: RwLock::new(None),
            cold_db: LevelDB::open(cold_path)?,
            hot_db: LevelDB::open(hot_path)?,
            block_cache: Mutex::new(LruCache::new(config.block_cache_size)),
            state_cache: Mutex::new(StateCache::new(config.state_cache_size)),
            immutable_validators: Arc::new(RwLock::new(Default::default())),
            config,
            spec,
            log,
            _phantom: PhantomData,
        };

        // Allow the slots-per-restore-point value to stay at the previous default if the config
        // uses the new default. Don't error on a failed read because the config itself may need
        // migrating.
        if let Ok(Some(disk_config)) = db.load_config() {
            if !db.config.slots_per_restore_point_set_explicitly
                && disk_config.slots_per_restore_point == PREV_DEFAULT_SLOTS_PER_RESTORE_POINT
                && db.config.slots_per_restore_point == DEFAULT_SLOTS_PER_RESTORE_POINT
            {
                debug!(
                    db.log,
                    "Ignoring slots-per-restore-point config in favour of on-disk value";
                    "config" => db.config.slots_per_restore_point,
                    "on_disk" => disk_config.slots_per_restore_point,
                );

                // Mutate the in-memory config so that it's compatible.
                db.config.slots_per_restore_point = PREV_DEFAULT_SLOTS_PER_RESTORE_POINT;
            }
        }

        // Load the previous split slot from the database (if any). This ensures we can
        // stop and restart correctly. This needs to occur *before* running any migrations
        // because some migrations load states and depend on the split.
        if let Some(split) = db.load_split()? {
            *db.split.write() = split;
            *db.anchor_info.write() = db.load_anchor_info()?;

            info!(
                db.log,
                "Hot-Cold DB initialized";
                "split_slot" => split.slot,
                "split_state" => ?split.state_root
            );
        }

        // Load validator pubkey cache.
        // FIXME(sproul): probably breaks migrations, etc
        let pubkey_cache = ValidatorPubkeyCache::load_from_store(&db)?;
        *db.immutable_validators.write() = pubkey_cache;

        // Ensure that the schema version of the on-disk database matches the software.
        // If the version is mismatched, an automatic migration will be attempted.
        let db = Arc::new(db);
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
    pub fn update_finalized_state(
        &self,
        state_root: Hash256,
        block_root: Hash256,
        state: BeaconState<E>,
    ) -> Result<(), Error> {
        self.state_cache
            .lock()
            .update_finalized_state(state_root, block_root, state)
    }

    pub fn state_cache_len(&self) -> usize {
        self.state_cache.lock().len()
    }

    /// Store a block and update the LRU cache.
    pub fn put_block(
        &self,
        block_root: &Hash256,
        block: SignedBeaconBlock<E>,
    ) -> Result<(), Error> {
        // Store on disk.
        let mut ops = Vec::with_capacity(2);
        let block = self.block_as_kv_store_ops(block_root, block, &mut ops)?;
        self.hot_db.do_atomically(ops)?;
        // Update cache.
        self.block_cache.lock().put(*block_root, block);
        Ok(())
    }

    /// Prepare a signed beacon block for storage in the database.
    ///
    /// Return the original block for re-use after storage. It's passed by value so it can be
    /// cracked open and have its payload extracted.
    pub fn block_as_kv_store_ops(
        &self,
        key: &Hash256,
        block: SignedBeaconBlock<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<SignedBeaconBlock<E>, Error> {
        // Split block into blinded block and execution payload.
        let (blinded_block, payload) = block.into();

        // Store blinded block.
        self.blinded_block_as_kv_store_ops(key, &blinded_block, ops);

        // Store execution payload if present.
        if let Some(ref execution_payload) = payload {
            ops.push(execution_payload.as_kv_store_op(*key)?);
        }

        // Re-construct block. This should always succeed.
        blinded_block
            .try_into_full_block(payload)
            .ok_or(Error::AddPayloadLogicError)
    }

    /// Prepare a signed beacon block for storage in the datbase *without* its payload.
    pub fn blinded_block_as_kv_store_ops(
        &self,
        key: &Hash256,
        blinded_block: &SignedBeaconBlock<E, BlindedPayload<E>>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) {
        let db_key = get_key_for_col(DBColumn::BeaconBlock.into(), key.as_bytes());
        ops.push(KeyValueStoreOp::PutKeyValue(
            db_key,
            blinded_block.as_ssz_bytes(),
        ));
    }

    pub fn try_get_full_block(
        &self,
        block_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<DatabaseBlock<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_BLOCK_GET_COUNT);

        // Check the cache.
        if let Some(block) = self.block_cache.lock().get(block_root) {
            metrics::inc_counter(&metrics::BEACON_BLOCK_CACHE_HIT_COUNT);
            return Ok(Some(DatabaseBlock::Full(block.clone())));
        }

        // Load the blinded block.
        let blinded_block = match self.get_blinded_block(block_root, slot)? {
            Some(block) => block,
            None => return Ok(None),
        };

        // If the block is after the split point then we should have the full execution payload
        // stored in the database. If it isn't but payload pruning is disabled, try to load it
        // on-demand.
        //
        // Hold the split lock so that it can't change while loading the payload.
        let split = self.split.read_recursive();

        let block = if blinded_block.message().execution_payload().is_err()
            || blinded_block.slot() >= split.slot
        {
            // Re-constructing the full block should always succeed here.
            let full_block = self.make_full_block(block_root, blinded_block)?;

            // Add to cache.
            self.block_cache.lock().put(*block_root, full_block.clone());

            DatabaseBlock::Full(full_block)
        } else if !self.config.prune_payloads {
            // If payload pruning is disabled there's a chance we may have the payload of
            // this finalized block. Attempt to load it but don't error in case it's missing.
            if let Some(payload) = self.get_execution_payload(block_root)? {
                DatabaseBlock::Full(
                    blinded_block
                        .try_into_full_block(Some(payload))
                        .ok_or(Error::AddPayloadLogicError)?,
                )
            } else {
                DatabaseBlock::Blinded(blinded_block)
            }
        } else {
            DatabaseBlock::Blinded(blinded_block)
        };
        drop(split);

        Ok(Some(block))
    }

    /// Fetch a full block with execution payload from the store.
    pub fn get_full_block(
        &self,
        block_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        match self.try_get_full_block(block_root, slot)? {
            Some(DatabaseBlock::Full(block)) => Ok(Some(block)),
            Some(DatabaseBlock::Blinded(block)) => Err(
                HotColdDBError::MissingFullBlockExecutionPayloadPruned(*block_root, block.slot())
                    .into(),
            ),
            None => Ok(None),
        }
    }

    /// Convert a blinded block into a full block by loading its execution payload if necessary.
    pub fn make_full_block(
        &self,
        block_root: &Hash256,
        blinded_block: SignedBeaconBlock<E, BlindedPayload<E>>,
    ) -> Result<SignedBeaconBlock<E>, Error> {
        if blinded_block.message().execution_payload().is_ok() {
            let execution_payload = self
                .get_execution_payload(block_root)?
                .ok_or(HotColdDBError::MissingExecutionPayload(*block_root))?;
            blinded_block.try_into_full_block(Some(execution_payload))
        } else {
            blinded_block.try_into_full_block(None)
        }
        .ok_or(Error::AddPayloadLogicError)
    }

    pub fn get_blinded_block(
        &self,
        block_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<SignedBlindedBeaconBlock<E>>, Error> {
        if let Some(slot) = slot {
            if slot < self.get_split_slot() || slot == 0 {
                // To the freezer DB.
                self.get_cold_blinded_block_by_slot(slot)
            } else {
                self.get_hot_blinded_block(block_root)
            }
        } else {
            match self.get_hot_blinded_block(block_root)? {
                Some(block) => Ok(Some(block)),
                None => self.get_cold_blinded_block_by_root(block_root),
            }
        }
    }

    pub fn get_hot_blinded_block(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<SignedBlindedBeaconBlock<E>>, Error> {
        self.get_block_with(block_root, |bytes| {
            SignedBeaconBlock::from_ssz_bytes(bytes, &self.spec)
        })
    }

    pub fn get_cold_blinded_block_by_root(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<SignedBlindedBeaconBlock<E>>, Error> {
        // Load slot.
        if let Some(FrozenBlockSlot(block_slot)) = self.cold_db.get(block_root)? {
            self.get_cold_blinded_block_by_slot(block_slot)
        } else {
            Ok(None)
        }
    }

    pub fn get_cold_blinded_block_by_slot(
        &self,
        slot: Slot,
    ) -> Result<Option<SignedBlindedBeaconBlock<E>>, Error> {
        let bytes = if let Some(bytes) = self.cold_db.get_bytes(
            DBColumn::BeaconBlockFrozen.into(),
            &slot.as_u64().to_be_bytes(),
        )? {
            bytes
        } else {
            return Ok(None);
        };

        let mut ssz_bytes = Vec::with_capacity(self.config.estimate_decompressed_size(bytes.len()));
        let mut decoder = Decoder::new(&*bytes).map_err(Error::Compression)?;
        decoder
            .read_to_end(&mut ssz_bytes)
            .map_err(Error::Compression)?;
        Ok(Some(SignedBeaconBlock::from_ssz_bytes(
            &ssz_bytes, &self.spec,
        )?))
    }

    pub fn put_cold_blinded_block(
        &self,
        block_root: &Hash256,
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<(), Error> {
        let mut ops = Vec::with_capacity(2);
        self.blinded_block_as_cold_kv_store_ops(block_root, block, &mut ops)?;
        self.cold_db.do_atomically(ops)
    }

    pub fn blinded_block_as_cold_kv_store_ops(
        &self,
        block_root: &Hash256,
        block: &SignedBlindedBeaconBlock<E>,
        kv_store_ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        // Write the block root to slot mapping.
        let slot = block.slot();
        kv_store_ops.push(FrozenBlockSlot(slot).as_kv_store_op(*block_root)?);

        // Write the block keyed by slot.
        let db_key = get_key_for_col(
            DBColumn::BeaconBlockFrozen.into(),
            &slot.as_u64().to_be_bytes(),
        );

        let ssz_bytes = block.as_ssz_bytes();
        let mut compressed_value =
            Vec::with_capacity(self.config.estimate_compressed_size(ssz_bytes.len()));
        let mut encoder = Encoder::new(&mut compressed_value, self.config.compression_level)
            .map_err(Error::Compression)?;
        encoder.write_all(&ssz_bytes).map_err(Error::Compression)?;
        encoder.finish().map_err(Error::Compression)?;

        kv_store_ops.push(KeyValueStoreOp::PutKeyValue(db_key, compressed_value));

        Ok(())
    }

    /// Fetch a block from the store, ignoring which fork variant it *should* be for.
    pub fn get_block_any_variant<Payload: ExecPayload<E>>(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<SignedBeaconBlock<E, Payload>>, Error> {
        self.get_block_with(block_root, SignedBeaconBlock::any_from_ssz_bytes)
    }

    /// Fetch a block from the store using a custom decode function.
    ///
    /// This is useful for e.g. ignoring the slot-indicated fork to forcefully load a block as if it
    /// were for a different fork.
    pub fn get_block_with<Payload: ExecPayload<E>>(
        &self,
        block_root: &Hash256,
        decoder: impl FnOnce(&[u8]) -> Result<SignedBeaconBlock<E, Payload>, ssz::DecodeError>,
    ) -> Result<Option<SignedBeaconBlock<E, Payload>>, Error> {
        self.hot_db
            .get_bytes(DBColumn::BeaconBlock.into(), block_root.as_bytes())?
            .map(|block_bytes| decoder(&block_bytes))
            .transpose()
            .map_err(|e| e.into())
    }

    /// Load the execution payload for a block from disk.
    pub fn get_execution_payload(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<ExecutionPayload<E>>, Error> {
        self.get_item(block_root)
    }

    /// Check if the execution payload for a block exists on disk.
    pub fn execution_payload_exists(&self, block_root: &Hash256) -> Result<bool, Error> {
        self.get_item::<ExecutionPayload<E>>(block_root)
            .map(|payload| payload.is_some())
    }

    /// Determine whether a block exists in the database (hot *or* cold).
    pub fn block_exists(&self, block_root: &Hash256) -> Result<bool, Error> {
        Ok(self
            .hot_db
            .key_exists(DBColumn::BeaconBlock.into(), block_root.as_bytes())?
            || self
                .cold_db
                .key_exists(DBColumn::BeaconBlock.into(), block_root.as_bytes())?)
    }

    /// Delete a block from the store and the block cache.
    pub fn delete_block(&self, block_root: &Hash256) -> Result<(), Error> {
        self.block_cache.lock().pop(block_root);
        self.hot_db
            .key_delete(DBColumn::BeaconBlock.into(), block_root.as_bytes())?;
        self.hot_db
            .key_delete(DBColumn::ExecPayload.into(), block_root.as_bytes())
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
                self.get_hot_state(state_root)
            }
        } else {
            match self.get_hot_state(state_root)? {
                Some(state) => Ok(Some(state)),
                None => self.load_cold_state(state_root),
            }
        }
    }

    /// Get a state with `latest_block_root == block_root` advanced through to at most `slot`.
    ///
    /// The `state_root` argument is used to look up the block's un-advanced state in case of a
    /// cache miss.
    pub fn get_advanced_state(
        &self,
        block_root: Hash256,
        slot: Slot,
        state_root: Hash256,
    ) -> Result<Option<(Hash256, BeaconState<E>)>, Error> {
        if let Some(cached) = self.state_cache.lock().get_by_block_root(block_root, slot) {
            return Ok(Some(cached));
        }
        Ok(self
            .get_hot_state(&state_root)?
            .map(|state| (state_root, state)))
    }

    /// Delete a state, ensuring it is removed from the LRU cache, as well as from on-disk.
    ///
    /// It is assumed that all states being deleted reside in the hot DB, even if their slot is less
    /// than the split point. You shouldn't delete states from the finalized portion of the chain
    /// (which are frozen, and won't be deleted), or valid descendents of the finalized checkpoint
    /// (which will be deleted by this function but shouldn't be).
    pub fn delete_state(&self, state_root: &Hash256, slot: Slot) -> Result<(), Error> {
        self.do_atomically(vec![StoreOp::DeleteState(*state_root, Some(slot))])
    }

    pub fn forwards_block_roots_iterator(
        &self,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>> + '_, Error> {
        HybridForwardsBlockRootsIterator::new(
            self,
            start_slot,
            None,
            || (end_state, end_block_root),
            spec,
        )
    }

    pub fn forwards_block_roots_iterator_until(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        get_state: impl FnOnce() -> (BeaconState<E>, Hash256),
        spec: &ChainSpec,
    ) -> Result<HybridForwardsBlockRootsIterator<E, Hot, Cold>, Error> {
        HybridForwardsBlockRootsIterator::new(self, start_slot, Some(end_slot), get_state, spec)
    }

    pub fn forwards_state_roots_iterator(
        &self,
        start_slot: Slot,
        end_state_root: Hash256,
        end_state: BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>> + '_, Error> {
        HybridForwardsStateRootsIterator::new(
            self,
            start_slot,
            None,
            || (end_state, end_state_root),
            spec,
        )
    }

    pub fn forwards_state_roots_iterator_until(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        get_state: impl FnOnce() -> (BeaconState<E>, Hash256),
        spec: &ChainSpec,
    ) -> Result<HybridForwardsStateRootsIterator<E, Hot, Cold>, Error> {
        HybridForwardsStateRootsIterator::new(self, start_slot, Some(end_slot), get_state, spec)
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
    pub fn convert_to_kv_batch(
        &self,
        batch: Vec<StoreOp<E>>,
    ) -> Result<Vec<KeyValueStoreOp>, Error> {
        let mut key_value_batch = Vec::with_capacity(batch.len());
        for op in batch {
            match op {
                StoreOp::PutBlock(block_root, block) => {
                    self.block_as_kv_store_ops(
                        &block_root,
                        block.as_ref().clone(),
                        &mut key_value_batch,
                    )?;
                }

                StoreOp::PutState(state_root, state) => {
                    self.store_hot_state(&state_root, state, &mut key_value_batch)?;
                }

                StoreOp::PutStateTemporaryFlag(state_root) => {
                    key_value_batch.push(TemporaryFlag.as_kv_store_op(state_root)?);
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
                        // Delete full state if any.
                        let state_key =
                            get_key_for_col(DBColumn::BeaconState.into(), state_root.as_bytes());
                        key_value_batch.push(KeyValueStoreOp::DeleteKey(state_key));

                        // Delete diff too.
                        let diff_key = get_key_for_col(
                            DBColumn::BeaconStateDiff.into(),
                            state_root.as_bytes(),
                        );
                        key_value_batch.push(KeyValueStoreOp::DeleteKey(diff_key));
                    }
                }
                StoreOp::KeyValueOp(kv_op) => key_value_batch.push(kv_op),
                StoreOp::DeleteExecutionPayload(block_root) => {
                    let key = get_key_for_col(DBColumn::ExecPayload.into(), block_root.as_bytes());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(key));
                }
            }
        }
        Ok(key_value_batch)
    }

    pub fn do_atomically(&self, batch: Vec<StoreOp<E>>) -> Result<(), Error> {
        // Update the block cache whilst holding a lock, to ensure that the cache updates atomically
        // with the database.
        let mut block_cache = self.block_cache.lock();

        for op in &batch {
            match op {
                StoreOp::PutBlock(block_root, block) => {
                    block_cache.put(*block_root, (**block).clone());
                }

                StoreOp::PutState(_, _) => (),

                StoreOp::PutStateTemporaryFlag(_) => (),

                StoreOp::DeleteStateTemporaryFlag(_) => (),

                StoreOp::DeleteBlock(block_root) => {
                    block_cache.pop(block_root);
                    self.state_cache.lock().delete_block_states(block_root);
                }

                StoreOp::DeleteState(state_root, _) => {
                    self.state_cache.lock().delete_state(state_root)
                }

                StoreOp::KeyValueOp(_) => (),

                StoreOp::DeleteExecutionPayload(_) => (),
            }
        }

        self.hot_db
            .do_atomically(self.convert_to_kv_batch(batch)?)?;
        drop(block_cache);

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
        // Put the state in the cache.
        // FIXME(sproul): could optimise out the block root
        let block_root = state.get_latest_block_root(*state_root);

        // Avoid storing states in the database if they already exist in the state cache.
        // The exception to this is the finalized state, which must exist in the cache before it
        // is stored on disk.
        if let PutStateOutcome::Duplicate =
            self.state_cache
                .lock()
                .put_state(*state_root, block_root, state)?
        {
            return Ok(());
        }

        // Store a summary of the state.
        // We store one even for the epoch boundary states, as we may need their slots
        // when doing a look up by state root.
        let diff_base_slot = self.state_diff_slot(state.slot());

        let hot_state_summary = HotStateSummary::new(state_root, state, diff_base_slot)?;
        let op = hot_state_summary.as_kv_store_op(*state_root)?;
        ops.push(op);

        // On an epoch boundary, consider storing:
        //
        // 1. A full state, if the state is the split state or a fork boundary state.
        // 2. A state diff, if the state is a multiple of `epochs_per_state_diff` after the
        //    split state.
        if state.slot() % E::slots_per_epoch() == 0 {
            if self.is_stored_as_full_state(*state_root, state.slot())? {
                info!(
                    self.log,
                    "Storing full state on epoch boundary";
                    "slot" => state.slot(),
                    "state_root" => ?state_root,
                );
                self.store_full_state_in_batch(state_root, state, ops)?;
            } else if let Some(base_slot) = diff_base_slot {
                debug!(
                    self.log,
                    "Storing state diff on boundary";
                    "slot" => state.slot(),
                    "base_slot" => base_slot,
                    "state_root" => ?state_root,
                );
                let diff_base_state_root = hot_state_summary.diff_base_state_root;
                let diff_base_state = self.get_hot_state(&diff_base_state_root)?.ok_or(
                    HotColdDBError::MissingEpochBoundaryState(diff_base_state_root),
                )?;

                let compute_diff_timer =
                    metrics::start_timer(&metrics::BEACON_STATE_DIFF_COMPUTE_TIME);
                let diff = BeaconStateDiff::compute_diff(&diff_base_state, state)?;
                drop(compute_diff_timer);
                ops.push(self.state_diff_as_kv_store_op(state_root, &diff)?);
            }
        }

        Ok(())
    }

    pub fn store_full_state(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        let mut ops = Vec::with_capacity(4);
        self.store_full_state_in_batch(state_root, state, &mut ops)?;
        self.hot_db.do_atomically(ops)
    }

    pub fn store_full_state_in_batch(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        store_full_state(state_root, state, ops, &self.config)
    }

    /// Get a post-finalization state from the database or store.
    pub fn get_hot_state(&self, state_root: &Hash256) -> Result<Option<BeaconState<E>>, Error> {
        if let Some(state) = self.state_cache.lock().get_by_state_root(*state_root) {
            return Ok(Some(state));
        }
        warn!(
            self.log,
            "State cache missed";
            "state_root" => ?state_root,
        );

        let state_from_disk = self.load_hot_state(state_root)?;

        if let Some((state, block_root)) = state_from_disk {
            self.state_cache
                .lock()
                .put_state(*state_root, block_root, &state)?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    /// Load a post-finalization state from the hot database.
    ///
    /// Use a combination of state diffs and replayed blocks as appropriate.
    ///
    /// Return the `(state, latest_block_root)` if found.
    pub fn load_hot_state(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<(BeaconState<E>, Hash256)>, Error> {
        let _timer = metrics::start_timer(&metrics::BEACON_HOT_STATE_READ_TIMES);
        metrics::inc_counter(&metrics::BEACON_STATE_HOT_GET_COUNT);

        // If the state is the finalized state, load it from disk. This should only be necessary
        // once during start-up, after which point the finalized state will be cached.
        if *state_root == self.get_split_info().state_root {
            return self.load_hot_state_full(state_root).map(Some);
        }

        let target_summary = if let Some(summary) = self.load_hot_state_summary(state_root)? {
            summary
        } else {
            return Ok(None);
        };

        let target_slot = target_summary.slot;
        let target_latest_block_root = target_summary.latest_block_root;

        // Load the latest block, and use it to confirm the validity of this state.
        if self
            .get_blinded_block(&target_summary.latest_block_root, None)?
            .is_none()
        {
            // Dangling state, will be deleted fully once finalization advances past it.
            debug!(
                self.log,
                "Ignoring state load for dangling state";
                "state_root" => ?state_root,
                "slot" => target_slot,
                "latest_block_root" => ?target_summary.latest_block_root,
            );
            return Ok(None);
        }

        // Backtrack until we reach a state that is in the cache, or in the worst case
        // the finalized state (this should only be reachable on first start-up).
        let state_summary_iter = HotStateRootIter::new(self, target_slot, *state_root);

        // State and state root of the state upon which blocks and diffs will be replayed.
        let mut base_state = None;

        // State diffs to be replayed on top of `base_state`.
        // Each element is `(summary, state_root, diff)` such that applying `diff` to the
        // state with `summary.diff_base_state_root` yields the state with `state_root`.
        let mut state_diffs = VecDeque::new();

        // State roots for all slots between `base_state` and the `target_slot`. Depending on how
        // the diffs fall, some of these roots may not be needed.
        let mut state_roots = VecDeque::new();

        for res in state_summary_iter {
            let (prior_state_root, prior_summary) = res?;

            state_roots.push_front(Ok((prior_state_root, prior_summary.slot)));

            // Check if this state is in the cache.
            if let Some(state) = self.state_cache.lock().get_by_state_root(prior_state_root) {
                debug!(
                    self.log,
                    "Found cached base state for replay";
                    "base_state_root" => ?prior_state_root,
                    "base_slot" => prior_summary.slot,
                    "target_state_root" => ?state_root,
                    "target_slot" => target_slot,
                );
                base_state = Some((prior_state_root, state));
                break;
            }

            // If the prior state is the split state and it isn't cached then load it in
            // entirety from disk. This should only happen on first start up.
            if prior_state_root == self.get_split_info().state_root {
                debug!(
                    self.log,
                    "Using split state as base state for replay";
                    "base_state_root" => ?prior_state_root,
                    "base_slot" => prior_summary.slot,
                    "target_state_root" => ?state_root,
                    "target_slot" => target_slot,
                );
                let (split_state, _) = self.load_hot_state_full(&prior_state_root)?;
                base_state = Some((prior_state_root, split_state));
                break;
            }

            // If there's a state diff stored at this slot, load it and store it for application.
            if !prior_summary.diff_base_state_root.is_zero() {
                let diff = self.load_state_diff(prior_state_root)?;
                state_diffs.push_front((prior_summary, prior_state_root, diff));
            }
        }

        let (_, mut state) = base_state.ok_or(Error::NoBaseStateFound(*state_root))?;

        // Construct a mutable iterator for the state roots, which will be iterated through
        // consecutive calls to `replay_blocks`.
        let mut state_roots_iter = state_roots.into_iter();

        // This hook caches states from block replay so that they may be reused.
        let state_cacher_hook = |opt_state_root: Option<Hash256>, state: &mut BeaconState<_>| {
            // Ensure all caches are built before attempting to cache.
            state.update_tree_hash_cache()?;
            state.build_all_caches(&self.spec)?;

            if let Some(state_root) = opt_state_root {
                // Cache
                if state.slot() + MAX_PARENT_STATES_TO_CACHE >= target_slot
                    || state.slot() % E::slots_per_epoch() == 0
                {
                    let slot = state.slot();
                    let latest_block_root = state.get_latest_block_root(state_root);
                    if let PutStateOutcome::New =
                        self.state_cache
                            .lock()
                            .put_state(state_root, latest_block_root, state)?
                    {
                        debug!(
                            self.log,
                            "Cached ancestor state";
                            "state_root" => ?state_root,
                            "slot" => slot,
                        );
                    }
                }
            } else {
                debug!(
                    self.log,
                    "Block replay state root miss";
                    "slot" => state.slot(),
                );
            }
            Ok(())
        };

        // Apply the diffs, and replay blocks atop the base state to reach the target state.
        while state.slot() < target_slot {
            // Drop unncessary diffs.
            state_diffs.retain(|(summary, diff_root, _)| {
                let keep = summary.diff_base_slot >= state.slot();
                if !keep {
                    debug!(
                        self.log,
                        "Ignoring irrelevant state diff";
                        "diff_state_root" => ?diff_root,
                        "diff_base_slot" => summary.diff_base_slot,
                        "current_state_slot" => state.slot(),
                    );
                }
                keep
            });

            // Get the next diff that will be applicable, taking the highest slot diff in case of
            // multiple diffs which are applicable at the same base slot, which can happen if the
            // diff frequency has changed.
            let mut next_state_diff: Option<(HotStateSummary, Hash256, BeaconStateDiff<_>)> = None;
            while let Some((summary, _, _)) = state_diffs.front() {
                if next_state_diff.as_ref().map_or(true, |(current, _, _)| {
                    summary.diff_base_slot == current.diff_base_slot
                }) {
                    next_state_diff = state_diffs.pop_front();
                } else {
                    break;
                }
            }

            // Replay blocks to get to the next diff's base state, or to the target state if there
            // is no next diff to apply.
            if next_state_diff
                .as_ref()
                .map_or(true, |(next_summary, _, _)| {
                    next_summary.diff_base_slot != state.slot()
                })
            {
                let (next_slot, latest_block_root) = next_state_diff
                    .as_ref()
                    .map(|(summary, _, _)| (summary.diff_base_slot, summary.latest_block_root))
                    .unwrap_or_else(|| (target_summary.slot, target_latest_block_root));
                debug!(
                    self.log,
                    "Replaying blocks";
                    "from_slot" => state.slot(),
                    "to_slot" => next_slot,
                    "latest_block_root" => ?latest_block_root,
                );
                let blocks =
                    self.load_blocks_to_replay(state.slot(), next_slot, latest_block_root)?;

                state = self.replay_blocks(
                    state,
                    blocks,
                    next_slot,
                    &mut state_roots_iter,
                    Some(Box::new(state_cacher_hook)),
                )?;

                state.update_tree_hash_cache()?;
                state.build_all_caches(&self.spec)?;
            }

            // Apply state diff. Block replay should have ensured that the diff is now applicable.
            if let Some((summary, to_root, diff)) = next_state_diff {
                debug!(
                    self.log,
                    "Applying state diff";
                    "from_root" => ?summary.diff_base_state_root,
                    "from_slot" => summary.diff_base_slot,
                    "to_root" => ?to_root,
                    "to_slot" => summary.slot,
                );
                debug_assert_eq!(summary.diff_base_slot, state.slot());

                diff.apply_diff(&mut state)?;

                state.update_tree_hash_cache()?;
                state.build_all_caches(&self.spec)?;
            }
        }

        Ok(Some((state, target_latest_block_root)))
    }

    /// Determine if the `state_root` at `slot` should be stored as a full state.
    ///
    /// This is dependent on the database's current split point, so may change from `false` to
    /// `true` after a finalization update. It cannot change from `true` to `false` for a state in
    /// the hot database as the split state will be migrated to the freezer.
    ///
    /// All fork boundary states are also stored as full states.
    pub fn is_stored_as_full_state(&self, state_root: Hash256, slot: Slot) -> Result<bool, Error> {
        let split = self.get_split_info();

        if slot >= split.slot {
            Ok(state_root == split.state_root
                || self.spec.fork_activated_at_slot::<E>(slot).is_some())
        } else {
            Err(Error::SlotIsBeforeSplit { slot })
        }
    }

    /// Determine if a state diff should be stored at `slot`.
    ///
    /// If `Some(base_slot)` is returned then a state diff should be constructed for the state
    /// at `slot` based on the ancestor state at `base_slot`. The frequency of state diffs stored
    /// on disk is determined by the `epochs_per_state_diff` parameter.
    pub fn state_diff_slot(&self, slot: Slot) -> Option<Slot> {
        let split = self.get_split_info();
        let slots_per_epoch = E::slots_per_epoch();

        if slot % slots_per_epoch != 0 {
            return None;
        }

        let epochs_since_split = slot.saturating_sub(split.slot).epoch(slots_per_epoch);

        (epochs_since_split > 0 && epochs_since_split % self.config.epochs_per_state_diff == 0)
            .then(|| slot.saturating_sub(self.config.epochs_per_state_diff * slots_per_epoch))
    }

    pub fn load_hot_state_full(
        &self,
        state_root: &Hash256,
    ) -> Result<(BeaconState<E>, Hash256), Error> {
        let pubkey_cache = self.immutable_validators.read();
        let immutable_validators = |i: usize| pubkey_cache.get_validator(i);
        let mut state = get_full_state(
            &self.hot_db,
            state_root,
            immutable_validators,
            &self.config,
            &self.spec,
        )?
        .ok_or(HotColdDBError::MissingEpochBoundaryState(*state_root))?;

        // Do a tree hash here so that the cache is fully built.
        state.update_tree_hash_cache()?;
        state.build_all_caches(&self.spec)?;

        let latest_block_root = state.get_latest_block_root(*state_root);
        Ok((state, latest_block_root))
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
        ops.push(ColdStateSummary { slot: state.slot() }.as_kv_store_op(*state_root)?);

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
        let op = partial_state.as_kv_store_op(&self.config)?;
        ops.push(op);

        // 2. Store updated vector entries.
        let db = &self.cold_db;
        store_updated_vector(BlockRoots, db, state, &self.spec, ops)?;
        store_updated_vector(StateRoots, db, state, &self.spec, ops)?;
        store_updated_vector(HistoricalRoots, db, state, &self.spec, ops)?;
        store_updated_vector(RandaoMixes, db, state, &self.spec, ops)?;

        // 3. Store restore point.
        // FIXME(sproul): backwards compat
        /*
        let restore_point_index = state.slot().as_u64() / self.config.slots_per_restore_point;
        self.store_restore_point_hash(restore_point_index, *state_root, ops)?;
        */

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
                self.load_restore_point(slot)
            } else {
                self.load_cold_intermediate_state(slot)
            }
            .map(Some)
        } else {
            Ok(None)
        }
    }

    /// Load a restore point state by its `slot`.
    fn load_restore_point(&self, slot: Slot) -> Result<BeaconState<E>, Error> {
        let bytes = self
            .cold_db
            .get_bytes(
                DBColumn::BeaconRestorePointState.into(),
                &slot.as_u64().to_be_bytes(),
            )?
            .ok_or(HotColdDBError::MissingRestorePointState(slot))?;

        let mut ssz_bytes = Vec::with_capacity(self.config.estimate_decompressed_size(bytes.len()));
        let mut decoder = Decoder::new(&*bytes).map_err(Error::Compression)?;
        decoder
            .read_to_end(&mut ssz_bytes)
            .map_err(Error::Compression)?;

        let mut partial_state: PartialBeaconState<E> =
            PartialBeaconState::from_ssz_bytes(&ssz_bytes, &self.spec)?;

        // Fill in the fields of the partial state.
        partial_state.load_block_roots(&self.cold_db, &self.spec)?;
        partial_state.load_state_roots(&self.cold_db, &self.spec)?;
        partial_state.load_historical_roots(&self.cold_db, &self.spec)?;
        partial_state.load_randao_mixes(&self.cold_db, &self.spec)?;

        let pubkey_cache = self.immutable_validators.read();
        let immutable_validators = |i: usize| pubkey_cache.get_validator(i);

        partial_state.try_into_full_state(immutable_validators)
    }

    /* FIXME(sproul): backwards compat
    /// Load a restore point state by its `restore_point_index`.
    fn load_legacy_restore_point_by_index(
        &self,
        restore_point_index: u64,
    ) -> Result<BeaconState<E>, Error> {
        let state_root = self.load_restore_point_hash(restore_point_index)?;
        self.load_restore_point(&state_root)
    }
    */

    /// Load a frozen state that lies between restore points.
    fn load_cold_intermediate_state(&self, slot: Slot) -> Result<BeaconState<E>, Error> {
        // 1. Load the restore points either side of the intermediate state.
        let sprp = self.config.slots_per_restore_point;
        let low_restore_point_slot = slot / sprp * sprp;
        let high_restore_point_slot = low_restore_point_slot + sprp;

        // Acquire the read lock, so that the split can't change while this is happening.
        let split = self.split.read_recursive();

        let low_restore_point = self.load_restore_point(low_restore_point_slot)?;
        let high_restore_point = self.get_restore_point(high_restore_point_slot, &split)?;

        // 2. Load the blocks from the high restore point back to the low restore point.
        let blocks = self.load_blocks_to_replay(
            low_restore_point.slot(),
            slot,
            self.get_high_restore_point_block_root(&high_restore_point, slot)?,
        )?;

        // 3. Replay the blocks on top of the low restore point.
        // Use a forwards state root iterator to avoid doing any tree hashing.
        // The state root of the high restore point should never be used, so is safely set to 0.
        let state_root_iter = self.forwards_state_roots_iterator_until(
            low_restore_point.slot(),
            slot,
            || (high_restore_point, Hash256::zero()),
            &self.spec,
        )?;

        self.replay_blocks(low_restore_point, blocks, slot, state_root_iter, None)
    }

    /// Get the restore point with the given index, or if it is out of bounds, the split state.
    pub(crate) fn get_restore_point(
        &self,
        slot: Slot,
        split: &Split,
    ) -> Result<BeaconState<E>, Error> {
        if slot >= split.slot.as_u64() {
            self.get_state(&split.state_root, Some(split.slot))?
                .ok_or(HotColdDBError::MissingSplitState(
                    split.state_root,
                    split.slot,
                ))
                .map_err(Into::into)
        } else {
            self.load_restore_point(slot)
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
    ) -> Result<Vec<SignedBeaconBlock<E, BlindedPayload<E>>>, Error> {
        let mut blocks = ParentRootBlockIterator::new(self, end_block_hash)
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
            .collect::<Result<Vec<_>, _>>()?;
        blocks.reverse();
        Ok(blocks)
    }

    /// Replay `blocks` on top of `state` until `target_slot` is reached.
    ///
    /// Will skip slots as necessary. The returned state is not guaranteed
    /// to have any caches built, beyond those immediately required by block processing.
    pub fn replay_blocks(
        &self,
        state: BeaconState<E>,
        blocks: Vec<SignedBeaconBlock<E, BlindedPayload<E>>>,
        target_slot: Slot,
        state_root_iter: impl Iterator<Item = Result<(Hash256, Slot), Error>>,
        pre_slot_hook: Option<PreSlotHook<E, Error>>,
    ) -> Result<BeaconState<E>, Error> {
        let mut block_replayer = BlockReplayer::new(state, &self.spec)
            .no_signature_verification()
            .minimal_block_root_verification()
            .state_root_iter(state_root_iter);

        if let Some(pre_slot_hook) = pre_slot_hook {
            block_replayer = block_replayer.pre_slot_hook(pre_slot_hook);
        }

        block_replayer
            .apply_blocks(blocks, Some(target_slot))
            .map(|block_replayer| {
                // FIXME(sproul): tweak state miss condition
                /*
                if block_replayer.state_root_miss() {
                    Err(Error::MissingStateRoot(target_slot))
                }
                */
                block_replayer.into_state()
            })
    }

    /// Get a reference to the `ChainSpec` used by the database.
    pub fn get_chain_spec(&self) -> &ChainSpec {
        &self.spec
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

    /// Store the database schema version atomically with additional operations.
    pub fn store_schema_version_atomically(
        &self,
        schema_version: SchemaVersion,
        mut ops: Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        let column = SchemaVersion::db_column().into();
        let key = SCHEMA_VERSION_KEY.as_bytes();
        let db_key = get_key_for_col(column, key);
        let op = KeyValueStoreOp::PutKeyValue(db_key, schema_version.as_store_bytes()?);
        ops.push(op);

        self.hot_db.do_atomically(ops)
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
            let kv_op = self.store_anchor_info_in_batch(&new_value)?;
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
    fn store_anchor_info_in_batch(
        &self,
        anchor_info: &Option<AnchorInfo>,
    ) -> Result<KeyValueStoreOp, Error> {
        if let Some(ref anchor_info) = anchor_info {
            anchor_info.as_kv_store_op(ANCHOR_INFO_KEY)
        } else {
            Ok(KeyValueStoreOp::DeleteKey(get_key_for_col(
                DBColumn::BeaconMeta.into(),
                ANCHOR_INFO_KEY.as_bytes(),
            )))
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

    /// Return the in-memory configuration used by the database.
    pub fn get_config(&self) -> &StoreConfig {
        &self.config
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
    pub fn store_split_in_batch(&self) -> Result<KeyValueStoreOp, Error> {
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
    ) -> Result<(), Error> {
        let value = &RestorePointHash { state_root };
        let op = value.as_kv_store_op(Self::restore_point_key(restore_point_index))?;
        ops.push(op);
        Ok(())
    }

    /// Convert a `restore_point_index` into a database key.
    fn restore_point_key(restore_point_index: u64) -> Hash256 {
        Hash256::from_low_u64_be(restore_point_index)
    }

    /// Load a frozen state's slot, given its root.
    pub fn load_cold_state_slot(&self, state_root: &Hash256) -> Result<Option<Slot>, Error> {
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

    /// Iterate all hot state summaries in the database.
    pub fn iter_hot_state_summaries(
        &self,
    ) -> impl Iterator<Item = Result<(Hash256, HotStateSummary), Error>> + '_ {
        self.hot_db
            .iter_column(DBColumn::BeaconStateSummary)
            .map(|res| {
                let (key, value_bytes) = res?;
                Ok((key, HotStateSummary::from_store_bytes(&value_bytes)?))
            })
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
            .do_atomically(vec![self.pruning_checkpoint_store_op(checkpoint)?])
    }

    /// Create a staged store for the pruning checkpoint.
    pub fn pruning_checkpoint_store_op(
        &self,
        checkpoint: Checkpoint,
    ) -> Result<KeyValueStoreOp, Error> {
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

    /// Try to prune all execution payloads, returning early if there is no need to prune.
    pub fn try_prune_execution_payloads(&self, force: bool) -> Result<(), Error> {
        let split = self.get_split_info();

        if split.slot == 0 {
            return Ok(());
        }

        let bellatrix_fork_slot = if let Some(epoch) = self.spec.bellatrix_fork_epoch {
            epoch.start_slot(E::slots_per_epoch())
        } else {
            return Ok(());
        };

        // Load the split state so we can backtrack to find execution payloads.
        let split_state = self.get_state(&split.state_root, Some(split.slot))?.ok_or(
            HotColdDBError::MissingSplitState(split.state_root, split.slot),
        )?;

        // The finalized block may or may not have its execution payload stored, depending on
        // whether it was at a skipped slot. However for a fully pruned database its parent
        // should *always* have been pruned. In case of a long split (no parent found) we
        // continue as if the payloads are pruned, as the node probably has other things to worry
        // about.
        let split_block_root = split_state.get_latest_block_root(split.state_root);

        let already_pruned =
            process_results(split_state.rev_iter_block_roots(&self.spec), |mut iter| {
                iter.find(|(_, block_root)| *block_root != split_block_root)
                    .map_or(Ok(true), |(_, split_parent_root)| {
                        self.execution_payload_exists(&split_parent_root)
                            .map(|exists| !exists)
                    })
            })??;

        if already_pruned && !force {
            info!(self.log, "Execution payloads are pruned");
            return Ok(());
        }

        // Iterate block roots backwards to the Bellatrix fork or the anchor slot, whichever comes
        // first.
        warn!(
            self.log,
            "Pruning finalized payloads";
            "info" => "you may notice degraded I/O performance while this runs"
        );
        let anchor_slot = self.get_anchor_info().map(|info| info.anchor_slot);

        let mut ops = vec![];
        let mut last_pruned_block_root = None;

        for res in std::iter::once(Ok((split_block_root, split.slot)))
            .chain(BlockRootsIterator::new(self, &split_state))
        {
            let (block_root, slot) = match res {
                Ok(tuple) => tuple,
                Err(e) => {
                    warn!(
                        self.log,
                        "Stopping payload pruning early";
                        "error" => ?e,
                    );
                    break;
                }
            };

            if slot < bellatrix_fork_slot {
                info!(
                    self.log,
                    "Payload pruning reached Bellatrix boundary";
                );
                break;
            }

            if Some(block_root) != last_pruned_block_root
                && self.execution_payload_exists(&block_root)?
            {
                debug!(
                    self.log,
                    "Pruning execution payload";
                    "slot" => slot,
                    "block_root" => ?block_root,
                );
                last_pruned_block_root = Some(block_root);
                ops.push(StoreOp::DeleteExecutionPayload(block_root));
            }

            if Some(slot) == anchor_slot {
                info!(
                    self.log,
                    "Payload pruning reached anchor state";
                    "slot" => slot
                );
                break;
            }
        }
        let payloads_pruned = ops.len();
        self.do_atomically(ops)?;
        info!(
            self.log,
            "Execution payload pruning complete";
            "payloads_pruned" => payloads_pruned,
        );
        Ok(())
    }
}

/// Advance the split point of the store, moving new finalized states to the freezer.
pub fn migrate_database<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: Arc<HotColdDB<E, Hot, Cold>>,
    finalized_state_root: Hash256,
    finalized_block_root: Hash256,
    finalized_state: &BeaconState<E>,
) -> Result<(), Error> {
    debug!(
        store.log,
        "Freezer migration started";
        "slot" => finalized_state.slot()
    );

    // 0. Check that the migration is sensible.
    // The new finalized state must increase the current split slot, and lie on an epoch
    // boundary (in order for the hot state summary scheme to work).
    let current_split_slot = store.split.read_recursive().slot;
    let anchor_slot = store
        .anchor_info
        .read_recursive()
        .as_ref()
        .map(|a| a.anchor_slot);

    if finalized_state.slot() < current_split_slot {
        return Err(HotColdDBError::FreezeSlotError {
            current_split_slot,
            proposed_split_slot: finalized_state.slot(),
        }
        .into());
    }

    if finalized_state.slot() % E::slots_per_epoch() != 0 {
        return Err(HotColdDBError::FreezeSlotUnaligned(finalized_state.slot()).into());
    }

    // Store the new finalized state as a full state in the database. It would likely previously
    // have been stored in memory, or maybe as a diff.
    store.store_full_state(&finalized_state_root, finalized_state)?;

    // Copy all of the states between the new finalized state and the split slot, from the hot DB to
    // the cold DB.
    let mut hot_db_ops: Vec<StoreOp<E>> = Vec::new();
    let mut cold_db_block_ops: Vec<KeyValueStoreOp> = vec![];

    let state_root_iter = RootsIterator::new(&store, finalized_state);
    for maybe_tuple in state_root_iter.take_while(|result| match result {
        Ok((_, _, slot)) => {
            slot >= &current_split_slot
                && anchor_slot.map_or(true, |anchor_slot| slot >= &anchor_slot)
        }
        Err(_) => true,
    }) {
        let (block_root, state_root, slot) = maybe_tuple?;

        let mut cold_db_ops: Vec<KeyValueStoreOp> = Vec::new();

        if slot % store.config.slots_per_restore_point == 0 {
            let state: BeaconState<E> = store
                .get_hot_state(&state_root)?
                .ok_or(HotColdDBError::MissingStateToFreeze(state_root))?;

            store.store_cold_state(&state_root, &state, &mut cold_db_ops)?;
        }

        // Store a pointer from this state root to its slot, so we can later reconstruct states
        // from their state root alone.
        let cold_state_summary = ColdStateSummary { slot };
        let op = cold_state_summary.as_kv_store_op(state_root)?;
        cold_db_ops.push(op);

        // There are data dependencies between calls to `store_cold_state()` that prevent us from
        // doing one big call to `store.cold_db.do_atomically()` at end of the loop.
        store.cold_db.do_atomically(cold_db_ops)?;

        // Delete the old summary, and the full state if we lie on an epoch boundary.
        hot_db_ops.push(StoreOp::DeleteState(state_root, Some(slot)));

        // Delete the execution payload if payload pruning is enabled. At a skipped slot we may
        // delete the payload for the finalized block itself, but that's OK as we only guarantee
        // that payloads are present for slots >= the split slot. The payload fetching code is also
        // forgiving of missing payloads.
        if store.config.prune_payloads {
            hot_db_ops.push(StoreOp::DeleteExecutionPayload(block_root));
        }

        // Copy the blinded block from the hot database to the freezer.
        let blinded_block = store
            .get_blinded_block(&block_root, None)?
            .ok_or(Error::BlockNotFound(block_root))?;
        if blinded_block.slot() == slot {
            store.blinded_block_as_cold_kv_store_ops(
                &block_root,
                &blinded_block,
                &mut cold_db_block_ops,
            )?;
        }
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
    store.cold_db.do_atomically(cold_db_block_ops)?;
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
            slot: finalized_state.slot(),
            state_root: finalized_state_root,
        };
        store.hot_db.put_sync(&SPLIT_KEY, &split)?;

        // Split point is now persisted in the hot database on disk.  The in-memory split point
        // hasn't been modified elsewhere since we keep a write lock on it.  It's safe to update
        // the in-memory split point now.
        *split_guard = split;
    }

    // Delete the states from the hot database if we got this far.
    store.do_atomically(hot_db_ops)?;

    // Update the cache's view of the finalized state.
    store.update_finalized_state(
        finalized_state_root,
        finalized_block_root,
        finalized_state.clone(),
    )?;

    debug!(
        store.log,
        "Freezer migration complete";
        "slot" => finalized_state.slot()
    );

    Ok(())
}

/// Struct for storing the split slot and state root in the database.
#[derive(Debug, Clone, Copy, PartialEq, Default, Encode, Decode, Deserialize, Serialize)]
pub struct Split {
    pub slot: Slot,
    pub state_root: Hash256,
}

impl StoreItem for Split {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.as_ssz_bytes())
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

/// Struct for summarising a state in the hot database.
///
/// Allows full reconstruction by replaying blocks.
// FIXME(sproul): change to V20
#[superstruct(
    variants(V1, V10),
    variant_attributes(derive(Debug, Clone, Copy, Default, Encode, Decode)),
    no_enum
)]
pub struct HotStateSummary {
    pub slot: Slot,
    pub latest_block_root: Hash256,
    /// The state root of a state prior to this state with respect to which this state's diff is
    /// stored.
    ///
    /// Set to 0 if this state *is not* stored as a diff.
    ///
    /// Formerly known as the `epoch_boundary_state_root`.
    pub diff_base_state_root: Hash256,
    /// The slot of the state with `diff_base_state_root`, or 0 if no diff is stored.
    pub diff_base_slot: Slot,
    /// The state root of the state at the prior slot.
    #[superstruct(only(V10))]
    pub prev_state_root: Hash256,
}

pub type HotStateSummary = HotStateSummaryV10;

macro_rules! impl_store_item_summary {
    ($t:ty) => {
        impl StoreItem for $t {
            fn db_column() -> DBColumn {
                DBColumn::BeaconStateSummary
            }

            fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
                Ok(self.as_ssz_bytes())
            }

            fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Ok(Self::from_ssz_bytes(bytes)?)
            }
        }
    };
}
impl_store_item_summary!(HotStateSummaryV1);
impl_store_item_summary!(HotStateSummaryV10);

impl HotStateSummary {
    /// Construct a new summary of the given state.
    pub fn new<E: EthSpec>(
        state_root: &Hash256,
        state: &BeaconState<E>,
        diff_base_slot: Option<Slot>,
    ) -> Result<Self, Error> {
        // Fill in the state root on the latest block header if necessary (this happens on all
        // slots where there isn't a skip).
        let slot = state.slot();
        let latest_block_root = state.get_latest_block_root(*state_root);

        // Set the diff state root as appropriate.
        let diff_base_state_root = if let Some(base_slot) = diff_base_slot {
            *state
                .get_state_root(base_slot)
                .map_err(HotColdDBError::HotStateSummaryError)?
        } else {
            Hash256::zero()
        };

        let prev_state_root = if let Ok(prev_slot) = slot.safe_sub(1) {
            *state
                .get_state_root(prev_slot)
                .map_err(HotColdDBError::HotStateSummaryError)?
        } else {
            Hash256::zero()
        };

        Ok(HotStateSummary {
            slot,
            latest_block_root,
            diff_base_state_root,
            diff_base_slot: diff_base_slot.unwrap_or(Slot::new(0)),
            prev_state_root,
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

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.as_ssz_bytes())
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

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.as_ssz_bytes())
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

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![])
    }

    fn from_store_bytes(_: &[u8]) -> Result<Self, Error> {
        Ok(TemporaryFlag)
    }
}
