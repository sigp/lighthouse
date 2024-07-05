use crate::chunked_vector::{
    store_updated_vector, BlockRoots, HistoricalRoots, HistoricalSummaries, RandaoMixes, StateRoots,
};
use crate::config::{
    OnDiskStoreConfig, StoreConfig, DEFAULT_SLOTS_PER_RESTORE_POINT,
    PREV_DEFAULT_SLOTS_PER_RESTORE_POINT,
};
use crate::forwards_iter::{HybridForwardsBlockRootsIterator, HybridForwardsStateRootsIterator};
use crate::impls::beacon_state::{get_full_state, store_full_state};
use crate::iter::{BlockRootsIterator, ParentRootBlockIterator, RootsIterator};
use crate::leveldb_store::BytesKey;
use crate::leveldb_store::LevelDB;
use crate::memory_store::MemoryStore;
use crate::metadata::{
    AnchorInfo, BlobInfo, CompactionTimestamp, PruningCheckpoint, SchemaVersion, ANCHOR_INFO_KEY,
    BLOB_INFO_KEY, COMPACTION_TIMESTAMP_KEY, CONFIG_KEY, CURRENT_SCHEMA_VERSION,
    PRUNING_CHECKPOINT_KEY, SCHEMA_VERSION_KEY, SPLIT_KEY, STATE_UPPER_LIMIT_NO_RETAIN,
};
use crate::metrics;
use crate::state_cache::{PutStateOutcome, StateCache};
use crate::{
    get_key_for_col, ChunkWriter, DBColumn, DatabaseBlock, Error, ItemStore, KeyValueStoreOp,
    PartialBeaconState, StoreItem, StoreOp,
};
use itertools::process_results;
use leveldb::iterator::LevelDBIterator;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use slog::{debug, error, info, trace, warn, Logger};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    block_replayer::PreSlotHook, AllCaches, BlockProcessingError, BlockReplayer,
    SlotProcessingError,
};
use std::cmp::min;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use types::*;

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
    /// The starting slots for the range of blobs stored in the database.
    blob_info: RwLock<BlobInfo>,
    pub(crate) config: StoreConfig,
    /// Cold database containing compact historical data.
    pub cold_db: Cold,
    /// Database containing blobs. If None, store falls back to use `cold_db`.
    pub blobs_db: Cold,
    /// Hot database containing duplicated but quick-to-access recent data.
    ///
    /// The hot database also contains all blocks.
    pub hot_db: Hot,
    /// LRU cache of deserialized blocks and blobs. Updated whenever a block or blob is loaded.
    block_cache: Mutex<BlockCache<E>>,
    /// Cache of beacon states.
    ///
    /// LOCK ORDERING: this lock must always be locked *after* the `split` if both are required.
    state_cache: Mutex<StateCache<E>>,
    /// LRU cache of replayed states.
    historic_state_cache: Mutex<LruCache<Slot, BeaconState<E>>>,
    /// Chain spec.
    pub(crate) spec: ChainSpec,
    /// Logger.
    pub log: Logger,
    /// Mere vessel for E.
    _phantom: PhantomData<E>,
}

#[derive(Debug)]
struct BlockCache<E: EthSpec> {
    block_cache: LruCache<Hash256, SignedBeaconBlock<E>>,
    blob_cache: LruCache<Hash256, BlobSidecarList<E>>,
}

impl<E: EthSpec> BlockCache<E> {
    pub fn new(size: NonZeroUsize) -> Self {
        Self {
            block_cache: LruCache::new(size),
            blob_cache: LruCache::new(size),
        }
    }
    pub fn put_block(&mut self, block_root: Hash256, block: SignedBeaconBlock<E>) {
        self.block_cache.put(block_root, block);
    }
    pub fn put_blobs(&mut self, block_root: Hash256, blobs: BlobSidecarList<E>) {
        self.blob_cache.put(block_root, blobs);
    }
    pub fn get_block<'a>(&'a mut self, block_root: &Hash256) -> Option<&'a SignedBeaconBlock<E>> {
        self.block_cache.get(block_root)
    }
    pub fn get_blobs<'a>(&'a mut self, block_root: &Hash256) -> Option<&'a BlobSidecarList<E>> {
        self.blob_cache.get(block_root)
    }
    pub fn delete_block(&mut self, block_root: &Hash256) {
        let _ = self.block_cache.pop(block_root);
    }
    pub fn delete_blobs(&mut self, block_root: &Hash256) {
        let _ = self.blob_cache.pop(block_root);
    }
    pub fn delete(&mut self, block_root: &Hash256) {
        let _ = self.block_cache.pop(block_root);
        let _ = self.blob_cache.pop(block_root);
    }
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
    MissingExecutionPayload(Hash256),
    MissingFullBlockExecutionPayloadPruned(Hash256, Slot),
    MissingAnchorInfo,
    BlobsPreviouslyInDefaultStore,
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
    ZeroEpochsPerBlobPrune,
    BlobPruneLogicError,
    RestorePointBlockHashError(BeaconStateError),
    IterationError {
        unexpected_key: BytesKey,
    },
    FinalizedStateNotInHotDatabase {
        split_slot: Slot,
        request_slot: Slot,
        block_root: Hash256,
    },
    Rollback,
}

impl<E: EthSpec> HotColdDB<E, MemoryStore<E>, MemoryStore<E>> {
    pub fn open_ephemeral(
        config: StoreConfig,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<HotColdDB<E, MemoryStore<E>, MemoryStore<E>>, Error> {
        Self::verify_config(&config)?;

        let db = HotColdDB {
            split: RwLock::new(Split::default()),
            anchor_info: RwLock::new(None),
            blob_info: RwLock::new(BlobInfo::default()),
            cold_db: MemoryStore::open(),
            blobs_db: MemoryStore::open(),
            hot_db: MemoryStore::open(),
            block_cache: Mutex::new(BlockCache::new(config.block_cache_size)),
            state_cache: Mutex::new(StateCache::new(config.state_cache_size)),
            historic_state_cache: Mutex::new(LruCache::new(config.historic_state_cache_size)),
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
    /// The `migrate_schema` function is passed in so that the parent `BeaconChain` can provide
    /// context and access `BeaconChain`-level code without creating a circular dependency.
    pub fn open(
        hot_path: &Path,
        cold_path: &Path,
        blobs_db_path: &Path,
        migrate_schema: impl FnOnce(Arc<Self>, SchemaVersion, SchemaVersion) -> Result<(), Error>,
        config: StoreConfig,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<Arc<Self>, Error> {
        Self::verify_slots_per_restore_point(config.slots_per_restore_point)?;

        let mut db = HotColdDB {
            split: RwLock::new(Split::default()),
            anchor_info: RwLock::new(None),
            blob_info: RwLock::new(BlobInfo::default()),
            cold_db: LevelDB::open(cold_path)?,
            blobs_db: LevelDB::open(blobs_db_path)?,
            hot_db: LevelDB::open(hot_path)?,
            block_cache: Mutex::new(BlockCache::new(config.block_cache_size)),
            state_cache: Mutex::new(StateCache::new(config.state_cache_size)),
            historic_state_cache: Mutex::new(LruCache::new(config.historic_state_cache_size)),
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

        // Open separate blobs directory if configured and same configuration was used on previous
        // run.
        let blob_info = db.load_blob_info()?;
        let deneb_fork_slot = db
            .spec
            .deneb_fork_epoch
            .map(|epoch| epoch.start_slot(E::slots_per_epoch()));
        let new_blob_info = match &blob_info {
            Some(blob_info) => {
                // If the oldest block slot is already set do not allow the blob DB path to be
                // changed (require manual migration).
                if blob_info.oldest_blob_slot.is_some() && !blob_info.blobs_db {
                    return Err(HotColdDBError::BlobsPreviouslyInDefaultStore.into());
                }
                // Set the oldest blob slot to the Deneb fork slot if it is not yet set.
                // Always initialize `blobs_db` to true, we no longer support storing the blobs
                // in the freezer DB, because the UX is strictly worse for relocating the DB.
                let oldest_blob_slot = blob_info.oldest_blob_slot.or(deneb_fork_slot);
                BlobInfo {
                    oldest_blob_slot,
                    blobs_db: true,
                }
            }
            // First start.
            None => BlobInfo {
                // Set the oldest blob slot to the Deneb fork slot if it is not yet set.
                oldest_blob_slot: deneb_fork_slot,
                blobs_db: true,
            },
        };
        db.compare_and_set_blob_info_with_write(<_>::default(), new_blob_info.clone())?;
        info!(
            db.log,
            "Blob DB initialized";
            "path" => ?blobs_db_path,
            "oldest_blob_slot" => ?new_blob_info.oldest_blob_slot,
        );

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
        self.block_cache.lock().put_block(*block_root, block);
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
            ops.push(execution_payload.as_kv_store_op(*key));
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
    ) -> Result<Option<DatabaseBlock<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_BLOCK_GET_COUNT);

        // Check the cache.
        if let Some(block) = self.block_cache.lock().get_block(block_root) {
            metrics::inc_counter(&metrics::BEACON_BLOCK_CACHE_HIT_COUNT);
            return Ok(Some(DatabaseBlock::Full(block.clone())));
        }

        // Load the blinded block.
        let Some(blinded_block) = self.get_blinded_block(block_root)? else {
            return Ok(None);
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
            self.block_cache
                .lock()
                .put_block(*block_root, full_block.clone());

            DatabaseBlock::Full(full_block)
        } else if !self.config.prune_payloads {
            // If payload pruning is disabled there's a chance we may have the payload of
            // this finalized block. Attempt to load it but don't error in case it's missing.
            let fork_name = blinded_block.fork_name(&self.spec)?;
            if let Some(payload) = self.get_execution_payload(block_root, fork_name)? {
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
    ) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        match self.try_get_full_block(block_root)? {
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
            let fork_name = blinded_block.fork_name(&self.spec)?;
            let execution_payload = self
                .get_execution_payload(block_root, fork_name)?
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
    ) -> Result<Option<SignedBeaconBlock<E, BlindedPayload<E>>>, Error> {
        self.get_block_with(block_root, |bytes| {
            SignedBeaconBlock::from_ssz_bytes(bytes, &self.spec)
        })
    }

    /// Fetch a block from the store, ignoring which fork variant it *should* be for.
    pub fn get_block_any_variant<Payload: AbstractExecPayload<E>>(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<SignedBeaconBlock<E, Payload>>, Error> {
        self.get_block_with(block_root, SignedBeaconBlock::any_from_ssz_bytes)
    }

    /// Fetch a block from the store using a custom decode function.
    ///
    /// This is useful for e.g. ignoring the slot-indicated fork to forcefully load a block as if it
    /// were for a different fork.
    pub fn get_block_with<Payload: AbstractExecPayload<E>>(
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
    /// This method deserializes with the proper fork.
    pub fn get_execution_payload(
        &self,
        block_root: &Hash256,
        fork_name: ForkName,
    ) -> Result<Option<ExecutionPayload<E>>, Error> {
        let column = ExecutionPayload::<E>::db_column().into();
        let key = block_root.as_bytes();

        match self.hot_db.get_bytes(column, key)? {
            Some(bytes) => Ok(Some(ExecutionPayload::from_ssz_bytes(&bytes, fork_name)?)),
            None => Ok(None),
        }
    }

    /// Load the execution payload for a block from disk.
    /// DANGEROUS: this method just guesses the fork.
    pub fn get_execution_payload_dangerous_fork_agnostic(
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

    /// Check if the blobs for a block exists on disk.
    pub fn blobs_exist(&self, block_root: &Hash256) -> Result<bool, Error> {
        self.blobs_db
            .key_exists(DBColumn::BeaconBlob.into(), block_root.as_bytes())
    }

    /// Determine whether a block exists in the database.
    pub fn block_exists(&self, block_root: &Hash256) -> Result<bool, Error> {
        self.hot_db
            .key_exists(DBColumn::BeaconBlock.into(), block_root.as_bytes())
    }

    /// Delete a block from the store and the block cache.
    pub fn delete_block(&self, block_root: &Hash256) -> Result<(), Error> {
        self.block_cache.lock().delete(block_root);
        self.hot_db
            .key_delete(DBColumn::BeaconBlock.into(), block_root.as_bytes())?;
        self.hot_db
            .key_delete(DBColumn::ExecPayload.into(), block_root.as_bytes())?;
        self.blobs_db
            .key_delete(DBColumn::BeaconBlob.into(), block_root.as_bytes())
    }

    pub fn put_blobs(&self, block_root: &Hash256, blobs: BlobSidecarList<E>) -> Result<(), Error> {
        self.blobs_db.put_bytes(
            DBColumn::BeaconBlob.into(),
            block_root.as_bytes(),
            &blobs.as_ssz_bytes(),
        )?;
        self.block_cache.lock().put_blobs(*block_root, blobs);
        Ok(())
    }

    pub fn blobs_as_kv_store_ops(
        &self,
        key: &Hash256,
        blobs: BlobSidecarList<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) {
        let db_key = get_key_for_col(DBColumn::BeaconBlob.into(), key.as_bytes());
        ops.push(KeyValueStoreOp::PutKeyValue(db_key, blobs.as_ssz_bytes()));
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
        self.put_state_possibly_temporary(state_root, state, false)
    }

    /// Store a state in the store.
    ///
    /// The `temporary` flag indicates whether this state should be considered canonical.
    pub fn put_state_possibly_temporary(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
        temporary: bool,
    ) -> Result<(), Error> {
        let mut ops: Vec<KeyValueStoreOp> = Vec::new();
        if state.slot() < self.get_split_slot() {
            self.store_cold_state(state_root, state, &mut ops)?;
            self.cold_db.do_atomically(ops)
        } else {
            if temporary {
                ops.push(TemporaryFlag.as_kv_store_op(*state_root));
            }
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

    /// Get a state with `latest_block_root == block_root` advanced through to at most `max_slot`.
    ///
    /// The `state_root` argument is used to look up the block's un-advanced state in case an
    /// advanced state is not found.
    ///
    /// Return the `(result_state_root, state)` satisfying:
    ///
    /// - `result_state_root == state.canonical_root()`
    /// - `state.slot() <= max_slot`
    /// - `state.get_latest_block_root(result_state_root) == block_root`
    pub fn get_advanced_hot_state(
        &self,
        block_root: Hash256,
        max_slot: Slot,
        state_root: Hash256,
    ) -> Result<Option<(Hash256, BeaconState<E>)>, Error> {
        if let Some(cached) = self.get_advanced_hot_state_from_cache(block_root, max_slot) {
            return Ok(Some(cached));
        }

        // Hold a read lock on the split point so it can't move while we're trying to load the
        // state.
        let split = self.split.read_recursive();

        if state_root != split.state_root {
            warn!(
                self.log,
                "State cache missed";
                "state_root"  => ?state_root,
                "block_root" => ?block_root,
            );
        }

        // Sanity check max-slot against the split slot.
        if max_slot < split.slot {
            return Err(HotColdDBError::FinalizedStateNotInHotDatabase {
                split_slot: split.slot,
                request_slot: max_slot,
                block_root,
            }
            .into());
        }

        let state_root = if block_root == split.block_root && split.slot <= max_slot {
            split.state_root
        } else {
            state_root
        };
        let mut opt_state = self
            .load_hot_state(&state_root)?
            .map(|(state, _block_root)| (state_root, state));

        if let Some((state_root, state)) = opt_state.as_mut() {
            state.update_tree_hash_cache()?;
            state.build_all_caches(&self.spec)?;
            self.state_cache
                .lock()
                .put_state(*state_root, block_root, state)?;
            debug!(
                self.log,
                "Cached state";
                "state_root" => ?state_root,
                "slot" => state.slot(),
            );
        }
        drop(split);
        Ok(opt_state)
    }

    /// Same as `get_advanced_hot_state` but will return `None` if no compatible state is cached.
    ///
    /// If this function returns `Some(state)` then that `state` will always have
    /// `latest_block_header` matching `block_root` but may not be advanced all the way through to
    /// `max_slot`.
    pub fn get_advanced_hot_state_from_cache(
        &self,
        block_root: Hash256,
        max_slot: Slot,
    ) -> Option<(Hash256, BeaconState<E>)> {
        self.state_cache
            .lock()
            .get_by_block_root(block_root, max_slot)
    }

    /// Delete a state, ensuring it is removed from the LRU cache, as well as from on-disk.
    ///
    /// It is assumed that all states being deleted reside in the hot DB, even if their slot is less
    /// than the split point. You shouldn't delete states from the finalized portion of the chain
    /// (which are frozen, and won't be deleted), or valid descendents of the finalized checkpoint
    /// (which will be deleted by this function but shouldn't be).
    pub fn delete_state(&self, state_root: &Hash256, slot: Slot) -> Result<(), Error> {
        self.do_atomically_with_block_and_blobs_cache(vec![StoreOp::DeleteState(
            *state_root,
            Some(slot),
        )])
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
            || Ok((end_state, end_block_root)),
            spec,
        )
    }

    pub fn forwards_block_roots_iterator_until(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        get_state: impl FnOnce() -> Result<(BeaconState<E>, Hash256), Error>,
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
            || Ok((end_state, end_state_root)),
            spec,
        )
    }

    pub fn forwards_state_roots_iterator_until(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        get_state: impl FnOnce() -> Result<(BeaconState<E>, Hash256), Error>,
        spec: &ChainSpec,
    ) -> Result<HybridForwardsStateRootsIterator<E, Hot, Cold>, Error> {
        HybridForwardsStateRootsIterator::new(self, start_slot, Some(end_slot), get_state, spec)
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
            let (state, _) = self.load_hot_state(&epoch_boundary_state_root)?.ok_or(
                HotColdDBError::MissingEpochBoundaryState(epoch_boundary_state_root),
            )?;
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

                StoreOp::PutBlobs(block_root, blobs) => {
                    self.blobs_as_kv_store_ops(&block_root, blobs, &mut key_value_batch);
                }

                StoreOp::PutStateSummary(state_root, summary) => {
                    key_value_batch.push(summary.as_kv_store_op(state_root));
                }

                StoreOp::PutStateTemporaryFlag(state_root) => {
                    key_value_batch.push(TemporaryFlag.as_kv_store_op(state_root));
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

                StoreOp::DeleteBlobs(block_root) => {
                    let key = get_key_for_col(DBColumn::BeaconBlob.into(), block_root.as_bytes());
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

                StoreOp::DeleteExecutionPayload(block_root) => {
                    let key = get_key_for_col(DBColumn::ExecPayload.into(), block_root.as_bytes());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(key));
                }

                StoreOp::KeyValueOp(kv_op) => {
                    key_value_batch.push(kv_op);
                }
            }
        }
        Ok(key_value_batch)
    }

    pub fn do_atomically_with_block_and_blobs_cache(
        &self,
        batch: Vec<StoreOp<E>>,
    ) -> Result<(), Error> {
        let mut blobs_to_delete = Vec::new();
        let (blobs_ops, hot_db_ops): (Vec<StoreOp<E>>, Vec<StoreOp<E>>) =
            batch.into_iter().partition(|store_op| match store_op {
                StoreOp::PutBlobs(_, _) => true,
                StoreOp::DeleteBlobs(block_root) => {
                    match self.get_blobs(block_root) {
                        Ok(Some(blob_sidecar_list)) => {
                            blobs_to_delete.push((*block_root, blob_sidecar_list));
                        }
                        Err(e) => {
                            error!(
                                self.log, "Error getting blobs";
                                "block_root" => %block_root,
                                "error" => ?e
                            );
                        }
                        _ => (),
                    }
                    true
                }
                StoreOp::PutBlock(_, _) | StoreOp::DeleteBlock(_) => false,
                _ => false,
            });

        // Update database whilst holding a lock on cache, to ensure that the cache updates
        // atomically with the database.
        let mut guard = self.block_cache.lock();

        let blob_cache_ops = blobs_ops.clone();
        // Try to execute blobs store ops.
        self.blobs_db
            .do_atomically(self.convert_to_kv_batch(blobs_ops)?)?;

        let hot_db_cache_ops = hot_db_ops.clone();
        // Try to execute hot db store ops.
        let tx_res = match self.convert_to_kv_batch(hot_db_ops) {
            Ok(kv_store_ops) => self.hot_db.do_atomically(kv_store_ops),
            Err(e) => Err(e),
        };
        // Rollback on failure
        if let Err(e) = tx_res {
            error!(
                self.log,
                "Database write failed";
                "error" => ?e,
                "action" => "reverting blob DB changes"
            );
            let mut blob_cache_ops = blob_cache_ops;
            for op in blob_cache_ops.iter_mut() {
                let reverse_op = match op {
                    StoreOp::PutBlobs(block_root, _) => StoreOp::DeleteBlobs(*block_root),
                    StoreOp::DeleteBlobs(_) => match blobs_to_delete.pop() {
                        Some((block_root, blobs)) => StoreOp::PutBlobs(block_root, blobs),
                        None => return Err(HotColdDBError::Rollback.into()),
                    },
                    _ => return Err(HotColdDBError::Rollback.into()),
                };
                *op = reverse_op;
            }
            self.blobs_db
                .do_atomically(self.convert_to_kv_batch(blob_cache_ops)?)?;
            return Err(e);
        }

        for op in hot_db_cache_ops {
            match op {
                StoreOp::PutBlock(block_root, block) => {
                    guard.put_block(block_root, (*block).clone());
                }

                StoreOp::PutBlobs(_, _) => (),

                StoreOp::PutState(_, _) => (),

                StoreOp::PutStateSummary(_, _) => (),

                StoreOp::PutStateTemporaryFlag(_) => (),

                StoreOp::DeleteStateTemporaryFlag(_) => (),

                StoreOp::DeleteBlock(block_root) => {
                    guard.delete_block(&block_root);
                    self.state_cache.lock().delete_block_states(&block_root);
                }

                StoreOp::DeleteState(state_root, _) => {
                    self.state_cache.lock().delete_state(&state_root)
                }

                StoreOp::DeleteBlobs(_) => (),

                StoreOp::DeleteExecutionPayload(_) => (),

                StoreOp::KeyValueOp(_) => (),
            }
        }

        for op in blob_cache_ops {
            match op {
                StoreOp::PutBlobs(block_root, blobs) => {
                    guard.put_blobs(block_root, blobs);
                }

                StoreOp::DeleteBlobs(block_root) => {
                    guard.delete_blobs(&block_root);
                }

                _ => (),
            }
        }

        drop(guard);

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
        let block_root = state.get_latest_block_root(*state_root);

        // Avoid storing states in the database if they already exist in the state cache.
        // The exception to this is the finalized state, which must exist in the cache before it
        // is stored on disk.
        if let PutStateOutcome::Duplicate =
            self.state_cache
                .lock()
                .put_state(*state_root, block_root, state)?
        {
            debug!(
                self.log,
                "Skipping storage of cached state";
                "slot" => state.slot(),
                "state_root" => ?state_root
            );
            return Ok(());
        }

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

    /// Get a post-finalization state from the database or store.
    pub fn get_hot_state(&self, state_root: &Hash256) -> Result<Option<BeaconState<E>>, Error> {
        if let Some(state) = self.state_cache.lock().get_by_state_root(*state_root) {
            return Ok(Some(state));
        }

        if *state_root != self.get_split_info().state_root {
            // Do not warn on start up when loading the split state.
            warn!(
                self.log,
                "State cache missed";
                "state_root" => ?state_root,
            );
        }

        let state_from_disk = self.load_hot_state(state_root)?;

        if let Some((mut state, block_root)) = state_from_disk {
            state.update_tree_hash_cache()?;
            state.build_all_caches(&self.spec)?;
            self.state_cache
                .lock()
                .put_state(*state_root, block_root, &state)?;
            debug!(
                self.log,
                "Cached state";
                "state_root" => ?state_root,
                "slot" => state.slot(),
            );
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    /// Load a post-finalization state from the hot database.
    ///
    /// Will replay blocks from the nearest epoch boundary.
    ///
    /// Return the `(state, latest_block_root)` where `latest_block_root` is the root of the last
    /// block applied to `state`.
    pub fn load_hot_state(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<(BeaconState<E>, Hash256)>, Error> {
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
            let mut boundary_state =
                get_full_state(&self.hot_db, &epoch_boundary_state_root, &self.spec)?.ok_or(
                    HotColdDBError::MissingEpochBoundaryState(epoch_boundary_state_root),
                )?;

            // Immediately rebase the state from disk on the finalized state so that we can reuse
            // parts of the tree for state root calculation in `replay_blocks`.
            self.state_cache
                .lock()
                .rebase_on_finalized(&mut boundary_state, &self.spec)?;

            // Optimization to avoid even *thinking* about replaying blocks if we're already
            // on an epoch boundary.
            let mut state = if slot % E::slots_per_epoch() == 0 {
                boundary_state
            } else {
                // Cache ALL intermediate states that are reached during block replay. We may want
                // to restrict this in future to only cache epoch boundary states. At worst we will
                // cache up to 32 states for each state loaded, which should not flush out the cache
                // entirely.
                let state_cache_hook = |state_root, state: &mut BeaconState<E>| {
                    // Ensure all caches are built before attempting to cache.
                    state.update_tree_hash_cache()?;
                    state.build_all_caches(&self.spec)?;

                    let latest_block_root = state.get_latest_block_root(state_root);
                    let state_slot = state.slot();
                    if let PutStateOutcome::New =
                        self.state_cache
                            .lock()
                            .put_state(state_root, latest_block_root, state)?
                    {
                        debug!(
                            self.log,
                            "Cached ancestor state";
                            "state_root" => ?state_root,
                            "slot" => state_slot,
                        );
                    }
                    Ok(())
                };
                let blocks =
                    self.load_blocks_to_replay(boundary_state.slot(), slot, latest_block_root)?;
                self.replay_blocks(
                    boundary_state,
                    blocks,
                    slot,
                    no_state_root_iter(),
                    Some(Box::new(state_cache_hook)),
                )?
            };
            state.apply_pending_mutations()?;

            Ok(Some((state, latest_block_root)))
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
        // Block roots need to be written here as well as by the `ChunkWriter` in `migrate_db`
        // because states may require older block roots, and the writer only stores block roots
        // between the previous split point and the new split point.
        let db = &self.cold_db;
        store_updated_vector(BlockRoots, db, state, &self.spec, ops)?;
        store_updated_vector(StateRoots, db, state, &self.spec, ops)?;
        store_updated_vector(HistoricalRoots, db, state, &self.spec, ops)?;
        store_updated_vector(RandaoMixes, db, state, &self.spec, ops)?;
        store_updated_vector(HistoricalSummaries, db, state, &self.spec, ops)?;

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
            .ok_or(HotColdDBError::MissingRestorePoint(*state_root))?;
        let mut partial_state: PartialBeaconState<E> =
            PartialBeaconState::from_ssz_bytes(&partial_state_bytes, &self.spec)?;

        // Fill in the fields of the partial state.
        partial_state.load_block_roots(&self.cold_db, &self.spec)?;
        partial_state.load_state_roots(&self.cold_db, &self.spec)?;
        partial_state.load_historical_roots(&self.cold_db, &self.spec)?;
        partial_state.load_randao_mixes(&self.cold_db, &self.spec)?;
        partial_state.load_historical_summaries(&self.cold_db, &self.spec)?;

        let mut state: BeaconState<E> = partial_state.try_into()?;
        state.apply_pending_mutations()?;
        Ok(state)
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
        if let Some(state) = self.historic_state_cache.lock().get(&slot) {
            return Ok(state.clone());
        }

        // 1. Load the restore points either side of the intermediate state.
        let low_restore_point_idx = slot.as_u64() / self.config.slots_per_restore_point;
        let high_restore_point_idx = low_restore_point_idx + 1;

        // Use low restore point as the base state.
        let mut low_slot: Slot =
            Slot::new(low_restore_point_idx * self.config.slots_per_restore_point);
        let mut low_state: Option<BeaconState<E>> = None;

        // Try to get a more recent state from the cache to avoid massive blocks replay.
        for (s, state) in self.historic_state_cache.lock().iter() {
            if s.as_u64() / self.config.slots_per_restore_point == low_restore_point_idx
                && *s < slot
                && low_slot < *s
            {
                low_slot = *s;
                low_state = Some(state.clone());
            }
        }

        // If low_state is still None, use load_restore_point_by_index to load the state.
        let low_state = match low_state {
            Some(state) => state,
            None => self.load_restore_point_by_index(low_restore_point_idx)?,
        };

        // Acquire the read lock, so that the split can't change while this is happening.
        let split = self.split.read_recursive();

        let high_restore_point = self.get_restore_point(high_restore_point_idx, &split)?;

        // 2. Load the blocks from the high restore point back to the low point.
        let blocks = self.load_blocks_to_replay(
            low_slot,
            slot,
            self.get_high_restore_point_block_root(&high_restore_point, slot)?,
        )?;

        // 3. Replay the blocks on top of the low point.
        // Use a forwards state root iterator to avoid doing any tree hashing.
        // The state root of the high restore point should never be used, so is safely set to 0.
        let state_root_iter = self.forwards_state_roots_iterator_until(
            low_slot,
            slot,
            || Ok((high_restore_point, Hash256::zero())),
            &self.spec,
        )?;

        let mut state = self.replay_blocks(low_state, blocks, slot, Some(state_root_iter), None)?;
        state.apply_pending_mutations()?;

        // If state is not error, put it in the cache.
        self.historic_state_cache.lock().put(slot, state.clone());

        Ok(state)
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
            .copied()
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
        state_root_iter: Option<impl Iterator<Item = Result<(Hash256, Slot), Error>>>,
        pre_slot_hook: Option<PreSlotHook<E, Error>>,
    ) -> Result<BeaconState<E>, Error> {
        let mut block_replayer = BlockReplayer::new(state, &self.spec)
            .no_signature_verification()
            .minimal_block_root_verification();

        let have_state_root_iterator = state_root_iter.is_some();
        if let Some(state_root_iter) = state_root_iter {
            block_replayer = block_replayer.state_root_iter(state_root_iter);
        }

        if let Some(pre_slot_hook) = pre_slot_hook {
            block_replayer = block_replayer.pre_slot_hook(pre_slot_hook);
        }

        block_replayer
            .apply_blocks(blocks, Some(target_slot))
            .map(|block_replayer| {
                if have_state_root_iterator && block_replayer.state_root_miss() {
                    warn!(
                        self.log,
                        "State root cache miss during block replay";
                        "slot" => target_slot,
                    );
                }
                block_replayer.into_state()
            })
    }

    /// Fetch blobs for a given block from the store.
    pub fn get_blobs(&self, block_root: &Hash256) -> Result<Option<BlobSidecarList<E>>, Error> {
        // Check the cache.
        if let Some(blobs) = self.block_cache.lock().get_blobs(block_root) {
            metrics::inc_counter(&metrics::BEACON_BLOBS_CACHE_HIT_COUNT);
            return Ok(Some(blobs.clone()));
        }

        match self
            .blobs_db
            .get_bytes(DBColumn::BeaconBlob.into(), block_root.as_bytes())?
        {
            Some(ref blobs_bytes) => {
                let blobs = BlobSidecarList::from_ssz_bytes(blobs_bytes)?;
                self.block_cache
                    .lock()
                    .put_blobs(*block_root, blobs.clone());
                Ok(Some(blobs))
            }
            None => Ok(None),
        }
    }

    /// Get a reference to the `ChainSpec` used by the database.
    pub fn get_chain_spec(&self) -> &ChainSpec {
        &self.spec
    }

    /// Get a reference to the `Logger` used by the database.
    pub fn logger(&self) -> &Logger {
        &self.log
    }

    /// Fetch a copy of the current split slot from memory.
    pub fn get_split_slot(&self) -> Slot {
        self.split.read_recursive().slot
    }

    /// Fetch a copy of the current split slot from memory.
    pub fn get_split_info(&self) -> Split {
        *self.split.read_recursive()
    }

    pub fn set_split(&self, slot: Slot, state_root: Hash256, block_root: Hash256) {
        *self.split.write() = Split {
            slot,
            state_root,
            block_root,
        };
    }

    /// Fetch the slot of the most recently stored restore point (if any).
    pub fn get_latest_restore_point_slot(&self) -> Option<Slot> {
        let split_slot = self.get_split_slot();
        let anchor = self.get_anchor_info();

        // There are no restore points stored if the state upper limit lies in the hot database,
        // and the lower limit is zero. It hasn't been reached yet, and may never be.
        if anchor.as_ref().map_or(false, |a| {
            a.state_upper_limit >= split_slot && a.state_lower_limit == 0
        }) {
            None
        } else if let Some(lower_limit) = anchor
            .map(|a| a.state_lower_limit)
            .filter(|limit| *limit > 0)
        {
            Some(lower_limit)
        } else {
            Some(
                (split_slot - 1) / self.config.slots_per_restore_point
                    * self.config.slots_per_restore_point,
            )
        }
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
        let op = KeyValueStoreOp::PutKeyValue(db_key, schema_version.as_store_bytes());
        ops.push(op);

        self.hot_db.do_atomically(ops)
    }

    /// Initialise the anchor info for checkpoint sync starting from `block`.
    pub fn init_anchor_info(
        &self,
        block: BeaconBlockRef<'_, E>,
        retain_historic_states: bool,
    ) -> Result<KeyValueStoreOp, Error> {
        let anchor_slot = block.slot();
        let slots_per_restore_point = self.config.slots_per_restore_point;

        let state_upper_limit = if !retain_historic_states {
            STATE_UPPER_LIMIT_NO_RETAIN
        } else if anchor_slot % slots_per_restore_point == 0 {
            anchor_slot
        } else {
            // Set the `state_upper_limit` to the slot of the *next* restore point.
            // See `get_state_upper_limit` for rationale.
            (anchor_slot / slots_per_restore_point + 1) * slots_per_restore_point
        };
        let anchor_info = if state_upper_limit == 0 && anchor_slot == 0 {
            // Genesis archive node: no anchor because we *will* store all states.
            None
        } else {
            Some(AnchorInfo {
                anchor_slot,
                oldest_block_slot: anchor_slot,
                oldest_block_parent: block.parent_root(),
                state_upper_limit,
                state_lower_limit: self.spec.genesis_slot,
            })
        };
        self.compare_and_set_anchor_info(None, anchor_info)
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

    /// Initialize the `BlobInfo` when starting from genesis or a checkpoint.
    pub fn init_blob_info(&self, anchor_slot: Slot) -> Result<KeyValueStoreOp, Error> {
        let oldest_blob_slot = self.spec.deneb_fork_epoch.map(|fork_epoch| {
            std::cmp::max(anchor_slot, fork_epoch.start_slot(E::slots_per_epoch()))
        });
        let blob_info = BlobInfo {
            oldest_blob_slot,
            blobs_db: true,
        };
        self.compare_and_set_blob_info(self.get_blob_info(), blob_info)
    }

    /// Get a clone of the store's blob info.
    ///
    /// To do mutations, use `compare_and_set_blob_info`.
    pub fn get_blob_info(&self) -> BlobInfo {
        self.blob_info.read_recursive().clone()
    }

    /// Atomically update the blob info from `prev_value` to `new_value`.
    ///
    /// Return a `KeyValueStoreOp` which should be written to disk, possibly atomically with other
    /// values.
    ///
    /// Return an `BlobInfoConcurrentMutation` error if the `prev_value` provided
    /// is not correct.
    pub fn compare_and_set_blob_info(
        &self,
        prev_value: BlobInfo,
        new_value: BlobInfo,
    ) -> Result<KeyValueStoreOp, Error> {
        let mut blob_info = self.blob_info.write();
        if *blob_info == prev_value {
            let kv_op = self.store_blob_info_in_batch(&new_value);
            *blob_info = new_value;
            Ok(kv_op)
        } else {
            Err(Error::BlobInfoConcurrentMutation)
        }
    }

    /// As for `compare_and_set_blob_info`, but also writes the blob info to disk immediately.
    pub fn compare_and_set_blob_info_with_write(
        &self,
        prev_value: BlobInfo,
        new_value: BlobInfo,
    ) -> Result<(), Error> {
        let kv_store_op = self.compare_and_set_blob_info(prev_value, new_value)?;
        self.hot_db.do_atomically(vec![kv_store_op])
    }

    /// Load the blob info from disk, but do not set `self.blob_info`.
    fn load_blob_info(&self) -> Result<Option<BlobInfo>, Error> {
        self.hot_db.get(&BLOB_INFO_KEY)
    }

    /// Store the given `blob_info` to disk.
    ///
    /// The argument is intended to be `self.blob_info`, but is passed manually to avoid issues
    /// with recursive locking.
    fn store_blob_info_in_batch(&self, blob_info: &BlobInfo) -> KeyValueStoreOp {
        blob_info.as_kv_store_op(BLOB_INFO_KEY)
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

    /// Load the split point from disk, sans block root.
    fn load_split_partial(&self) -> Result<Option<Split>, Error> {
        self.hot_db.get(&SPLIT_KEY)
    }

    /// Load the split point from disk, including block root.
    fn load_split(&self) -> Result<Option<Split>, Error> {
        match self.load_split_partial()? {
            Some(mut split) => {
                // Load the hot state summary to get the block root.
                let summary = self.load_hot_state_summary(&split.state_root)?.ok_or(
                    HotColdDBError::MissingSplitState(split.state_root, split.slot),
                )?;
                split.block_root = summary.latest_block_root;
                Ok(Some(split))
            }
            None => Ok(None),
        }
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

    /// Verify that a parsed config is valid.
    fn verify_config(config: &StoreConfig) -> Result<(), HotColdDBError> {
        Self::verify_slots_per_restore_point(config.slots_per_restore_point)?;
        Self::verify_epochs_per_blob_prune(config.epochs_per_blob_prune)
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

    // Check that epochs_per_blob_prune is at least 1 epoch to avoid attempting to prune the same
    // epochs over and over again.
    fn verify_epochs_per_blob_prune(epochs_per_blob_prune: u64) -> Result<(), HotColdDBError> {
        if epochs_per_blob_prune > 0 {
            Ok(())
        } else {
            Err(HotColdDBError::ZeroEpochsPerBlobPrune)
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

    /// Update the linear array of frozen block roots with the block root for several skipped slots.
    ///
    /// Write the block root at all slots from `start_slot` (inclusive) to `end_slot` (exclusive).
    pub fn store_frozen_block_root_at_skip_slots(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        block_root: Hash256,
    ) -> Result<Vec<KeyValueStoreOp>, Error> {
        let mut ops = vec![];
        let mut block_root_writer =
            ChunkWriter::<BlockRoots, _, _>::new(&self.cold_db, start_slot.as_usize())?;
        for slot in start_slot.as_usize()..end_slot.as_usize() {
            block_root_writer.set(slot, block_root, &mut ops)?;
        }
        block_root_writer.write(&mut ops)?;
        Ok(ops)
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
        self.do_atomically_with_block_and_blobs_cache(ops)?;
        info!(
            self.log,
            "Execution payload pruning complete";
            "payloads_pruned" => payloads_pruned,
        );
        Ok(())
    }

    /// Try to prune blobs, approximating the current epoch from the split slot.
    pub fn try_prune_most_blobs(&self, force: bool) -> Result<(), Error> {
        let Some(deneb_fork_epoch) = self.spec.deneb_fork_epoch else {
            debug!(self.log, "Deneb fork is disabled");
            return Ok(());
        };
        // The current epoch is >= split_epoch + 2. It could be greater if the database is
        // configured to delay updating the split or finalization has ceased. In this instance we
        // choose to also delay the pruning of blobs (we never prune without finalization anyway).
        let min_current_epoch = self.get_split_slot().epoch(E::slots_per_epoch()) + 2;
        let min_data_availability_boundary = std::cmp::max(
            deneb_fork_epoch,
            min_current_epoch.saturating_sub(self.spec.min_epochs_for_blob_sidecars_requests),
        );

        self.try_prune_blobs(force, min_data_availability_boundary)
    }

    /// Try to prune blobs older than the data availability boundary.
    ///
    /// Blobs from the epoch `data_availability_boundary - blob_prune_margin_epochs` are retained.
    /// This epoch is an _exclusive_ endpoint for the pruning process.
    ///
    /// This function only supports pruning blobs older than the split point, which is older than
    /// (or equal to) finalization. Pruning blobs newer than finalization is not supported.
    ///
    /// This function also assumes that the split is stationary while it runs. It should only be
    /// run from the migrator thread (where `migrate_database` runs) or the database manager.
    pub fn try_prune_blobs(
        &self,
        force: bool,
        data_availability_boundary: Epoch,
    ) -> Result<(), Error> {
        if self.spec.deneb_fork_epoch.is_none() {
            debug!(self.log, "Deneb fork is disabled");
            return Ok(());
        }

        let pruning_enabled = self.get_config().prune_blobs;
        let margin_epochs = self.get_config().blob_prune_margin_epochs;
        let epochs_per_blob_prune = self.get_config().epochs_per_blob_prune;

        if !force && !pruning_enabled {
            debug!(
                self.log,
                "Blob pruning is disabled";
                "prune_blobs" => pruning_enabled
            );
            return Ok(());
        }

        let blob_info = self.get_blob_info();
        let Some(oldest_blob_slot) = blob_info.oldest_blob_slot else {
            error!(self.log, "Slot of oldest blob is not known");
            return Err(HotColdDBError::BlobPruneLogicError.into());
        };

        // Start pruning from the epoch of the oldest blob stored.
        // The start epoch is inclusive (blobs in this epoch will be pruned).
        let start_epoch = oldest_blob_slot.epoch(E::slots_per_epoch());

        // Prune blobs up until the `data_availability_boundary - margin` or the split
        // slot's epoch, whichever is older. We can't prune blobs newer than the split.
        // The end epoch is also inclusive (blobs in this epoch will be pruned).
        let split = self.get_split_info();
        let end_epoch = std::cmp::min(
            data_availability_boundary - margin_epochs - 1,
            split.slot.epoch(E::slots_per_epoch()) - 1,
        );
        let end_slot = end_epoch.end_slot(E::slots_per_epoch());

        let can_prune = end_epoch != 0 && start_epoch <= end_epoch;
        let should_prune = start_epoch + epochs_per_blob_prune <= end_epoch + 1;

        if !force && !should_prune || !can_prune {
            debug!(
                self.log,
                "Blobs are pruned";
                "oldest_blob_slot" => oldest_blob_slot,
                "data_availability_boundary" => data_availability_boundary,
                "split_slot" => split.slot,
                "end_epoch" => end_epoch,
                "start_epoch" => start_epoch,
            );
            return Ok(());
        }

        // Sanity checks.
        if let Some(anchor) = self.get_anchor_info() {
            if oldest_blob_slot < anchor.oldest_block_slot {
                error!(
                    self.log,
                    "Oldest blob is older than oldest block";
                    "oldest_blob_slot" => oldest_blob_slot,
                    "oldest_block_slot" => anchor.oldest_block_slot
                );
                return Err(HotColdDBError::BlobPruneLogicError.into());
            }
        }

        // Iterate block roots forwards from the oldest blob slot.
        debug!(
            self.log,
            "Pruning blobs";
            "start_epoch" => start_epoch,
            "end_epoch" => end_epoch,
            "data_availability_boundary" => data_availability_boundary,
        );

        let mut ops = vec![];
        let mut last_pruned_block_root = None;

        for res in self.forwards_block_roots_iterator_until(
            oldest_blob_slot,
            end_slot,
            || {
                let (_, split_state) = self
                    .get_advanced_hot_state(split.block_root, split.slot, split.state_root)?
                    .ok_or(HotColdDBError::MissingSplitState(
                        split.state_root,
                        split.slot,
                    ))?;

                Ok((split_state, split.block_root))
            },
            &self.spec,
        )? {
            let (block_root, slot) = match res {
                Ok(tuple) => tuple,
                Err(e) => {
                    warn!(
                        self.log,
                        "Stopping blob pruning early";
                        "error" => ?e,
                    );
                    break;
                }
            };

            if Some(block_root) != last_pruned_block_root && self.blobs_exist(&block_root)? {
                trace!(
                    self.log,
                    "Pruning blobs of block";
                    "slot" => slot,
                    "block_root" => ?block_root,
                );
                last_pruned_block_root = Some(block_root);
                ops.push(StoreOp::DeleteBlobs(block_root));
            }

            if slot >= end_slot {
                break;
            }
        }
        let blob_lists_pruned = ops.len();
        let new_blob_info = BlobInfo {
            oldest_blob_slot: Some(end_slot + 1),
            blobs_db: blob_info.blobs_db,
        };
        let update_blob_info = self.compare_and_set_blob_info(blob_info, new_blob_info)?;
        ops.push(StoreOp::KeyValueOp(update_blob_info));

        self.do_atomically_with_block_and_blobs_cache(ops)?;
        debug!(
            self.log,
            "Blob pruning complete";
            "blob_lists_pruned" => blob_lists_pruned,
        );

        Ok(())
    }

    /// This function fills in missing block roots between last restore point slot and split
    /// slot, if any.
    pub fn heal_freezer_block_roots_at_split(&self) -> Result<(), Error> {
        let split = self.get_split_info();
        let last_restore_point_slot = (split.slot - 1) / self.config.slots_per_restore_point
            * self.config.slots_per_restore_point;

        // Load split state (which has access to block roots).
        let (_, split_state) = self
            .get_advanced_hot_state(split.block_root, split.slot, split.state_root)?
            .ok_or(HotColdDBError::MissingSplitState(
                split.state_root,
                split.slot,
            ))?;

        let mut batch = vec![];
        let mut chunk_writer = ChunkWriter::<BlockRoots, _, _>::new(
            &self.cold_db,
            last_restore_point_slot.as_usize(),
        )?;

        for slot in (last_restore_point_slot.as_u64()..split.slot.as_u64()).map(Slot::new) {
            let block_root = *split_state.get_block_root(slot)?;
            chunk_writer.set(slot.as_usize(), block_root, &mut batch)?;
        }
        chunk_writer.write(&mut batch)?;
        self.cold_db.do_atomically(batch)?;

        Ok(())
    }

    pub fn heal_freezer_block_roots_at_genesis(&self) -> Result<(), Error> {
        let oldest_block_slot = self.get_oldest_block_slot();
        let split_slot = self.get_split_slot();

        // Check if backfill has been completed AND the freezer db has data in it
        if oldest_block_slot != 0 || split_slot == 0 {
            return Ok(());
        }

        let mut block_root_iter = self.forwards_block_roots_iterator_until(
            Slot::new(0),
            split_slot - 1,
            || {
                Err(Error::DBError {
                    message: "Should not require end state".to_string(),
                })
            },
            &self.spec,
        )?;

        let (genesis_block_root, _) = block_root_iter.next().ok_or_else(|| Error::DBError {
            message: "Genesis block root missing".to_string(),
        })??;

        let slots_to_fix = itertools::process_results(block_root_iter, |iter| {
            iter.take_while(|(block_root, _)| block_root.is_zero())
                .map(|(_, slot)| slot)
                .collect::<Vec<_>>()
        })?;

        let Some(first_slot) = slots_to_fix.first() else {
            return Ok(());
        };

        let mut chunk_writer =
            ChunkWriter::<BlockRoots, _, _>::new(&self.cold_db, first_slot.as_usize())?;
        let mut ops = vec![];
        for slot in slots_to_fix {
            chunk_writer.set(slot.as_usize(), genesis_block_root, &mut ops)?;
        }

        chunk_writer.write(&mut ops)?;
        self.cold_db.do_atomically(ops)?;

        Ok(())
    }

    /// Delete *all* states from the freezer database and update the anchor accordingly.
    ///
    /// WARNING: this method deletes the genesis state and replaces it with the provided
    /// `genesis_state`. This is to support its use in schema migrations where the storage scheme of
    /// the genesis state may be modified. It is the responsibility of the caller to ensure that the
    /// genesis state is correct, else a corrupt database will be created.
    pub fn prune_historic_states(
        &self,
        genesis_state_root: Hash256,
        genesis_state: &BeaconState<E>,
    ) -> Result<(), Error> {
        // Make sure there is no missing block roots before pruning
        self.heal_freezer_block_roots_at_split()?;

        // Update the anchor to use the dummy state upper limit and disable historic state storage.
        let old_anchor = self.get_anchor_info();
        let new_anchor = if let Some(old_anchor) = old_anchor.clone() {
            AnchorInfo {
                state_upper_limit: STATE_UPPER_LIMIT_NO_RETAIN,
                state_lower_limit: Slot::new(0),
                ..old_anchor.clone()
            }
        } else {
            AnchorInfo {
                anchor_slot: Slot::new(0),
                oldest_block_slot: Slot::new(0),
                oldest_block_parent: Hash256::zero(),
                state_upper_limit: STATE_UPPER_LIMIT_NO_RETAIN,
                state_lower_limit: Slot::new(0),
            }
        };

        // Commit the anchor change immediately: if the cold database ops fail they can always be
        // retried, and we can't do them atomically with this change anyway.
        self.compare_and_set_anchor_info_with_write(old_anchor, Some(new_anchor))?;

        // Stage freezer data for deletion. Do not bother loading and deserializing values as this
        // wastes time and is less schema-agnostic. My hope is that this method will be useful for
        // migrating to the tree-states schema (delete everything in the freezer then start afresh).
        let mut cold_ops = vec![];

        let columns = [
            DBColumn::BeaconState,
            DBColumn::BeaconStateSummary,
            DBColumn::BeaconRestorePoint,
            DBColumn::BeaconStateRoots,
            DBColumn::BeaconHistoricalRoots,
            DBColumn::BeaconRandaoMixes,
            DBColumn::BeaconHistoricalSummaries,
        ];

        for column in columns {
            for res in self.cold_db.iter_column_keys::<Vec<u8>>(column) {
                let key = res?;
                cold_ops.push(KeyValueStoreOp::DeleteKey(get_key_for_col(
                    column.as_str(),
                    &key,
                )));
            }
        }

        // XXX: We need to commit the mass deletion here *before* re-storing the genesis state, as
        // the current schema performs reads as part of `store_cold_state`. This can be deleted
        // once the target schema is tree-states. If the process is killed before the genesis state
        // is written this can be fixed by re-running.
        info!(
            self.log,
            "Deleting historic states";
            "num_kv" => cold_ops.len(),
        );
        self.cold_db.do_atomically(std::mem::take(&mut cold_ops))?;

        // If we just deleted the the genesis state, re-store it using the *current* schema, which
        // may be different from the schema of the genesis state we just deleted.
        if self.get_split_slot() > 0 {
            info!(
                self.log,
                "Re-storing genesis state";
                "state_root" => ?genesis_state_root,
            );
            self.store_cold_state(&genesis_state_root, genesis_state, &mut cold_ops)?;
            self.cold_db.do_atomically(cold_ops)?;
        }

        // In order to reclaim space, we need to compact the freezer DB as well.
        self.cold_db.compact()?;

        Ok(())
    }

    /// Prune states from the hot database which are prior to the split.
    ///
    /// This routine is important for cleaning up advanced states which are stored in the database
    /// with a temporary flag.
    pub fn prune_old_hot_states(&self) -> Result<(), Error> {
        let split = self.get_split_info();
        debug!(
            self.log,
            "Database state pruning started";
            "split_slot" => split.slot,
        );
        let mut state_delete_batch = vec![];
        for res in self
            .hot_db
            .iter_column::<Hash256>(DBColumn::BeaconStateSummary)
        {
            let (state_root, summary_bytes) = res?;
            let summary = HotStateSummary::from_ssz_bytes(&summary_bytes)?;

            if summary.slot <= split.slot {
                let old = summary.slot < split.slot;
                let non_canonical = summary.slot == split.slot
                    && state_root != split.state_root
                    && !split.state_root.is_zero();
                if old || non_canonical {
                    let reason = if old {
                        "old dangling state"
                    } else {
                        "non-canonical"
                    };
                    debug!(
                        self.log,
                        "Deleting state";
                        "state_root" => ?state_root,
                        "slot" => summary.slot,
                        "reason" => reason,
                    );
                    state_delete_batch.push(StoreOp::DeleteState(state_root, Some(summary.slot)));
                }
            }
        }
        let num_deleted_states = state_delete_batch.len();
        self.do_atomically_with_block_and_blobs_cache(state_delete_batch)?;
        debug!(
            self.log,
            "Database state pruning complete";
            "num_deleted_states" => num_deleted_states,
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
    let anchor_info = store.anchor_info.read_recursive().clone();
    let anchor_slot = anchor_info.as_ref().map(|a| a.anchor_slot);

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

    let mut hot_db_ops = vec![];
    let mut cold_db_ops = vec![];

    // Chunk writer for the linear block roots in the freezer DB.
    // Start at the new upper limit because we iterate backwards.
    let new_frozen_block_root_upper_limit = finalized_state.slot().as_usize().saturating_sub(1);
    let mut block_root_writer =
        ChunkWriter::<BlockRoots, _, _>::new(&store.cold_db, new_frozen_block_root_upper_limit)?;

    // 1. Copy all of the states between the new finalized state and the split slot, from the hot DB
    // to the cold DB. Delete the execution payloads of these now-finalized blocks.
    let state_root_iter = RootsIterator::new(&store, finalized_state);
    for maybe_tuple in state_root_iter.take_while(|result| match result {
        Ok((_, _, slot)) => {
            slot >= &current_split_slot
                && anchor_slot.map_or(true, |anchor_slot| slot >= &anchor_slot)
        }
        Err(_) => true,
    }) {
        let (block_root, state_root, slot) = maybe_tuple?;

        // Delete the execution payload if payload pruning is enabled. At a skipped slot we may
        // delete the payload for the finalized block itself, but that's OK as we only guarantee
        // that payloads are present for slots >= the split slot. The payload fetching code is also
        // forgiving of missing payloads.
        if store.config.prune_payloads {
            hot_db_ops.push(StoreOp::DeleteExecutionPayload(block_root));
        }

        // Delete the old summary, and the full state if we lie on an epoch boundary.
        hot_db_ops.push(StoreOp::DeleteState(state_root, Some(slot)));

        // Store the block root for this slot in the linear array of frozen block roots.
        block_root_writer.set(slot.as_usize(), block_root, &mut cold_db_ops)?;

        // Do not try to store states if a restore point is yet to be stored, or will never be
        // stored (see `STATE_UPPER_LIMIT_NO_RETAIN`). Make an exception for the genesis state
        // which always needs to be copied from the hot DB to the freezer and should not be deleted.
        if slot != 0
            && anchor_info
                .as_ref()
                .map_or(false, |anchor| slot < anchor.state_upper_limit)
        {
            debug!(store.log, "Pruning finalized state"; "slot" => slot);

            continue;
        }

        // Store a pointer from this state root to its slot, so we can later reconstruct states
        // from their state root alone.
        let cold_state_summary = ColdStateSummary { slot };
        let op = cold_state_summary.as_kv_store_op(state_root);
        cold_db_ops.push(op);

        if slot % store.config.slots_per_restore_point == 0 {
            let state: BeaconState<E> = get_full_state(&store.hot_db, &state_root, &store.spec)?
                .ok_or(HotColdDBError::MissingStateToFreeze(state_root))?;

            store.store_cold_state(&state_root, &state, &mut cold_db_ops)?;

            // Commit the batch of cold DB ops whenever a full state is written. Each state stored
            // may read the linear fields of previous states stored.
            store
                .cold_db
                .do_atomically(std::mem::take(&mut cold_db_ops))?;
        }
    }

    // Finish writing the block roots and commit the remaining cold DB ops.
    block_root_writer.write(&mut cold_db_ops)?;
    store.cold_db.do_atomically(cold_db_ops)?;

    // Warning: Critical section.  We have to take care not to put any of the two databases in an
    //          inconsistent state if the OS process dies at any point during the freezing
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

        // Detect a situation where the split point is (erroneously) changed from more than one
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
            block_root: finalized_block_root,
        };
        store.hot_db.put_sync(&SPLIT_KEY, &split)?;

        // Split point is now persisted in the hot database on disk. The in-memory split point
        // hasn't been modified elsewhere since we keep a write lock on it. It's safe to update
        // the in-memory split point now.
        *split_guard = split;
    }

    // Delete the blocks and states from the hot database if we got this far.
    store.do_atomically_with_block_and_blobs_cache(hot_db_ops)?;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode, Deserialize, Serialize)]
pub struct Split {
    pub slot: Slot,
    pub state_root: Hash256,
    /// The block root of the split state.
    ///
    /// This is used to provide special handling for the split state in the case where there are
    /// skipped slots. The split state will *always* be the advanced state, so callers
    /// who only have the finalized block root should use `get_advanced_hot_state` to get this state,
    /// rather than fetching `block.state_root()` (the unaligned state) which will have been pruned.
    #[ssz(skip_serializing, skip_deserializing)]
    pub block_root: Hash256,
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

/// Type hint.
fn no_state_root_iter() -> Option<std::iter::Empty<Result<(Hash256, Slot), Error>>> {
    None
}

/// Struct for summarising a state in the hot database.
///
/// Allows full reconstruction by replaying blocks.
#[derive(Debug, Clone, Copy, Default, Encode, Decode)]
pub struct HotStateSummary {
    pub slot: Slot,
    pub latest_block_root: Hash256,
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
