use crate::config::{OnDiskStoreConfig, StoreConfig};
use crate::forwards_iter::{HybridForwardsBlockRootsIterator, HybridForwardsStateRootsIterator};
use crate::hdiff::{HDiff, HDiffBuffer, HierarchyModuli, StorageStrategy};
use crate::historic_state_cache::HistoricStateCache;
use crate::impls::beacon_state::{get_full_state, store_full_state};
use crate::iter::{BlockRootsIterator, ParentRootBlockIterator, RootsIterator};
use crate::leveldb_store::{BytesKey, LevelDB};
use crate::memory_store::MemoryStore;
use crate::metadata::{
    AnchorInfo, BlobInfo, CompactionTimestamp, DataColumnInfo, PruningCheckpoint, SchemaVersion,
    ANCHOR_FOR_ARCHIVE_NODE, ANCHOR_INFO_KEY, ANCHOR_UNINITIALIZED, BLOB_INFO_KEY,
    COMPACTION_TIMESTAMP_KEY, CONFIG_KEY, CURRENT_SCHEMA_VERSION, DATA_COLUMN_INFO_KEY,
    PRUNING_CHECKPOINT_KEY, SCHEMA_VERSION_KEY, SPLIT_KEY, STATE_UPPER_LIMIT_NO_RETAIN,
};
use crate::state_cache::{PutStateOutcome, StateCache};
use crate::{
    get_data_column_key, get_key_for_col, DBColumn, DatabaseBlock, Error, ItemStore,
    KeyValueStoreOp, StoreItem, StoreOp,
};
use crate::{metrics, parse_data_column_key};
use itertools::{process_results, Itertools};
use leveldb::iterator::LevelDBIterator;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use safe_arith::SafeArith;
use serde::{Deserialize, Serialize};
use slog::{debug, error, info, trace, warn, Logger};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    block_replayer::PreSlotHook, AllCaches, BlockProcessingError, BlockReplayer,
    SlotProcessingError,
};
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use types::data_column_sidecar::{ColumnIndex, DataColumnSidecar, DataColumnSidecarList};
use types::*;
use zstd::{Decoder, Encoder};

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
    anchor_info: RwLock<AnchorInfo>,
    /// The starting slots for the range of blobs stored in the database.
    blob_info: RwLock<BlobInfo>,
    /// The starting slots for the range of data columns stored in the database.
    data_column_info: RwLock<DataColumnInfo>,
    pub(crate) config: StoreConfig,
    pub(crate) hierarchy: HierarchyModuli,
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
    /// Cache of historic states and hierarchical diff buffers.
    ///
    /// This cache is never pruned. It is only populated in response to historical queries from the
    /// HTTP API.
    historic_state_cache: Mutex<HistoricStateCache<E>>,
    /// Chain spec.
    pub(crate) spec: Arc<ChainSpec>,
    /// Logger.
    pub log: Logger,
    /// Mere vessel for E.
    _phantom: PhantomData<E>,
}

#[derive(Debug)]
struct BlockCache<E: EthSpec> {
    block_cache: LruCache<Hash256, SignedBeaconBlock<E>>,
    blob_cache: LruCache<Hash256, BlobSidecarList<E>>,
    data_column_cache: LruCache<Hash256, HashMap<ColumnIndex, Arc<DataColumnSidecar<E>>>>,
}

impl<E: EthSpec> BlockCache<E> {
    pub fn new(size: NonZeroUsize) -> Self {
        Self {
            block_cache: LruCache::new(size),
            blob_cache: LruCache::new(size),
            data_column_cache: LruCache::new(size),
        }
    }
    pub fn put_block(&mut self, block_root: Hash256, block: SignedBeaconBlock<E>) {
        self.block_cache.put(block_root, block);
    }
    pub fn put_blobs(&mut self, block_root: Hash256, blobs: BlobSidecarList<E>) {
        self.blob_cache.put(block_root, blobs);
    }
    pub fn put_data_column(&mut self, block_root: Hash256, data_column: Arc<DataColumnSidecar<E>>) {
        self.data_column_cache
            .get_or_insert_mut(block_root, Default::default)
            .insert(data_column.index, data_column);
    }
    pub fn get_block<'a>(&'a mut self, block_root: &Hash256) -> Option<&'a SignedBeaconBlock<E>> {
        self.block_cache.get(block_root)
    }
    pub fn get_blobs<'a>(&'a mut self, block_root: &Hash256) -> Option<&'a BlobSidecarList<E>> {
        self.blob_cache.get(block_root)
    }
    pub fn get_data_column<'a>(
        &'a mut self,
        block_root: &Hash256,
        column_index: &ColumnIndex,
    ) -> Option<&'a Arc<DataColumnSidecar<E>>> {
        self.data_column_cache
            .get(block_root)
            .and_then(|map| map.get(column_index))
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
    MissingRestorePointState(Slot),
    MissingRestorePoint(Hash256),
    MissingColdStateSummary(Hash256),
    MissingHotStateSummary(Hash256),
    MissingEpochBoundaryState(Hash256),
    MissingPrevState(Hash256),
    MissingSplitState(Hash256, Slot),
    MissingStateDiff(Hash256),
    MissingHDiff(Slot),
    MissingExecutionPayload(Hash256),
    MissingFullBlockExecutionPayloadPruned(Hash256, Slot),
    MissingAnchorInfo,
    MissingFrozenBlockSlot(Hash256),
    MissingFrozenBlock(Slot),
    MissingPathToBlobsDatabase,
    BlobsPreviouslyInDefaultStore,
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
        spec: Arc<ChainSpec>,
        log: Logger,
    ) -> Result<HotColdDB<E, MemoryStore<E>, MemoryStore<E>>, Error> {
        config.verify::<E>()?;

        let hierarchy = config.hierarchy_config.to_moduli()?;

        let db = HotColdDB {
            split: RwLock::new(Split::default()),
            anchor_info: RwLock::new(ANCHOR_UNINITIALIZED),
            blob_info: RwLock::new(BlobInfo::default()),
            data_column_info: RwLock::new(DataColumnInfo::default()),
            cold_db: MemoryStore::open(),
            blobs_db: MemoryStore::open(),
            hot_db: MemoryStore::open(),
            block_cache: Mutex::new(BlockCache::new(config.block_cache_size)),
            state_cache: Mutex::new(StateCache::new(config.state_cache_size)),
            historic_state_cache: Mutex::new(HistoricStateCache::new(
                config.hdiff_buffer_cache_size,
                config.historic_state_cache_size,
            )),
            config,
            hierarchy,
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
        spec: Arc<ChainSpec>,
        log: Logger,
    ) -> Result<Arc<Self>, Error> {
        config.verify::<E>()?;

        let hierarchy = config.hierarchy_config.to_moduli()?;

        let hot_db = LevelDB::open(hot_path)?;
        let anchor_info = RwLock::new(Self::load_anchor_info(&hot_db)?);

        let db = HotColdDB {
            split: RwLock::new(Split::default()),
            anchor_info,
            blob_info: RwLock::new(BlobInfo::default()),
            data_column_info: RwLock::new(DataColumnInfo::default()),
            cold_db: LevelDB::open(cold_path)?,
            blobs_db: LevelDB::open(blobs_db_path)?,
            hot_db,
            block_cache: Mutex::new(BlockCache::new(config.block_cache_size)),
            state_cache: Mutex::new(StateCache::new(config.state_cache_size)),
            historic_state_cache: Mutex::new(HistoricStateCache::new(
                config.hdiff_buffer_cache_size,
                config.historic_state_cache_size,
            )),
            config,
            hierarchy,
            spec,
            log,
            _phantom: PhantomData,
        };

        // Load the config from disk but don't error on a failed read because the config itself may
        // need migrating.
        let _ = db.load_config();

        // Load the previous split slot from the database (if any). This ensures we can
        // stop and restart correctly. This needs to occur *before* running any migrations
        // because some migrations load states and depend on the split.
        if let Some(split) = db.load_split()? {
            *db.split.write() = split;

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

        let data_column_info = db.load_data_column_info()?;
        let eip7594_fork_slot = db
            .spec
            .eip7594_fork_epoch
            .map(|epoch| epoch.start_slot(E::slots_per_epoch()));
        let new_data_column_info = match &data_column_info {
            Some(data_column_info) => {
                // Set the oldest data column slot to the fork slot if it is not yet set.
                let oldest_data_column_slot = data_column_info
                    .oldest_data_column_slot
                    .or(eip7594_fork_slot);
                DataColumnInfo {
                    oldest_data_column_slot,
                }
            }
            // First start.
            None => DataColumnInfo {
                // Set the oldest data column slot to the fork slot if it is not yet set.
                oldest_data_column_slot: eip7594_fork_slot,
            },
        };
        db.compare_and_set_data_column_info_with_write(
            <_>::default(),
            new_data_column_info.clone(),
        )?;

        info!(
            db.log,
            "Blob DB initialized";
            "path" => ?blobs_db_path,
            "oldest_blob_slot" => ?new_blob_info.oldest_blob_slot,
            "oldest_data_column_slot" => ?new_data_column_info.oldest_data_column_slot,
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
            let split = db.get_split_info();
            let anchor = db.get_anchor_info();
            db.config
                .check_compatibility(&disk_config, &split, &anchor)?;

            // Inform user if hierarchy config is changing.
            if let Ok(hierarchy_config) = disk_config.hierarchy_config() {
                if &db.config.hierarchy_config != hierarchy_config {
                    info!(
                        db.log,
                        "Updating historic state config";
                        "previous_config" => %hierarchy_config,
                        "new_config" => %db.config.hierarchy_config,
                    );
                }
            }
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
            BytesKey::from_vec(get_key_for_col(column.into(), Hash256::zero().as_slice()));

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

    pub fn register_metrics(&self) {
        let hsc_metrics = self.historic_state_cache.lock().metrics();

        metrics::set_gauge(
            &metrics::STORE_BEACON_BLOCK_CACHE_SIZE,
            self.block_cache.lock().block_cache.len() as i64,
        );
        metrics::set_gauge(
            &metrics::STORE_BEACON_BLOB_CACHE_SIZE,
            self.block_cache.lock().blob_cache.len() as i64,
        );
        metrics::set_gauge(
            &metrics::STORE_BEACON_STATE_CACHE_SIZE,
            self.state_cache.lock().len() as i64,
        );
        metrics::set_gauge(
            &metrics::STORE_BEACON_HISTORIC_STATE_CACHE_SIZE,
            hsc_metrics.num_state as i64,
        );
        metrics::set_gauge(
            &metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_SIZE,
            hsc_metrics.num_hdiff as i64,
        );
        metrics::set_gauge(
            &metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_BYTE_SIZE,
            hsc_metrics.hdiff_byte_size as i64,
        );

        let anchor_info = self.get_anchor_info();
        metrics::set_gauge(
            &metrics::STORE_BEACON_ANCHOR_SLOT,
            anchor_info.anchor_slot.as_u64() as i64,
        );
        metrics::set_gauge(
            &metrics::STORE_BEACON_OLDEST_BLOCK_SLOT,
            anchor_info.oldest_block_slot.as_u64() as i64,
        );
        metrics::set_gauge(
            &metrics::STORE_BEACON_STATE_LOWER_LIMIT,
            anchor_info.state_lower_limit.as_u64() as i64,
        );
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
        let db_key = get_key_for_col(DBColumn::BeaconBlock.into(), key.as_slice());
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
            .get_bytes(DBColumn::BeaconBlock.into(), block_root.as_slice())?
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
        let key = block_root.as_slice();

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

    /// Get the sync committee branch for the given block root
    /// Note: we only persist sync committee branches for checkpoint slots
    pub fn get_sync_committee_branch(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<MerkleProof>, Error> {
        let column = DBColumn::SyncCommitteeBranch;

        if let Some(bytes) = self
            .hot_db
            .get_bytes(column.into(), &block_root.as_ssz_bytes())?
        {
            let sync_committee_branch = Vec::<Hash256>::from_ssz_bytes(&bytes)?;
            return Ok(Some(sync_committee_branch));
        }

        Ok(None)
    }

    /// Fetch sync committee by sync committee period
    pub fn get_sync_committee(
        &self,
        sync_committee_period: u64,
    ) -> Result<Option<SyncCommittee<E>>, Error> {
        let column = DBColumn::SyncCommittee;

        if let Some(bytes) = self
            .hot_db
            .get_bytes(column.into(), &sync_committee_period.as_ssz_bytes())?
        {
            let sync_committee: SyncCommittee<E> = SyncCommittee::from_ssz_bytes(&bytes)?;
            return Ok(Some(sync_committee));
        }

        Ok(None)
    }

    pub fn store_sync_committee_branch(
        &self,
        block_root: Hash256,
        sync_committee_branch: &MerkleProof,
    ) -> Result<(), Error> {
        let column = DBColumn::SyncCommitteeBranch;
        self.hot_db.put_bytes(
            column.into(),
            &block_root.as_ssz_bytes(),
            &sync_committee_branch.as_ssz_bytes(),
        )?;
        Ok(())
    }

    pub fn store_sync_committee(
        &self,
        sync_committee_period: u64,
        sync_committee: &SyncCommittee<E>,
    ) -> Result<(), Error> {
        let column = DBColumn::SyncCommittee;
        self.hot_db.put_bytes(
            column.into(),
            &sync_committee_period.to_le_bytes(),
            &sync_committee.as_ssz_bytes(),
        )?;

        Ok(())
    }

    pub fn get_light_client_update(
        &self,
        sync_committee_period: u64,
    ) -> Result<Option<LightClientUpdate<E>>, Error> {
        let column = DBColumn::LightClientUpdate;
        let res = self
            .hot_db
            .get_bytes(column.into(), &sync_committee_period.to_le_bytes())?;

        if let Some(light_client_update_bytes) = res {
            let epoch = sync_committee_period
                .safe_mul(self.spec.epochs_per_sync_committee_period.into())?;

            let fork_name = self.spec.fork_name_at_epoch(epoch.into());

            let light_client_update =
                LightClientUpdate::from_ssz_bytes(&light_client_update_bytes, &fork_name)?;

            return Ok(Some(light_client_update));
        }

        Ok(None)
    }

    pub fn get_light_client_updates(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<LightClientUpdate<E>>, Error> {
        let column = DBColumn::LightClientUpdate;
        let mut light_client_updates = vec![];
        for res in self
            .hot_db
            .iter_column_from::<Vec<u8>>(column, &start_period.to_le_bytes())
        {
            let (sync_committee_bytes, light_client_update_bytes) = res?;
            let sync_committee_period = u64::from_ssz_bytes(&sync_committee_bytes)?;
            let epoch = sync_committee_period
                .safe_mul(self.spec.epochs_per_sync_committee_period.into())?;

            let fork_name = self.spec.fork_name_at_epoch(epoch.into());

            let light_client_update =
                LightClientUpdate::from_ssz_bytes(&light_client_update_bytes, &fork_name)?;

            light_client_updates.push(light_client_update);

            if sync_committee_period >= start_period + count {
                break;
            }
        }
        Ok(light_client_updates)
    }

    pub fn store_light_client_update(
        &self,
        sync_committee_period: u64,
        light_client_update: &LightClientUpdate<E>,
    ) -> Result<(), Error> {
        let column = DBColumn::LightClientUpdate;

        self.hot_db.put_bytes(
            column.into(),
            &sync_committee_period.to_le_bytes(),
            &light_client_update.as_ssz_bytes(),
        )?;

        Ok(())
    }

    /// Check if the blobs for a block exists on disk.
    pub fn blobs_exist(&self, block_root: &Hash256) -> Result<bool, Error> {
        self.blobs_db
            .key_exists(DBColumn::BeaconBlob.into(), block_root.as_slice())
    }

    /// Determine whether a block exists in the database.
    pub fn block_exists(&self, block_root: &Hash256) -> Result<bool, Error> {
        self.hot_db
            .key_exists(DBColumn::BeaconBlock.into(), block_root.as_slice())
    }

    /// Delete a block from the store and the block cache.
    pub fn delete_block(&self, block_root: &Hash256) -> Result<(), Error> {
        self.block_cache.lock().delete(block_root);
        self.hot_db
            .key_delete(DBColumn::BeaconBlock.into(), block_root.as_slice())?;
        self.hot_db
            .key_delete(DBColumn::ExecPayload.into(), block_root.as_slice())?;
        self.blobs_db
            .key_delete(DBColumn::BeaconBlob.into(), block_root.as_slice())
    }

    pub fn put_blobs(&self, block_root: &Hash256, blobs: BlobSidecarList<E>) -> Result<(), Error> {
        self.blobs_db.put_bytes(
            DBColumn::BeaconBlob.into(),
            block_root.as_slice(),
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
        let db_key = get_key_for_col(DBColumn::BeaconBlob.into(), key.as_slice());
        ops.push(KeyValueStoreOp::PutKeyValue(db_key, blobs.as_ssz_bytes()));
    }

    pub fn data_columns_as_kv_store_ops(
        &self,
        block_root: &Hash256,
        data_columns: DataColumnSidecarList<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) {
        for data_column in data_columns {
            let db_key = get_key_for_col(
                DBColumn::BeaconDataColumn.into(),
                &get_data_column_key(block_root, &data_column.index),
            );
            ops.push(KeyValueStoreOp::PutKeyValue(
                db_key,
                data_column.as_ssz_bytes(),
            ));
        }
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
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>> + '_, Error> {
        HybridForwardsBlockRootsIterator::new(
            self,
            DBColumn::BeaconBlockRoots,
            start_slot,
            None,
            || Ok((end_state, end_block_root)),
        )
    }

    pub fn forwards_block_roots_iterator_until(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        get_state: impl FnOnce() -> Result<(BeaconState<E>, Hash256), Error>,
    ) -> Result<HybridForwardsBlockRootsIterator<E, Hot, Cold>, Error> {
        HybridForwardsBlockRootsIterator::new(
            self,
            DBColumn::BeaconBlockRoots,
            start_slot,
            Some(end_slot),
            get_state,
        )
    }

    pub fn forwards_state_roots_iterator(
        &self,
        start_slot: Slot,
        end_state_root: Hash256,
        end_state: BeaconState<E>,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>> + '_, Error> {
        HybridForwardsStateRootsIterator::new(
            self,
            DBColumn::BeaconStateRoots,
            start_slot,
            None,
            || Ok((end_state, end_state_root)),
        )
    }

    pub fn forwards_state_roots_iterator_until(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        get_state: impl FnOnce() -> Result<(BeaconState<E>, Hash256), Error>,
    ) -> Result<HybridForwardsStateRootsIterator<E, Hot, Cold>, Error> {
        HybridForwardsStateRootsIterator::new(
            self,
            DBColumn::BeaconStateRoots,
            start_slot,
            Some(end_slot),
            get_state,
        )
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

                StoreOp::PutDataColumns(block_root, data_columns) => {
                    self.data_columns_as_kv_store_ops(
                        &block_root,
                        data_columns,
                        &mut key_value_batch,
                    );
                }

                StoreOp::PutStateSummary(state_root, summary) => {
                    key_value_batch.push(summary.as_kv_store_op(state_root));
                }

                StoreOp::PutStateTemporaryFlag(state_root) => {
                    key_value_batch.push(TemporaryFlag.as_kv_store_op(state_root));
                }

                StoreOp::DeleteStateTemporaryFlag(state_root) => {
                    let db_key =
                        get_key_for_col(TemporaryFlag::db_column().into(), state_root.as_slice());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(db_key));
                }

                StoreOp::DeleteBlock(block_root) => {
                    let key = get_key_for_col(DBColumn::BeaconBlock.into(), block_root.as_slice());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(key));
                }

                StoreOp::DeleteBlobs(block_root) => {
                    let key = get_key_for_col(DBColumn::BeaconBlob.into(), block_root.as_slice());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(key));
                }

                StoreOp::DeleteDataColumns(block_root, column_indices) => {
                    for index in column_indices {
                        let key = get_key_for_col(
                            DBColumn::BeaconDataColumn.into(),
                            &get_data_column_key(&block_root, &index),
                        );
                        key_value_batch.push(KeyValueStoreOp::DeleteKey(key));
                    }
                }

                StoreOp::DeleteState(state_root, slot) => {
                    // Delete the hot state summary.
                    let state_summary_key =
                        get_key_for_col(DBColumn::BeaconStateSummary.into(), state_root.as_slice());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(state_summary_key));

                    // Delete the state temporary flag (if any). Temporary flags are commonly
                    // created by the state advance routine.
                    let state_temp_key = get_key_for_col(
                        DBColumn::BeaconStateTemporary.into(),
                        state_root.as_slice(),
                    );
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(state_temp_key));

                    if slot.map_or(true, |slot| slot % E::slots_per_epoch() == 0) {
                        let state_key =
                            get_key_for_col(DBColumn::BeaconState.into(), state_root.as_slice());
                        key_value_batch.push(KeyValueStoreOp::DeleteKey(state_key));
                    }
                }

                StoreOp::DeleteExecutionPayload(block_root) => {
                    let key = get_key_for_col(DBColumn::ExecPayload.into(), block_root.as_slice());
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(key));
                }

                StoreOp::DeleteSyncCommitteeBranch(block_root) => {
                    let key = get_key_for_col(
                        DBColumn::SyncCommitteeBranch.into(),
                        block_root.as_slice(),
                    );
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
        let mut data_columns_to_delete = Vec::new();
        let (blobs_ops, hot_db_ops): (Vec<StoreOp<E>>, Vec<StoreOp<E>>) =
            batch.into_iter().partition(|store_op| match store_op {
                StoreOp::PutBlobs(_, _) | StoreOp::PutDataColumns(_, _) => true,
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
                StoreOp::DeleteDataColumns(block_root, indices) => {
                    match indices
                        .iter()
                        .map(|index| self.get_data_column(block_root, index))
                        .collect::<Result<Vec<_>, _>>()
                    {
                        Ok(data_column_sidecar_list_opt) => {
                            let data_column_sidecar_list = data_column_sidecar_list_opt
                                .into_iter()
                                .flatten()
                                .collect::<Vec<_>>();
                            // Must push the same number of items as StoreOp::DeleteDataColumns items to
                            // prevent a `HotColdDBError::Rollback` error below in case of rollback
                            data_columns_to_delete.push((*block_root, data_column_sidecar_list));
                        }
                        Err(e) => {
                            error!(
                                self.log, "Error getting data columns";
                                "block_root" => %block_root,
                                "error" => ?e
                            );
                        }
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
                    StoreOp::PutDataColumns(block_root, data_columns) => {
                        let indices = data_columns.iter().map(|c| c.index).collect();
                        StoreOp::DeleteDataColumns(*block_root, indices)
                    }
                    StoreOp::DeleteBlobs(_) => match blobs_to_delete.pop() {
                        Some((block_root, blobs)) => StoreOp::PutBlobs(block_root, blobs),
                        None => return Err(HotColdDBError::Rollback.into()),
                    },
                    StoreOp::DeleteDataColumns(_, _) => match data_columns_to_delete.pop() {
                        Some((block_root, data_columns)) => {
                            StoreOp::PutDataColumns(block_root, data_columns)
                        }
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

                StoreOp::PutDataColumns(_, _) => (),

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

                StoreOp::DeleteDataColumns(_, _) => (),

                StoreOp::DeleteExecutionPayload(_) => (),

                StoreOp::DeleteSyncCommitteeBranch(_) => (),

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
                    Ok(())
                };
                let blocks =
                    self.load_blocks_to_replay(boundary_state.slot(), slot, latest_block_root)?;
                let _t = metrics::start_timer(&metrics::STORE_BEACON_REPLAY_HOT_BLOCKS_TIME);
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

    pub fn store_cold_state_summary(
        &self,
        state_root: &Hash256,
        slot: Slot,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        ops.push(ColdStateSummary { slot }.as_kv_store_op(*state_root));
        ops.push(KeyValueStoreOp::PutKeyValue(
            get_key_for_col(
                DBColumn::BeaconStateRoots.into(),
                &slot.as_u64().to_be_bytes(),
            ),
            state_root.as_slice().to_vec(),
        ));
        Ok(())
    }

    /// Store a pre-finalization state in the freezer database.
    pub fn store_cold_state(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        self.store_cold_state_summary(state_root, state.slot(), ops)?;

        let slot = state.slot();
        match self.hierarchy.storage_strategy(slot)? {
            StorageStrategy::ReplayFrom(from) => {
                debug!(
                    self.log,
                    "Storing cold state";
                    "strategy" => "replay",
                    "from_slot" => from,
                    "slot" => state.slot(),
                );
                // Already have persisted the state summary, don't persist anything else
            }
            StorageStrategy::Snapshot => {
                debug!(
                    self.log,
                    "Storing cold state";
                    "strategy" => "snapshot",
                    "slot" => state.slot(),
                );
                self.store_cold_state_as_snapshot(state, ops)?;
            }
            StorageStrategy::DiffFrom(from) => {
                debug!(
                    self.log,
                    "Storing cold state";
                    "strategy" => "diff",
                    "from_slot" => from,
                    "slot" => state.slot(),
                );
                self.store_cold_state_as_diff(state, from, ops)?;
            }
        }

        Ok(())
    }

    pub fn store_cold_state_as_snapshot(
        &self,
        state: &BeaconState<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        let bytes = state.as_ssz_bytes();
        let compressed_value = {
            let _timer = metrics::start_timer(&metrics::STORE_BEACON_STATE_FREEZER_COMPRESS_TIME);
            let mut out = Vec::with_capacity(self.config.estimate_compressed_size(bytes.len()));
            let mut encoder = Encoder::new(&mut out, self.config.compression_level)
                .map_err(Error::Compression)?;
            encoder.write_all(&bytes).map_err(Error::Compression)?;
            encoder.finish().map_err(Error::Compression)?;
            out
        };

        let key = get_key_for_col(
            DBColumn::BeaconStateSnapshot.into(),
            &state.slot().as_u64().to_be_bytes(),
        );
        ops.push(KeyValueStoreOp::PutKeyValue(key, compressed_value));
        Ok(())
    }

    fn load_cold_state_bytes_as_snapshot(&self, slot: Slot) -> Result<Option<Vec<u8>>, Error> {
        match self.cold_db.get_bytes(
            DBColumn::BeaconStateSnapshot.into(),
            &slot.as_u64().to_be_bytes(),
        )? {
            Some(bytes) => {
                let _timer =
                    metrics::start_timer(&metrics::STORE_BEACON_STATE_FREEZER_DECOMPRESS_TIME);
                let mut ssz_bytes =
                    Vec::with_capacity(self.config.estimate_decompressed_size(bytes.len()));
                let mut decoder = Decoder::new(&*bytes).map_err(Error::Compression)?;
                decoder
                    .read_to_end(&mut ssz_bytes)
                    .map_err(Error::Compression)?;
                Ok(Some(ssz_bytes))
            }
            None => Ok(None),
        }
    }

    fn load_cold_state_as_snapshot(&self, slot: Slot) -> Result<Option<BeaconState<E>>, Error> {
        Ok(self
            .load_cold_state_bytes_as_snapshot(slot)?
            .map(|bytes| BeaconState::from_ssz_bytes(&bytes, &self.spec))
            .transpose()?)
    }

    pub fn store_cold_state_as_diff(
        &self,
        state: &BeaconState<E>,
        from_slot: Slot,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        // Load diff base state bytes.
        let (_, base_buffer) = {
            let _t = metrics::start_timer(&metrics::STORE_BEACON_HDIFF_BUFFER_LOAD_FOR_STORE_TIME);
            self.load_hdiff_buffer_for_slot(from_slot)?
        };
        let target_buffer = HDiffBuffer::from_state(state.clone());
        let diff = {
            let _timer = metrics::start_timer(&metrics::STORE_BEACON_HDIFF_BUFFER_COMPUTE_TIME);
            HDiff::compute(&base_buffer, &target_buffer, &self.config)?
        };
        let diff_bytes = diff.as_ssz_bytes();

        let key = get_key_for_col(
            DBColumn::BeaconStateDiff.into(),
            &state.slot().as_u64().to_be_bytes(),
        );
        ops.push(KeyValueStoreOp::PutKeyValue(key, diff_bytes));
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
        let storage_strategy = self.hierarchy.storage_strategy(slot)?;

        // Search for a state from this slot or a recent prior slot in the historic state cache.
        let mut historic_state_cache = self.historic_state_cache.lock();

        let cached_state = itertools::process_results(
            storage_strategy
                .replay_from_range(slot)
                .rev()
                .map(|prior_slot| historic_state_cache.get_state(prior_slot, &self.spec)),
            |mut iter| iter.find_map(|cached_state| cached_state),
        )?;
        drop(historic_state_cache);

        if let Some(cached_state) = cached_state {
            if cached_state.slot() == slot {
                metrics::inc_counter(&metrics::STORE_BEACON_HISTORIC_STATE_CACHE_HIT);
                return Ok(cached_state);
            }
            metrics::inc_counter(&metrics::STORE_BEACON_HISTORIC_STATE_CACHE_MISS);

            return self.load_cold_state_by_slot_using_replay(cached_state, slot);
        }

        metrics::inc_counter(&metrics::STORE_BEACON_HISTORIC_STATE_CACHE_MISS);

        // Load using the diff hierarchy. For states that require replay we recurse into this
        // function so that we can try to get their pre-state *as a state* rather than an hdiff
        // buffer.
        match self.hierarchy.storage_strategy(slot)? {
            StorageStrategy::Snapshot | StorageStrategy::DiffFrom(_) => {
                let buffer_timer =
                    metrics::start_timer(&metrics::STORE_BEACON_HDIFF_BUFFER_LOAD_TIME);
                let (_, buffer) = self.load_hdiff_buffer_for_slot(slot)?;
                drop(buffer_timer);
                let state = buffer.as_state(&self.spec)?;

                self.historic_state_cache
                    .lock()
                    .put_both(slot, state.clone(), buffer);
                Ok(state)
            }
            StorageStrategy::ReplayFrom(from) => {
                // No prior state found in cache (above), need to load by diffing and then
                // replaying.
                let base_state = self.load_cold_state_by_slot(from)?;
                self.load_cold_state_by_slot_using_replay(base_state, slot)
            }
        }
    }

    fn load_cold_state_by_slot_using_replay(
        &self,
        mut base_state: BeaconState<E>,
        slot: Slot,
    ) -> Result<BeaconState<E>, Error> {
        if !base_state.all_caches_built() {
            // Build all caches and update the historic state cache so that these caches may be used
            // at future slots. We do this lazily here rather than when populating the cache in
            // order to speed up queries at snapshot/diff slots, which are already slow.
            let cache_timer =
                metrics::start_timer(&metrics::STORE_BEACON_COLD_BUILD_BEACON_CACHES_TIME);
            base_state.build_all_caches(&self.spec)?;
            debug!(
                self.log,
                "Built caches for historic state";
                "target_slot" => slot,
                "build_time_ms" => metrics::stop_timer_with_duration(cache_timer).as_millis()
            );
            self.historic_state_cache
                .lock()
                .put_state(base_state.slot(), base_state.clone());
        }

        if base_state.slot() == slot {
            return Ok(base_state);
        }

        let blocks = self.load_cold_blocks(base_state.slot() + 1, slot)?;

        // Include state root for base state as it is required by block processing to not
        // have to hash the state.
        let replay_timer = metrics::start_timer(&metrics::STORE_BEACON_REPLAY_COLD_BLOCKS_TIME);
        let state_root_iter =
            self.forwards_state_roots_iterator_until(base_state.slot(), slot, || {
                Err(Error::StateShouldNotBeRequired(slot))
            })?;
        let state = self.replay_blocks(base_state, blocks, slot, Some(state_root_iter), None)?;
        debug!(
            self.log,
            "Replayed blocks for historic state";
            "target_slot" => slot,
            "replay_time_ms" => metrics::stop_timer_with_duration(replay_timer).as_millis()
        );

        self.historic_state_cache
            .lock()
            .put_state(slot, state.clone());
        Ok(state)
    }

    fn load_hdiff_for_slot(&self, slot: Slot) -> Result<HDiff, Error> {
        let bytes = {
            let _t = metrics::start_timer(&metrics::BEACON_HDIFF_READ_TIMES);
            self.cold_db
                .get_bytes(
                    DBColumn::BeaconStateDiff.into(),
                    &slot.as_u64().to_be_bytes(),
                )?
                .ok_or(HotColdDBError::MissingHDiff(slot))?
        };
        let hdiff = {
            let _t = metrics::start_timer(&metrics::BEACON_HDIFF_DECODE_TIMES);
            HDiff::from_ssz_bytes(&bytes)?
        };
        Ok(hdiff)
    }

    /// Returns `HDiffBuffer` for the specified slot, or `HDiffBuffer` for the `ReplayFrom` slot if
    /// the diff for the specified slot is not stored.
    fn load_hdiff_buffer_for_slot(&self, slot: Slot) -> Result<(Slot, HDiffBuffer), Error> {
        if let Some(buffer) = self.historic_state_cache.lock().get_hdiff_buffer(slot) {
            debug!(
                self.log,
                "Hit hdiff buffer cache";
                "slot" => slot
            );
            metrics::inc_counter(&metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_HIT);
            return Ok((slot, buffer));
        }
        metrics::inc_counter(&metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_MISS);

        // Load buffer for the previous state.
        // This amount of recursion (<10 levels) should be OK.
        let t = std::time::Instant::now();
        match self.hierarchy.storage_strategy(slot)? {
            // Base case.
            StorageStrategy::Snapshot => {
                let state = self
                    .load_cold_state_as_snapshot(slot)?
                    .ok_or(Error::MissingSnapshot(slot))?;
                let buffer = HDiffBuffer::from_state(state.clone());

                self.historic_state_cache
                    .lock()
                    .put_both(slot, state, buffer.clone());

                let load_time_ms = t.elapsed().as_millis();
                debug!(
                    self.log,
                    "Cached state and hdiff buffer";
                    "load_time_ms" => load_time_ms,
                    "slot" => slot
                );

                Ok((slot, buffer))
            }
            // Recursive case.
            StorageStrategy::DiffFrom(from) => {
                let (_buffer_slot, mut buffer) = self.load_hdiff_buffer_for_slot(from)?;

                // Load diff and apply it to buffer.
                let diff = self.load_hdiff_for_slot(slot)?;
                {
                    let _timer =
                        metrics::start_timer(&metrics::STORE_BEACON_HDIFF_BUFFER_APPLY_TIME);
                    diff.apply(&mut buffer, &self.config)?;
                }

                self.historic_state_cache
                    .lock()
                    .put_hdiff_buffer(slot, buffer.clone());

                let load_time_ms = t.elapsed().as_millis();
                debug!(
                    self.log,
                    "Cached hdiff buffer";
                    "load_time_ms" => load_time_ms,
                    "slot" => slot
                );

                Ok((slot, buffer))
            }
            StorageStrategy::ReplayFrom(from) => self.load_hdiff_buffer_for_slot(from),
        }
    }

    /// Load cold blocks between `start_slot` and `end_slot` inclusive.
    pub fn load_cold_blocks(
        &self,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<SignedBlindedBeaconBlock<E>>, Error> {
        let _t = metrics::start_timer(&metrics::STORE_BEACON_LOAD_COLD_BLOCKS_TIME);
        let block_root_iter =
            self.forwards_block_roots_iterator_until(start_slot, end_slot, || {
                Err(Error::StateShouldNotBeRequired(end_slot))
            })?;
        process_results(block_root_iter, |iter| {
            iter.map(|(block_root, _slot)| block_root)
                .dedup()
                .map(|block_root| {
                    self.get_blinded_block(&block_root)?
                        .ok_or(Error::MissingBlock(block_root))
                })
                .collect()
        })?
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
        let _t = metrics::start_timer(&metrics::STORE_BEACON_LOAD_HOT_BLOCKS_TIME);
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
        metrics::inc_counter_by(&metrics::STORE_BEACON_REPLAYED_BLOCKS, blocks.len() as u64);

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
            .get_bytes(DBColumn::BeaconBlob.into(), block_root.as_slice())?
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

    /// Fetch all keys in the data_column column with prefix `block_root`
    pub fn get_data_column_keys(&self, block_root: Hash256) -> Result<Vec<ColumnIndex>, Error> {
        self.blobs_db
            .iter_raw_keys(DBColumn::BeaconDataColumn, block_root.as_slice())
            .map(|key| key.and_then(|key| parse_data_column_key(key).map(|key| key.1)))
            .collect()
    }

    /// Fetch a single data_column for a given block from the store.
    pub fn get_data_column(
        &self,
        block_root: &Hash256,
        column_index: &ColumnIndex,
    ) -> Result<Option<Arc<DataColumnSidecar<E>>>, Error> {
        // Check the cache.
        if let Some(data_column) = self
            .block_cache
            .lock()
            .get_data_column(block_root, column_index)
        {
            metrics::inc_counter(&metrics::BEACON_DATA_COLUMNS_CACHE_HIT_COUNT);
            return Ok(Some(data_column.clone()));
        }

        match self.blobs_db.get_bytes(
            DBColumn::BeaconDataColumn.into(),
            &get_data_column_key(block_root, column_index),
        )? {
            Some(ref data_column_bytes) => {
                let data_column = Arc::new(DataColumnSidecar::from_ssz_bytes(data_column_bytes)?);
                self.block_cache
                    .lock()
                    .put_data_column(*block_root, data_column.clone());
                Ok(Some(data_column))
            }
            None => Ok(None),
        }
    }

    /// Get a reference to the `ChainSpec` used by the database.
    pub fn get_chain_spec(&self) -> &Arc<ChainSpec> {
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
        let key = SCHEMA_VERSION_KEY.as_slice();
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

        // Set the `state_upper_limit` to the slot of the *next* checkpoint.
        let next_snapshot_slot = self.hierarchy.next_snapshot_slot(anchor_slot)?;
        let state_upper_limit = if !retain_historic_states {
            STATE_UPPER_LIMIT_NO_RETAIN
        } else {
            next_snapshot_slot
        };
        let anchor_info = if state_upper_limit == 0 && anchor_slot == 0 {
            // Genesis archive node: no anchor because we *will* store all states.
            ANCHOR_FOR_ARCHIVE_NODE
        } else {
            AnchorInfo {
                anchor_slot,
                oldest_block_slot: anchor_slot,
                oldest_block_parent: block.parent_root(),
                state_upper_limit,
                state_lower_limit: self.spec.genesis_slot,
            }
        };
        self.compare_and_set_anchor_info(ANCHOR_UNINITIALIZED, anchor_info)
    }

    /// Get a clone of the store's anchor info.
    ///
    /// To do mutations, use `compare_and_set_anchor_info`.
    pub fn get_anchor_info(&self) -> AnchorInfo {
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
        prev_value: AnchorInfo,
        new_value: AnchorInfo,
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
        prev_value: AnchorInfo,
        new_value: AnchorInfo,
    ) -> Result<(), Error> {
        let kv_store_op = self.compare_and_set_anchor_info(prev_value, new_value)?;
        self.hot_db.do_atomically(vec![kv_store_op])
    }

    /// Load the anchor info from disk.
    fn load_anchor_info(hot_db: &Hot) -> Result<AnchorInfo, Error> {
        Ok(hot_db
            .get(&ANCHOR_INFO_KEY)?
            .unwrap_or(ANCHOR_UNINITIALIZED))
    }

    /// Store the given `anchor_info` to disk.
    ///
    /// The argument is intended to be `self.anchor_info`, but is passed manually to avoid issues
    /// with recursive locking.
    fn store_anchor_info_in_batch(&self, anchor_info: &AnchorInfo) -> KeyValueStoreOp {
        anchor_info.as_kv_store_op(ANCHOR_INFO_KEY)
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

    /// Initialize the `DataColumnInfo` when starting from genesis or a checkpoint.
    pub fn init_data_column_info(&self, anchor_slot: Slot) -> Result<KeyValueStoreOp, Error> {
        let oldest_data_column_slot = self.spec.eip7594_fork_epoch.map(|fork_epoch| {
            std::cmp::max(anchor_slot, fork_epoch.start_slot(E::slots_per_epoch()))
        });
        let data_column_info = DataColumnInfo {
            oldest_data_column_slot,
        };
        self.compare_and_set_data_column_info(self.get_data_column_info(), data_column_info)
    }

    /// Get a clone of the store's data column info.
    ///
    /// To do mutations, use `compare_and_set_data_column_info`.
    pub fn get_data_column_info(&self) -> DataColumnInfo {
        self.data_column_info.read_recursive().clone()
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

    /// Atomically update the data column info from `prev_value` to `new_value`.
    ///
    /// Return a `KeyValueStoreOp` which should be written to disk, possibly atomically with other
    /// values.
    ///
    /// Return an `DataColumnInfoConcurrentMutation` error if the `prev_value` provided
    /// is not correct.
    pub fn compare_and_set_data_column_info(
        &self,
        prev_value: DataColumnInfo,
        new_value: DataColumnInfo,
    ) -> Result<KeyValueStoreOp, Error> {
        let mut data_column_info = self.data_column_info.write();
        if *data_column_info == prev_value {
            let kv_op = self.store_data_column_info_in_batch(&new_value);
            *data_column_info = new_value;
            Ok(kv_op)
        } else {
            Err(Error::DataColumnInfoConcurrentMutation)
        }
    }

    /// As for `compare_and_set_data_column_info`, but also writes the blob info to disk immediately.
    pub fn compare_and_set_data_column_info_with_write(
        &self,
        prev_value: DataColumnInfo,
        new_value: DataColumnInfo,
    ) -> Result<(), Error> {
        let kv_store_op = self.compare_and_set_data_column_info(prev_value, new_value)?;
        self.hot_db.do_atomically(vec![kv_store_op])
    }

    /// Load the blob info from disk, but do not set `self.data_column_info`.
    fn load_data_column_info(&self) -> Result<Option<DataColumnInfo>, Error> {
        self.hot_db.get(&DATA_COLUMN_INFO_KEY)
    }

    /// Store the given `data_column_info` to disk.
    ///
    /// The argument is intended to be `self.data_column_info`, but is passed manually to avoid issues
    /// with recursive locking.
    fn store_data_column_info_in_batch(
        &self,
        data_column_info: &DataColumnInfo,
    ) -> KeyValueStoreOp {
        data_column_info.as_kv_store_op(DATA_COLUMN_INFO_KEY)
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
        // become unavailable as finalisation advances due to the lack of a snapshot in the
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
        let anchor = self.anchor_info.read_recursive();
        (
            anchor.state_lower_limit,
            min(anchor.state_upper_limit, split_slot),
        )
    }

    /// Return the minimum slot such that blocks are available for all subsequent slots.
    pub fn get_oldest_block_slot(&self) -> Slot {
        self.anchor_info.read_recursive().oldest_block_slot
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

    /// Run a compaction pass to free up space used by deleted states.
    pub fn compact(&self) -> Result<(), Error> {
        self.hot_db.compact()?;
        Ok(())
    }

    /// Run a compaction pass on the freezer DB to free up space used by deleted states.
    pub fn compact_freezer(&self) -> Result<(), Error> {
        let current_schema_columns = vec![
            DBColumn::BeaconColdStateSummary,
            DBColumn::BeaconStateSnapshot,
            DBColumn::BeaconStateDiff,
            DBColumn::BeaconStateRoots,
        ];

        // We can remove this once schema V21 has been gone for a while.
        let previous_schema_columns = vec![
            DBColumn::BeaconState,
            DBColumn::BeaconStateSummary,
            DBColumn::BeaconBlockRootsChunked,
            DBColumn::BeaconStateRootsChunked,
            DBColumn::BeaconRestorePoint,
            DBColumn::BeaconHistoricalRoots,
            DBColumn::BeaconRandaoMixes,
            DBColumn::BeaconHistoricalSummaries,
        ];
        let mut columns = current_schema_columns;
        columns.extend(previous_schema_columns);

        for column in columns {
            info!(
                self.log,
                "Starting compaction";
                "column" => ?column
            );
            self.cold_db.compact_column(column)?;
            info!(
                self.log,
                "Finishing compaction";
                "column" => ?column
            );
        }
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
        for slot in start_slot.as_u64()..end_slot.as_u64() {
            ops.push(KeyValueStoreOp::PutKeyValue(
                get_key_for_col(DBColumn::BeaconBlockRoots.into(), &slot.to_be_bytes()),
                block_root.as_slice().to_vec(),
            ));
        }
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
        let anchor_slot = self.get_anchor_info().anchor_slot;

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

            if slot == anchor_slot {
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
        let anchor = self.get_anchor_info();
        if oldest_blob_slot < anchor.oldest_block_slot {
            error!(
                self.log,
                "Oldest blob is older than oldest block";
                "oldest_blob_slot" => oldest_blob_slot,
                "oldest_block_slot" => anchor.oldest_block_slot
            );
            return Err(HotColdDBError::BlobPruneLogicError.into());
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

        for res in self.forwards_block_roots_iterator_until(oldest_blob_slot, end_slot, || {
            let (_, split_state) = self
                .get_advanced_hot_state(split.block_root, split.slot, split.state_root)?
                .ok_or(HotColdDBError::MissingSplitState(
                    split.state_root,
                    split.slot,
                ))?;

            Ok((split_state, split.block_root))
        })? {
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

            if Some(block_root) != last_pruned_block_root {
                if self
                    .spec
                    .is_peer_das_enabled_for_epoch(slot.epoch(E::slots_per_epoch()))
                {
                    // data columns
                    let indices = self.get_data_column_keys(block_root)?;
                    if !indices.is_empty() {
                        trace!(
                            self.log,
                            "Pruning data columns of block";
                            "slot" => slot,
                            "block_root" => ?block_root,
                        );
                        last_pruned_block_root = Some(block_root);
                        ops.push(StoreOp::DeleteDataColumns(block_root, indices));
                    }
                } else if self.blobs_exist(&block_root)? {
                    trace!(
                        self.log,
                        "Pruning blobs of block";
                        "slot" => slot,
                        "block_root" => ?block_root,
                    );
                    last_pruned_block_root = Some(block_root);
                    ops.push(StoreOp::DeleteBlobs(block_root));
                }
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
        // Update the anchor to use the dummy state upper limit and disable historic state storage.
        let old_anchor = self.get_anchor_info();
        let new_anchor = AnchorInfo {
            state_upper_limit: STATE_UPPER_LIMIT_NO_RETAIN,
            state_lower_limit: Slot::new(0),
            ..old_anchor.clone()
        };

        // Commit the anchor change immediately: if the cold database ops fail they can always be
        // retried, and we can't do them atomically with this change anyway.
        self.compare_and_set_anchor_info_with_write(old_anchor, new_anchor)?;

        // Stage freezer data for deletion. Do not bother loading and deserializing values as this
        // wastes time and is less schema-agnostic. My hope is that this method will be useful for
        // migrating to the tree-states schema (delete everything in the freezer then start afresh).
        let mut cold_ops = vec![];

        let current_schema_columns = vec![
            DBColumn::BeaconColdStateSummary,
            DBColumn::BeaconStateSnapshot,
            DBColumn::BeaconStateDiff,
            DBColumn::BeaconStateRoots,
        ];

        // This function is intended to be able to clean up leftover V21 freezer database stuff in
        // the case where the V22 schema upgrade failed *after* commiting the version increment but
        // *before* cleaning up the freezer DB.
        //
        // We can remove this once schema V21 has been gone for a while.
        let previous_schema_columns = vec![
            DBColumn::BeaconState,
            DBColumn::BeaconStateSummary,
            DBColumn::BeaconBlockRootsChunked,
            DBColumn::BeaconStateRootsChunked,
            DBColumn::BeaconRestorePoint,
            DBColumn::BeaconHistoricalRoots,
            DBColumn::BeaconRandaoMixes,
            DBColumn::BeaconHistoricalSummaries,
        ];

        let mut columns = current_schema_columns;
        columns.extend(previous_schema_columns);

        for column in columns {
            for res in self.cold_db.iter_column_keys::<Vec<u8>>(column) {
                let key = res?;
                cold_ops.push(KeyValueStoreOp::DeleteKey(get_key_for_col(
                    column.as_str(),
                    &key,
                )));
            }
        }
        let delete_ops = cold_ops.len();

        // If we just deleted the genesis state, re-store it using the current* schema.
        if self.get_split_slot() > 0 {
            info!(
                self.log,
                "Re-storing genesis state";
                "state_root" => ?genesis_state_root,
            );
            self.store_cold_state(&genesis_state_root, genesis_state, &mut cold_ops)?;
        }

        info!(
            self.log,
            "Deleting historic states";
            "delete_ops" => delete_ops,
        );
        self.cold_db.do_atomically(cold_ops)?;

        // In order to reclaim space, we need to compact the freezer DB as well.
        self.compact_freezer()?;

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

    if finalized_state.slot() < current_split_slot {
        return Err(HotColdDBError::FreezeSlotError {
            current_split_slot,
            proposed_split_slot: finalized_state.slot(),
        }
        .into());
    }

    // finalized_state.slot() must be at an epoch boundary
    // else we may introduce bugs to the migration/pruning logic
    if finalized_state.slot() % E::slots_per_epoch() != 0 {
        return Err(HotColdDBError::FreezeSlotUnaligned(finalized_state.slot()).into());
    }

    let mut hot_db_ops = vec![];
    let mut cold_db_block_ops = vec![];
    let mut epoch_boundary_blocks = HashSet::new();
    let mut non_checkpoint_block_roots = HashSet::new();

    // Iterate in descending order until the current split slot
    let state_roots = RootsIterator::new(&store, finalized_state)
        .take_while(|result| match result {
            Ok((_, _, slot)) => *slot >= current_split_slot,
            Err(_) => true,
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Then, iterate states in slot ascending order, as they are stored wrt previous states.
    for (block_root, state_root, slot) in state_roots.into_iter().rev() {
        // Delete the execution payload if payload pruning is enabled. At a skipped slot we may
        // delete the payload for the finalized block itself, but that's OK as we only guarantee
        // that payloads are present for slots >= the split slot. The payload fetching code is also
        // forgiving of missing payloads.
        if store.config.prune_payloads {
            hot_db_ops.push(StoreOp::DeleteExecutionPayload(block_root));
        }

        // Store the slot to block root mapping.
        cold_db_block_ops.push(KeyValueStoreOp::PutKeyValue(
            get_key_for_col(
                DBColumn::BeaconBlockRoots.into(),
                &slot.as_u64().to_be_bytes(),
            ),
            block_root.as_slice().to_vec(),
        ));

        // At a missed slot, `state_root_iter` will return the block root
        // from the previous non-missed slot. This ensures that the block root at an
        // epoch boundary is always a checkpoint block root. We keep track of block roots
        // at epoch boundaries by storing them in the `epoch_boundary_blocks` hash set.
        // We then ensure that block roots at the epoch boundary aren't included in the
        // `non_checkpoint_block_roots` hash set.
        if slot % E::slots_per_epoch() == 0 {
            epoch_boundary_blocks.insert(block_root);
        } else {
            non_checkpoint_block_roots.insert(block_root);
        }

        if epoch_boundary_blocks.contains(&block_root) {
            non_checkpoint_block_roots.remove(&block_root);
        }

        // Delete the old summary, and the full state if we lie on an epoch boundary.
        hot_db_ops.push(StoreOp::DeleteState(state_root, Some(slot)));

        // Do not try to store states if a restore point is yet to be stored, or will never be
        // stored (see `STATE_UPPER_LIMIT_NO_RETAIN`). Make an exception for the genesis state
        // which always needs to be copied from the hot DB to the freezer and should not be deleted.
        if slot != 0 && slot < anchor_info.state_upper_limit {
            debug!(store.log, "Pruning finalized state"; "slot" => slot);
            continue;
        }

        let mut cold_db_ops = vec![];

        // Only store the cold state if it's on a diff boundary.
        // Calling `store_cold_state_summary` instead of `store_cold_state` for those allows us
        // to skip loading many hot states.
        if matches!(
            store.hierarchy.storage_strategy(slot)?,
            StorageStrategy::ReplayFrom(..)
        ) {
            // Store slot -> state_root and state_root -> slot mappings.
            store.store_cold_state_summary(&state_root, slot, &mut cold_db_ops)?;
        } else {
            let state: BeaconState<E> = store
                .get_hot_state(&state_root)?
                .ok_or(HotColdDBError::MissingStateToFreeze(state_root))?;

            store.store_cold_state(&state_root, &state, &mut cold_db_ops)?;
        }

        // Cold states are diffed with respect to each other, so we need to finish writing previous
        // states before storing new ones.
        store.cold_db.do_atomically(cold_db_ops)?;
    }

    // Prune sync committee branch data for all non checkpoint block roots.
    // Note that `non_checkpoint_block_roots` should only contain non checkpoint block roots
    // as long as `finalized_state.slot()` is at an epoch boundary. If this were not the case
    // we risk the chance of pruning a `sync_committee_branch` for a checkpoint block root.
    // E.g. if `current_split_slot` = (Epoch A slot 0) and `finalized_state.slot()` = (Epoch C slot 31)
    // and (Epoch D slot 0) is a skipped slot, we will have pruned a `sync_committee_branch`
    // for a checkpoint block root.
    non_checkpoint_block_roots
        .into_iter()
        .for_each(|block_root| {
            hot_db_ops.push(StoreOp::DeleteSyncCommitteeBranch(block_root));
        });

    // Warning: Critical section.  We have to take care not to put any of the two databases in an
    //          inconsistent state if the OS process dies at any point during the freezing
    //          procedure.
    //
    // Since it is pretty much impossible to be atomic across more than one database, we trade
    // losing track of states to delete, for consistency.  In other words: We should be safe to die
    // at any point below but it may happen that some states won't be deleted from the hot database
    // and will remain there forever.  Since dying in these particular few lines should be an
    // exceedingly rare event, this should be an acceptable tradeoff.
    store.cold_db.do_atomically(cold_db_block_ops)?;
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
        DBColumn::BeaconColdStateSummary
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
