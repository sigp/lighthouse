use crate::config::{OnDiskStoreConfig, StoreConfig};
use crate::database::interface::BeaconNodeBackend;
use crate::forwards_iter::{HybridForwardsBlockRootsIterator, HybridForwardsStateRootsIterator};
use crate::hdiff::{HDiff, HDiffBuffer, HierarchyConfig, HierarchyModuli, StorageStrategy};
use crate::historic_state_cache::HistoricStateCache;
use crate::iter::{BlockRootsIterator, ParentRootBlockIterator, RootsIterator};
use crate::memory_store::MemoryStore;
use crate::metadata::{
    ANCHOR_INFO_KEY, ANCHOR_UNINITIALIZED, AnchorInfo, BLOB_INFO_KEY, BlobInfo,
    COMPACTION_TIMESTAMP_KEY, CONFIG_KEY, CURRENT_SCHEMA_VERSION, CompactionTimestamp,
    DATA_COLUMN_CUSTODY_INFO_KEY, DATA_COLUMN_INFO_KEY, DataColumnCustodyInfo, DataColumnInfo,
    SCHEMA_VERSION_KEY, SPLIT_KEY, STATE_UPPER_LIMIT_NO_RETAIN, SchemaVersion,
};
use crate::state_cache::{PutStateOutcome, StateCache};
use crate::{
    BlobSidecarListFromRoot, DBColumn, DatabaseBlock, Error, ItemStore, KeyValueStoreOp, StoreItem,
    StoreOp, get_data_column_key,
    metrics::{self, COLD_METRIC, HOT_METRIC},
    parse_data_column_key,
};
use itertools::{Itertools, process_results};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use safe_arith::SafeArith;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    AllCaches, BlockProcessingError, BlockReplayer, SlotProcessingError,
    block_replayer::PreSlotHook,
};
use std::cmp::{Ordering, min};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};
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
    pub hierarchy: HierarchyModuli,
    /// Cold database containing compact historical data.
    pub cold_db: Cold,
    /// Database containing blobs. If None, store falls back to use `cold_db`.
    pub blobs_db: Cold,
    /// Hot database containing duplicated but quick-to-access recent data.
    ///
    /// The hot database also contains all blocks.
    pub hot_db: Hot,
    /// LRU cache of deserialized blocks and blobs. Updated whenever a block or blob is loaded.
    block_cache: Option<Mutex<BlockCache<E>>>,
    /// Cache of beacon states.
    ///
    /// LOCK ORDERING: this lock must always be locked *after* the `split` if both are required.
    pub state_cache: Mutex<StateCache<E>>,
    /// Cache of historic states and hierarchical diff buffers.
    ///
    /// This cache is never pruned. It is only populated in response to historical queries from the
    /// HTTP API.
    historic_state_cache: Mutex<HistoricStateCache<E>>,
    /// Chain spec.
    pub spec: Arc<ChainSpec>,
    /// Mere vessel for E.
    _phantom: PhantomData<E>,
}

#[derive(Debug)]
struct BlockCache<E: EthSpec> {
    block_cache: LruCache<Hash256, SignedBeaconBlock<E>>,
    blob_cache: LruCache<Hash256, BlobSidecarList<E>>,
    data_column_cache: LruCache<Hash256, HashMap<ColumnIndex, Arc<DataColumnSidecar<E>>>>,
    data_column_custody_info_cache: Option<DataColumnCustodyInfo>,
}

impl<E: EthSpec> BlockCache<E> {
    pub fn new(size: NonZeroUsize) -> Self {
        Self {
            block_cache: LruCache::new(size),
            blob_cache: LruCache::new(size),
            data_column_cache: LruCache::new(size),
            data_column_custody_info_cache: None,
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
    pub fn put_data_column_custody_info(
        &mut self,
        data_column_custody_info: Option<DataColumnCustodyInfo>,
    ) {
        self.data_column_custody_info_cache = data_column_custody_info;
    }
    pub fn get_block<'a>(&'a mut self, block_root: &Hash256) -> Option<&'a SignedBeaconBlock<E>> {
        self.block_cache.get(block_root)
    }
    pub fn get_blobs<'a>(&'a mut self, block_root: &Hash256) -> Option<&'a BlobSidecarList<E>> {
        self.blob_cache.get(block_root)
    }
    // Note: data columns are all individually cached, hence there's no guarantee that
    // `data_column_cache.get(block_root)` will return all custody columns.
    pub fn get_data_column(
        &mut self,
        block_root: &Hash256,
        column_index: &ColumnIndex,
    ) -> Option<Arc<DataColumnSidecar<E>>> {
        self.data_column_cache
            .get(block_root)
            .and_then(|map| map.get(column_index).cloned())
    }
    pub fn get_data_column_custody_info(&self) -> Option<DataColumnCustodyInfo> {
        self.data_column_custody_info_cache.clone()
    }
    pub fn delete_block(&mut self, block_root: &Hash256) {
        let _ = self.block_cache.pop(block_root);
    }
    pub fn delete_blobs(&mut self, block_root: &Hash256) {
        let _ = self.blob_cache.pop(block_root);
    }
    pub fn delete_data_columns(&mut self, block_root: &Hash256) {
        let _ = self.data_column_cache.pop(block_root);
    }
    pub fn delete(&mut self, block_root: &Hash256) {
        self.delete_block(block_root);
        self.delete_blobs(block_root);
        self.delete_data_columns(block_root);
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
    MissingEpochBoundaryState(Hash256, Hash256),
    MissingHotState {
        state_root: Hash256,
        requested_by_state_summary: (Hash256, Slot),
    },
    MissingPrevState(Hash256),
    MissingSplitState(Hash256, Slot),
    MissingHotHDiff(Hash256),
    MissingHDiff(Slot),
    MissingExecutionPayload(Hash256),
    MissingFullBlockExecutionPayloadPruned(Hash256, Slot),
    MissingAnchorInfo,
    MissingFrozenBlockSlot(Hash256),
    MissingFrozenBlock(Slot),
    MissingPathToBlobsDatabase,
    BlobsPreviouslyInDefaultStore,
    HdiffGetPriorStateRootError(Slot, Slot),
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
    ) -> Result<HotColdDB<E, MemoryStore<E>, MemoryStore<E>>, Error> {
        config.verify::<E>()?;

        let hierarchy = config.hierarchy_config.to_moduli()?;

        // NOTE: Anchor slot is initialized to 0, which is only valid for new DBs. We shouldn't
        // be reusing memory stores, but if we want to do that we should redo this.
        let db = HotColdDB {
            split: RwLock::new(Split::default()),
            anchor_info: RwLock::new(ANCHOR_UNINITIALIZED),
            blob_info: RwLock::new(BlobInfo::default()),
            data_column_info: RwLock::new(DataColumnInfo::default()),
            cold_db: MemoryStore::open(),
            blobs_db: MemoryStore::open(),
            hot_db: MemoryStore::open(),
            block_cache: NonZeroUsize::new(config.block_cache_size)
                .map(BlockCache::new)
                .map(Mutex::new),
            state_cache: Mutex::new(StateCache::new(
                config.state_cache_size,
                config.state_cache_headroom,
                config.hot_hdiff_buffer_cache_size,
            )),
            historic_state_cache: Mutex::new(HistoricStateCache::new(
                config.cold_hdiff_buffer_cache_size,
                config.historic_state_cache_size,
            )),
            config,
            hierarchy,
            spec,
            _phantom: PhantomData,
        };

        Ok(db)
    }
}

impl<E: EthSpec> HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>> {
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
    ) -> Result<Arc<Self>, Error> {
        debug!("Opening HotColdDB");
        config.verify::<E>()?;

        let hierarchy = config.hierarchy_config.to_moduli()?;

        debug!(?hot_path, "Opening LevelDB");
        let hot_db = BeaconNodeBackend::open(&config, hot_path)?;

        let anchor_info = RwLock::new(Self::load_anchor_info(&hot_db)?);
        debug!(?anchor_info, "Loaded anchor info");

        let db = HotColdDB {
            split: RwLock::new(Split::default()),
            anchor_info,
            blob_info: RwLock::new(BlobInfo::default()),
            data_column_info: RwLock::new(DataColumnInfo::default()),
            blobs_db: BeaconNodeBackend::open(&config, blobs_db_path)?,
            cold_db: BeaconNodeBackend::open(&config, cold_path)?,
            hot_db,
            block_cache: NonZeroUsize::new(config.block_cache_size)
                .map(BlockCache::new)
                .map(Mutex::new),
            state_cache: Mutex::new(StateCache::new(
                config.state_cache_size,
                config.state_cache_headroom,
                config.hot_hdiff_buffer_cache_size,
            )),
            historic_state_cache: Mutex::new(HistoricStateCache::new(
                config.cold_hdiff_buffer_cache_size,
                config.historic_state_cache_size,
            )),
            config,
            hierarchy,
            spec,
            _phantom: PhantomData,
        };
        // Load the config from disk but don't error on a failed read because the config itself may
        // need migrating.
        let _ = db.load_config();

        // Load the previous split slot from the database (if any). This ensures we can
        // stop and restart correctly. This needs to occur *before* running any migrations
        // because some migrations load states and depend on the split.
        //
        // We use a method that is ambivalent to the state summaries being V22 or V24, because
        // we need to support several scenarios:
        //
        // - Migrating from V22 to V24: initially summaries are V22 , and we need
        //   to be able to load a block root from them. Loading the split partially at first
        //   (without reading a V24 summary) and then completing the full load after the migration
        //   runs is possible in this case, but not in the next case.
        // - Migrating from V24 to V22: initially summaries are V24, but after the migration runs
        //   they will be V22. If we used the "load full split after migration" approach with strict
        //   V24 summaries, it would break when trying to read V22 summaries after the migration.
        //
        // Therefore we take the most flexible approach of reading _either_ a V22 or V24 summary and
        // using this to load the split correctly the first time.
        if let Some(split) = db.load_split()? {
            *db.split.write() = split;

            info!(
                %split.slot,
                ?split.state_root,
                ?split.block_root,
                "Hot-Cold DB initialized"
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
        let fulu_fork_slot = db
            .spec
            .fulu_fork_epoch
            .map(|epoch| epoch.start_slot(E::slots_per_epoch()));
        let new_data_column_info = match &data_column_info {
            Some(data_column_info) => {
                // Set the oldest data column slot to the fork slot if it is not yet set.
                let oldest_data_column_slot =
                    data_column_info.oldest_data_column_slot.or(fulu_fork_slot);
                DataColumnInfo {
                    oldest_data_column_slot,
                }
            }
            // First start.
            None => DataColumnInfo {
                // Set the oldest data column slot to the fork slot if it is not yet set.
                oldest_data_column_slot: fulu_fork_slot,
            },
        };
        db.compare_and_set_data_column_info_with_write(
            <_>::default(),
            new_data_column_info.clone(),
        )?;

        info!(
            path = ?blobs_db_path,
            oldest_blob_slot = ?new_blob_info.oldest_blob_slot,
            oldest_data_column_slot = ?new_data_column_info.oldest_data_column_slot,
            "Blob DB initialized"
        );

        // Ensure that any on-disk config is compatible with the supplied config.
        //
        // We do this prior to the migration now, because we don't want the migration using the
        // in-memory config if it is inconsistent with the on-disk config. In future we may need
        // to put this in/after the migration if the migration changes the config format.
        if let Some(disk_config) = db.load_config()? {
            db.config.check_compatibility(&disk_config)?;
        }
        db.store_config()?;

        // Ensure that the schema version of the on-disk database matches the software.
        // If the version is mismatched, an automatic migration will be attempted.
        let db = Arc::new(db);
        if let Some(schema_version) = db.load_schema_version()? {
            debug!(
                from_version = schema_version.as_u64(),
                to_version = CURRENT_SCHEMA_VERSION.as_u64(),
                "Attempting schema migration"
            );
            migrate_schema(db.clone(), schema_version, CURRENT_SCHEMA_VERSION).map_err(|e| {
                Error::MigrationError(format!(
                    "Migrating from {:?} to {:?}: {:?}",
                    schema_version, CURRENT_SCHEMA_VERSION, e
                ))
            })?;
        } else {
            db.store_schema_version(CURRENT_SCHEMA_VERSION)?;
        }

        // TODO(tree-states): Here we can choose to prune advanced states to reclaim disk space. As
        // it's a foreground task there's no risk of race condition that can corrupt the DB.
        // Advanced states for invalid blocks that were never written to the DB, or descendants of
        // heads can be safely pruned at the expense of potentially having to recompute them in the
        // future. However this would require a new dedicated pruning routine.

        // If configured, run a foreground compaction pass.
        if db.config.compact_on_init {
            info!("Running foreground compaction");
            db.compact()?;
            info!("Foreground compaction complete");
        }

        debug!(anchor = ?db.get_anchor_info(), "Store anchor info");

        Ok(db)
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> HotColdDB<E, Hot, Cold> {
    fn cold_storage_strategy(&self, slot: Slot) -> Result<StorageStrategy, Error> {
        // The start slot for the freezer HDiff is always 0
        Ok(self.hierarchy.storage_strategy(slot, Slot::new(0))?)
    }

    pub fn hot_storage_strategy(&self, slot: Slot) -> Result<StorageStrategy, Error> {
        Ok(self
            .hierarchy
            .storage_strategy(slot, self.hot_hdiff_start_slot()?)?)
    }

    pub fn hot_hdiff_start_slot(&self) -> Result<Slot, Error> {
        let anchor_slot = self.anchor_info.read_recursive().anchor_slot;
        if anchor_slot == u64::MAX {
            // If hot_hdiff_start_slot returns such a high value all writes will fail. This should
            // never happen, but it's best to stop this useless value from propagating downstream
            Err(Error::AnchorUninitialized)
        } else {
            Ok(anchor_slot)
        }
    }

    pub fn update_finalized_state(
        &self,
        state_root: Hash256,
        block_root: Hash256,
        state: BeaconState<E>,
    ) -> Result<(), Error> {
        let start_slot = self.get_anchor_info().anchor_slot;
        let pre_finalized_slots_to_retain = self
            .hierarchy
            .closest_layer_points(state.slot(), start_slot);
        self.state_cache.lock().update_finalized_state(
            state_root,
            block_root,
            state,
            &pre_finalized_slots_to_retain,
        )
    }

    pub fn state_cache_len(&self) -> usize {
        self.state_cache.lock().len()
    }

    pub fn register_metrics(&self) {
        let hsc_metrics = self.historic_state_cache.lock().metrics();

        if let Some(block_cache) = &self.block_cache {
            let cache = block_cache.lock();
            metrics::set_gauge(
                &metrics::STORE_BEACON_BLOCK_CACHE_SIZE,
                cache.block_cache.len() as i64,
            );
            metrics::set_gauge(
                &metrics::STORE_BEACON_BLOB_CACHE_SIZE,
                cache.blob_cache.len() as i64,
            );
        }
        let state_cache = self.state_cache.lock();
        metrics::set_gauge(
            &metrics::STORE_BEACON_STATE_CACHE_SIZE,
            state_cache.len() as i64,
        );
        metrics::set_gauge_vec(
            &metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_SIZE,
            HOT_METRIC,
            state_cache.num_hdiff_buffers() as i64,
        );
        metrics::set_gauge_vec(
            &metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_BYTE_SIZE,
            HOT_METRIC,
            state_cache.hdiff_buffer_mem_usage() as i64,
        );
        drop(state_cache);
        metrics::set_gauge(
            &metrics::STORE_BEACON_HISTORIC_STATE_CACHE_SIZE,
            hsc_metrics.num_state as i64,
        );
        metrics::set_gauge_vec(
            &metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_SIZE,
            COLD_METRIC,
            hsc_metrics.num_hdiff as i64,
        );
        metrics::set_gauge_vec(
            &metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_BYTE_SIZE,
            COLD_METRIC,
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
        self.block_cache
            .as_ref()
            .inspect(|cache| cache.lock().put_block(*block_root, block));
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

    /// Prepare a signed beacon block for storage in the database *without* its payload.
    pub fn blinded_block_as_kv_store_ops(
        &self,
        key: &Hash256,
        blinded_block: &SignedBeaconBlock<E, BlindedPayload<E>>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) {
        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconBlock,
            key.as_slice().into(),
            blinded_block.as_ssz_bytes(),
        ));
    }

    pub fn try_get_full_block(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<DatabaseBlock<E>>, Error> {
        metrics::inc_counter(&metrics::BEACON_BLOCK_GET_COUNT);

        // Check the cache.
        if let Some(cache) = &self.block_cache
            && let Some(block) = cache.lock().get_block(block_root)
        {
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
                .as_ref()
                .inspect(|cache| cache.lock().put_block(*block_root, full_block.clone()));

            DatabaseBlock::Full(full_block)
        } else if !self.config.prune_payloads || *block_root == split.block_root {
            // If payload pruning is disabled there's a chance we may have the payload of
            // this finalized block. Attempt to load it but don't error in case it's missing.
            //
            // We also allow for the split block's payload to be loaded *if it exists*. This is
            // necessary on startup when syncing from an unaligned checkpoint (a checkpoint state
            // at a skipped slot), and then loading the canonical head (with payload). If we modify
            // payload pruning in future so that it doesn't prune the split block's payload, then
            // this case could move to the case above where we error if the payload is missing.
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
    #[instrument(skip_all)]
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
            .get_bytes(DBColumn::BeaconBlock, block_root.as_slice())?
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
        let key = block_root.as_slice();

        match self
            .hot_db
            .get_bytes(ExecutionPayload::<E>::db_column(), key)?
        {
            Some(bytes) => Ok(Some(ExecutionPayload::from_ssz_bytes_by_fork(
                &bytes, fork_name,
            )?)),
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

        if let Some(bytes) = self.hot_db.get_bytes(column, &block_root.as_ssz_bytes())? {
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
            .get_bytes(column, &sync_committee_period.as_ssz_bytes())?
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
            column,
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
            column,
            &sync_committee_period.to_le_bytes(),
            &sync_committee.as_ssz_bytes(),
        )?;

        Ok(())
    }

    pub fn get_light_client_update(
        &self,
        sync_committee_period: u64,
    ) -> Result<Option<LightClientUpdate<E>>, Error> {
        let res = self.hot_db.get_bytes(
            DBColumn::LightClientUpdate,
            &sync_committee_period.to_le_bytes(),
        )?;

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
        self.hot_db.put_bytes(
            DBColumn::LightClientUpdate,
            &sync_committee_period.to_le_bytes(),
            &light_client_update.as_ssz_bytes(),
        )?;

        Ok(())
    }

    /// Check if the blobs for a block exists on disk.
    pub fn blobs_exist(&self, block_root: &Hash256) -> Result<bool, Error> {
        self.blobs_db
            .key_exists(DBColumn::BeaconBlob, block_root.as_slice())
    }

    /// Determine whether a block exists in the database.
    pub fn block_exists(&self, block_root: &Hash256) -> Result<bool, Error> {
        self.hot_db
            .key_exists(DBColumn::BeaconBlock, block_root.as_slice())
    }

    /// Delete a block from the store and the block cache.
    pub fn delete_block(&self, block_root: &Hash256) -> Result<(), Error> {
        self.block_cache
            .as_ref()
            .inspect(|cache| cache.lock().delete(block_root));
        self.hot_db
            .key_delete(DBColumn::BeaconBlock, block_root.as_slice())?;
        self.hot_db
            .key_delete(DBColumn::ExecPayload, block_root.as_slice())?;
        self.blobs_db
            .key_delete(DBColumn::BeaconBlob, block_root.as_slice())
    }

    pub fn put_blobs(&self, block_root: &Hash256, blobs: BlobSidecarList<E>) -> Result<(), Error> {
        self.blobs_db.put_bytes(
            DBColumn::BeaconBlob,
            block_root.as_slice(),
            &blobs.as_ssz_bytes(),
        )?;
        self.block_cache
            .as_ref()
            .inspect(|cache| cache.lock().put_blobs(*block_root, blobs));
        Ok(())
    }

    pub fn blobs_as_kv_store_ops(
        &self,
        key: &Hash256,
        blobs: BlobSidecarList<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) {
        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconBlob,
            key.as_slice().to_vec(),
            blobs.as_ssz_bytes(),
        ));
    }

    pub fn data_column_as_kv_store_ops(
        &self,
        block_root: &Hash256,
        data_column: Arc<DataColumnSidecar<E>>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) {
        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconDataColumn,
            get_data_column_key(block_root, &data_column.index),
            data_column.as_ssz_bytes(),
        ));
    }

    pub fn put_data_column_custody_info(
        &self,
        earliest_data_column_slot: Option<Slot>,
    ) -> Result<(), Error> {
        let data_column_custody_info = DataColumnCustodyInfo {
            earliest_data_column_slot,
        };

        self.blobs_db
            .put(&DATA_COLUMN_CUSTODY_INFO_KEY, &data_column_custody_info)?;

        self.block_cache.as_ref().inspect(|cache| {
            cache
                .lock()
                .put_data_column_custody_info(Some(data_column_custody_info))
        });

        Ok(())
    }

    pub fn put_data_columns(
        &self,
        block_root: &Hash256,
        data_columns: DataColumnSidecarList<E>,
    ) -> Result<(), Error> {
        for data_column in data_columns {
            self.blobs_db.put_bytes(
                DBColumn::BeaconDataColumn,
                &get_data_column_key(block_root, &data_column.index),
                &data_column.as_ssz_bytes(),
            )?;
            self.block_cache
                .as_ref()
                .inspect(|cache| cache.lock().put_data_column(*block_root, data_column));
        }
        Ok(())
    }

    pub fn data_columns_as_kv_store_ops(
        &self,
        block_root: &Hash256,
        data_columns: DataColumnSidecarList<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) {
        for data_column in data_columns {
            ops.push(KeyValueStoreOp::PutKeyValue(
                DBColumn::BeaconDataColumn,
                get_data_column_key(block_root, &data_column.index),
                data_column.as_ssz_bytes(),
            ));
        }
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
        update_cache: bool,
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
                self.get_hot_state(state_root, update_cache)
            }
        } else {
            match self.get_hot_state(state_root, update_cache)? {
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
    #[instrument(skip_all, fields(?block_root, %max_slot, ?state_root), level = "debug")]
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
            warn!(?state_root, ?block_root, "State cache missed");
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
        // It's a bit redundant but we elect to cache the state here and down below.
        let mut opt_state = self
            .load_hot_state(&state_root, true)
            .map_err(|e| {
                Error::LoadingHotStateError(
                    format!("get advanced {block_root} {max_slot}"),
                    state_root,
                    e.into(),
                )
            })?
            .map(|(state, _block_root)| (state_root, state));

        if let Some((state_root, state)) = opt_state.as_mut() {
            state.update_tree_hash_cache()?;
            state.build_all_caches(&self.spec)?;
            if let PutStateOutcome::New(deleted_states) =
                self.state_cache
                    .lock()
                    .put_state(*state_root, block_root, state)?
            {
                debug!(
                    ?state_root,
                    state_slot = %state.slot(),
                    ?deleted_states,
                    location = "get_advanced_hot_state",
                    "Cached state",
                );
            }
        }
        drop(split);
        Ok(opt_state)
    }

    /// Same as `get_advanced_hot_state` but will return `None` if no compatible state is cached.
    ///
    /// If this function returns `Some(state)` then that `state` will always have
    /// `latest_block_header` matching `block_root` but may not be advanced all the way through to
    /// `max_slot`.
    #[instrument(skip_all, fields(?block_root, %max_slot), level = "debug")]
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
    ) -> Result<HybridForwardsBlockRootsIterator<'_, E, Hot, Cold>, Error> {
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
    ) -> Result<HybridForwardsStateRootsIterator<'_, E, Hot, Cold>, Error> {
        HybridForwardsStateRootsIterator::new(
            self,
            DBColumn::BeaconStateRoots,
            start_slot,
            Some(end_slot),
            get_state,
        )
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

                StoreOp::DeleteBlock(block_root) => {
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(
                        DBColumn::BeaconBlock,
                        block_root.as_slice().to_vec(),
                    ));
                }

                StoreOp::DeleteBlobs(block_root) => {
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(
                        DBColumn::BeaconBlob,
                        block_root.as_slice().to_vec(),
                    ));
                }

                StoreOp::DeleteDataColumns(block_root, column_indices) => {
                    for index in column_indices {
                        let key = get_data_column_key(&block_root, &index);
                        key_value_batch
                            .push(KeyValueStoreOp::DeleteKey(DBColumn::BeaconDataColumn, key));
                    }
                }

                StoreOp::DeleteState(state_root, slot) => {
                    // Delete the hot state summary.
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(
                        DBColumn::BeaconStateHotSummary,
                        state_root.as_slice().to_vec(),
                    ));

                    if let Some(slot) = slot {
                        match self.hot_storage_strategy(slot)? {
                            StorageStrategy::Snapshot => {
                                // Full state stored in this position
                                key_value_batch.push(KeyValueStoreOp::DeleteKey(
                                    DBColumn::BeaconStateHotSnapshot,
                                    state_root.as_slice().to_vec(),
                                ));
                            }
                            StorageStrategy::DiffFrom(_) => {
                                // Diff stored in this position
                                key_value_batch.push(KeyValueStoreOp::DeleteKey(
                                    DBColumn::BeaconStateHotDiff,
                                    state_root.as_slice().to_vec(),
                                ));
                            }
                            StorageStrategy::ReplayFrom(_) => {
                                // Nothing else to delete
                            }
                        }
                    } else {
                        // NOTE(hdiff): Attempt to delete both snapshots and diffs if we don't know
                        // the slot.
                        key_value_batch.push(KeyValueStoreOp::DeleteKey(
                            DBColumn::BeaconStateHotSnapshot,
                            state_root.as_slice().to_vec(),
                        ));
                        key_value_batch.push(KeyValueStoreOp::DeleteKey(
                            DBColumn::BeaconStateHotDiff,
                            state_root.as_slice().to_vec(),
                        ));
                    }
                }

                StoreOp::DeleteExecutionPayload(block_root) => {
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(
                        DBColumn::ExecPayload,
                        block_root.as_slice().to_vec(),
                    ));
                }

                StoreOp::DeleteSyncCommitteeBranch(block_root) => {
                    key_value_batch.push(KeyValueStoreOp::DeleteKey(
                        DBColumn::SyncCommitteeBranch,
                        block_root.as_slice().to_vec(),
                    ));
                }

                StoreOp::KeyValueOp(kv_op) => {
                    key_value_batch.push(kv_op);
                }
            }
        }
        Ok(key_value_batch)
    }

    pub fn delete_batch(&self, col: DBColumn, ops: Vec<Hash256>) -> Result<(), Error> {
        let new_ops: HashSet<&[u8]> = ops.iter().map(|v| v.as_slice()).collect();
        self.hot_db.delete_batch(col, new_ops)
    }

    pub fn delete_if(
        &self,
        column: DBColumn,
        f: impl Fn(&[u8]) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        self.hot_db.delete_if(column, f)
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
                        Ok(BlobSidecarListFromRoot::Blobs(blob_sidecar_list)) => {
                            blobs_to_delete.push((*block_root, blob_sidecar_list));
                        }
                        Ok(BlobSidecarListFromRoot::NoBlobs | BlobSidecarListFromRoot::NoRoot) => {}
                        Err(e) => {
                            error!(
                                %block_root,
                                error = ?e,
                                "Error getting blobs"
                            );
                        }
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
                                %block_root,
                                error = ?e,
                                "Error getting data columns"
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
        let guard = self.block_cache.as_ref().map(|cache| cache.lock());

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
                error = ?e,
                action = "reverting blob DB changes",
                "Database write failed"
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

        // Delete from the state cache.
        for op in &hot_db_cache_ops {
            match op {
                StoreOp::DeleteBlock(block_root) => {
                    self.state_cache.lock().delete_block_states(block_root);
                }
                StoreOp::DeleteState(state_root, _) => {
                    self.state_cache.lock().delete_state(state_root)
                }
                _ => (),
            }
        }

        // If the block cache is enabled, also delete from the block cache.
        if let Some(mut guard) = guard {
            for op in hot_db_cache_ops {
                match op {
                    StoreOp::PutBlock(block_root, block) => {
                        guard.put_block(block_root, (*block).clone());
                    }

                    StoreOp::PutBlobs(_, _) => (),

                    StoreOp::PutDataColumns(_, _) => (),

                    StoreOp::PutState(_, _) => (),

                    StoreOp::PutStateSummary(_, _) => (),

                    StoreOp::DeleteBlock(block_root) => {
                        guard.delete_block(&block_root);
                    }

                    StoreOp::DeleteState(_, _) => (),

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
        match self.state_cache.lock().put_state(
            *state_root,
            state.get_latest_block_root(*state_root),
            state,
        )? {
            PutStateOutcome::New(deleted_states) => {
                debug!(
                    ?state_root,
                    state_slot = %state.slot(),
                    ?deleted_states,
                    location = "store_hot_state",
                    "Cached state",
                );
            }
            PutStateOutcome::Duplicate => {
                debug!(
                    ?state_root,
                    state_slot = %state.slot(),
                    "State already exists in state cache",
                );
                // NOTE: We used to return early here, but had some issues with states being
                // in the cache but not on disk. Instead of relying on the cache we try loading
                // the state summary below and rely on that instead.
            }
            // Continue to store.
            PutStateOutcome::Finalized | PutStateOutcome::PreFinalizedHDiffBuffer => {}
        }

        // Computing diffs is expensive so we avoid it if we already have this state stored on
        // disk.
        if self.load_hot_state_summary(state_root)?.is_some() {
            debug!(
                slot = %state.slot(),
                ?state_root,
                "Skipping storage of state already in the DB"
            );
            return Ok(());
        }

        let summary = self.store_hot_state_summary(state_root, state, ops)?;
        self.store_hot_state_diffs(state_root, state, ops)?;

        debug!(
            ?state_root,
            slot = %state.slot(),
            storage_strategy = ?self.hot_storage_strategy(state.slot())?,
            diff_base_state = %summary.diff_base_state,
            previous_state_root = ?summary.previous_state_root,
            "Storing hot state summary and diffs"
        );

        Ok(())
    }

    /// Store a post-finalization state efficiently in the hot database.
    pub fn store_hot_state_summary(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<HotStateSummary, Error> {
        // Store a summary of the state.
        // We store one even for the epoch boundary states, as we may need their slots
        // when doing a look up by state root.
        let hot_state_summary = HotStateSummary::new(
            self,
            *state_root,
            state,
            self.hot_storage_strategy(state.slot())?,
        )?;
        ops.push(hot_state_summary.as_kv_store_op(*state_root));
        Ok(hot_state_summary)
    }

    pub fn store_hot_state_diffs(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        let slot = state.slot();
        let storage_strategy = self.hot_storage_strategy(slot)?;
        match storage_strategy {
            StorageStrategy::ReplayFrom(_) => {
                // Already have persisted the state summary, don't persist anything else
            }
            StorageStrategy::Snapshot => {
                self.store_hot_state_as_snapshot(state_root, state, ops)?;
            }
            StorageStrategy::DiffFrom(from_slot) => {
                let from_root = get_ancestor_state_root(self, state, from_slot).map_err(|e| {
                    Error::StateSummaryIteratorError {
                        error: e,
                        from_state_root: *state_root,
                        from_state_slot: state.slot(),
                        target_slot: slot,
                    }
                })?;
                self.store_hot_state_as_diff(state_root, state, from_root, ops)?;
            }
        }
        Ok(())
    }

    fn store_hot_state_as_diff(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
        from_root: Hash256,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        let base_buffer = {
            let _t = metrics::start_timer_vec(
                &metrics::BEACON_HDIFF_BUFFER_LOAD_BEFORE_STORE_TIME,
                HOT_METRIC,
            );
            self.load_hot_hdiff_buffer(from_root).map_err(|e| {
                Error::LoadingHotHdiffBufferError(
                    format!("store state as diff {state_root:?} {}", state.slot()),
                    from_root,
                    e.into(),
                )
            })?
        };
        let target_buffer = HDiffBuffer::from_state(state.clone());
        let diff = {
            let _timer = metrics::start_timer_vec(&metrics::BEACON_HDIFF_COMPUTE_TIME, HOT_METRIC);
            HDiff::compute(&base_buffer, &target_buffer, &self.config)?
        };
        let diff_bytes = diff.as_ssz_bytes();
        let layer = HierarchyConfig::exponent_for_slot(state.slot());
        metrics::observe_vec(
            &metrics::BEACON_HDIFF_SIZES,
            &[&layer.to_string()],
            diff_bytes.len() as f64,
        );
        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconStateHotDiff,
            state_root.as_slice().to_vec(),
            diff_bytes,
        ));
        Ok(())
    }

    /// Get a post-finalization state from the database or store.
    pub fn get_hot_state(
        &self,
        state_root: &Hash256,
        update_cache: bool,
    ) -> Result<Option<BeaconState<E>>, Error> {
        if let Some(state) = self.state_cache.lock().get_by_state_root(*state_root) {
            return Ok(Some(state));
        }

        if *state_root != self.get_split_info().state_root {
            // Do not warn on start up when loading the split state.
            warn!(?state_root, "State cache missed");
        }

        let state_from_disk = self.load_hot_state(state_root, update_cache).map_err(|e| {
            Error::LoadingHotStateError("get state".to_owned(), *state_root, e.into())
        })?;

        if let Some((mut state, block_root)) = state_from_disk {
            state.update_tree_hash_cache()?;
            state.build_all_caches(&self.spec)?;
            if update_cache {
                if let PutStateOutcome::New(deleted_states) =
                    self.state_cache
                        .lock()
                        .put_state(*state_root, block_root, &state)?
                {
                    debug!(
                        ?state_root,
                        state_slot = %state.slot(),
                        ?deleted_states,
                        location = "get_hot_state",
                        "Cached state",
                    );
                }
            } else {
                debug!(
                    ?state_root,
                    state_slot = %state.slot(),
                    "Did not cache state",
                );
            }

            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    fn load_hot_hdiff_buffer(&self, state_root: Hash256) -> Result<HDiffBuffer, Error> {
        if let Some(buffer) = self
            .state_cache
            .lock()
            .get_hdiff_buffer_by_state_root(state_root)
        {
            return Ok(buffer);
        }

        let Some(HotStateSummary {
            slot,
            diff_base_state,
            ..
        }) = self.load_hot_state_summary(&state_root)?
        else {
            return Err(Error::MissingHotStateSummary(state_root));
        };

        let buffer = match self.hot_storage_strategy(slot)? {
            StorageStrategy::Snapshot => {
                let Some(state) = self.load_hot_state_as_snapshot(state_root)? else {
                    let existing_snapshots = self.load_hot_state_snapshot_roots()?;
                    debug!(
                        requested = ?state_root,
                        existing_snapshots = ?existing_snapshots,
                        "Missing hot state snapshot"
                    );
                    return Err(Error::MissingHotStateSnapshot(state_root, slot));
                };
                HDiffBuffer::from_state(state)
            }
            StorageStrategy::DiffFrom(from_slot) => {
                let from_state_root = diff_base_state.get_root(from_slot)?;
                let mut buffer = self.load_hot_hdiff_buffer(from_state_root).map_err(|e| {
                    Error::LoadingHotHdiffBufferError(
                        format!("load hdiff DiffFrom {from_slot} {state_root}"),
                        from_state_root,
                        e.into(),
                    )
                })?;
                let diff = self.load_hot_hdiff(state_root)?;
                {
                    let _timer =
                        metrics::start_timer_vec(&metrics::BEACON_HDIFF_APPLY_TIME, HOT_METRIC);
                    diff.apply(&mut buffer, &self.config)?;
                }
                buffer
            }
            StorageStrategy::ReplayFrom(from_slot) => {
                let from_state_root = diff_base_state.get_root(from_slot)?;
                self.load_hot_hdiff_buffer(from_state_root).map_err(|e| {
                    Error::LoadingHotHdiffBufferError(
                        format!("load hdiff ReplayFrom {from_slot} {state_root}"),
                        from_state_root,
                        e.into(),
                    )
                })?
            }
        };

        // Add buffer to cache for future calls.
        self.state_cache
            .lock()
            .put_hdiff_buffer(state_root, slot, &buffer);

        Ok(buffer)
    }

    fn load_hot_hdiff(&self, state_root: Hash256) -> Result<HDiff, Error> {
        let bytes = {
            let _t = metrics::start_timer_vec(&metrics::BEACON_HDIFF_READ_TIME, HOT_METRIC);
            self.hot_db
                .get_bytes(DBColumn::BeaconStateHotDiff, state_root.as_slice())?
                .ok_or(HotColdDBError::MissingHotHDiff(state_root))?
        };
        let hdiff = {
            let _t = metrics::start_timer_vec(&metrics::BEACON_HDIFF_DECODE_TIME, HOT_METRIC);
            HDiff::from_ssz_bytes(&bytes)?
        };
        Ok(hdiff)
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
        update_cache: bool,
    ) -> Result<Option<(BeaconState<E>, Hash256)>, Error> {
        metrics::inc_counter(&metrics::BEACON_STATE_HOT_GET_COUNT);

        if let Some(HotStateSummary {
            slot,
            latest_block_root,
            diff_base_state,
            ..
        }) = self.load_hot_state_summary(state_root)?
        {
            let mut state = match self.hot_storage_strategy(slot)? {
                strat @ StorageStrategy::Snapshot | strat @ StorageStrategy::DiffFrom(_) => {
                    let buffer_timer = metrics::start_timer_vec(
                        &metrics::BEACON_HDIFF_BUFFER_LOAD_TIME,
                        HOT_METRIC,
                    );
                    let buffer = self.load_hot_hdiff_buffer(*state_root).map_err(|e| {
                        Error::LoadingHotHdiffBufferError(
                            format!("load state {strat:?} {slot}"),
                            *state_root,
                            e.into(),
                        )
                    })?;
                    drop(buffer_timer);
                    let mut state = buffer.as_state(&self.spec)?;

                    // Immediately rebase the state from diffs on the finalized state so that we
                    // can utilise structural sharing and don't consume excess memory.
                    self.state_cache
                        .lock()
                        .rebase_on_finalized(&mut state, &self.spec)?;

                    state
                }
                StorageStrategy::ReplayFrom(from_slot) => {
                    let from_state_root = diff_base_state.get_root(from_slot)?;

                    let (mut base_state, _) = self
                        .load_hot_state(&from_state_root, update_cache)
                        .map_err(|e| {
                            Error::LoadingHotStateError(
                                format!("load state ReplayFrom {from_slot}"),
                                *state_root,
                                e.into(),
                            )
                        })?
                        .ok_or(HotColdDBError::MissingHotState {
                            state_root: from_state_root,
                            requested_by_state_summary: (*state_root, slot),
                        })?;

                    // Immediately rebase the state from disk on the finalized state so that we can
                    // reuse parts of the tree for state root calculation in `replay_blocks`.
                    self.state_cache
                        .lock()
                        .rebase_on_finalized(&mut base_state, &self.spec)?;

                    self.load_hot_state_using_replay(
                        base_state,
                        slot,
                        latest_block_root,
                        update_cache,
                    )?
                }
            };
            state.apply_pending_mutations()?;

            Ok(Some((state, latest_block_root)))
        } else {
            Ok(None)
        }
    }

    pub fn load_hot_state_using_replay(
        &self,
        base_state: BeaconState<E>,
        slot: Slot,
        latest_block_root: Hash256,
        update_cache: bool,
    ) -> Result<BeaconState<E>, Error> {
        if base_state.slot() == slot {
            return Ok(base_state);
        }

        let blocks = self.load_blocks_to_replay(base_state.slot(), slot, latest_block_root)?;
        let _t = metrics::start_timer(&metrics::STORE_BEACON_REPLAY_HOT_BLOCKS_TIME);

        // If replaying blocks, and `update_cache` is true, also cache the epoch boundary
        // state that this state is based on. It may be useful as the basis of more states
        // in the same epoch.
        let state_cache_hook = |state_root, state: &mut BeaconState<E>| {
            if !update_cache || state.slot() % E::slots_per_epoch() != 0 {
                return Ok(());
            }
            // Ensure all caches are built before attempting to cache.
            state.update_tree_hash_cache()?;
            state.build_all_caches(&self.spec)?;

            let latest_block_root = state.get_latest_block_root(state_root);
            if let PutStateOutcome::New(_) =
                self.state_cache
                    .lock()
                    .put_state(state_root, latest_block_root, state)?
            {
                debug!(
                    ?state_root,
                    state_slot = %state.slot(),
                    descendant_slot = %slot,
                    "Cached ancestor state",
                );
            }
            Ok(())
        };

        self.replay_blocks(
            base_state,
            blocks,
            slot,
            no_state_root_iter(),
            Some(Box::new(state_cache_hook)),
        )
    }

    pub fn store_cold_state_summary(
        &self,
        state_root: &Hash256,
        slot: Slot,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        ops.push(ColdStateSummary { slot }.as_kv_store_op(*state_root));
        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconStateRoots,
            slot.as_u64().to_be_bytes().to_vec(),
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
        match self.cold_storage_strategy(slot)? {
            StorageStrategy::ReplayFrom(from) => {
                debug!(
                    strategy = "replay",
                    from_slot = %from,
                    %slot,
                    "Storing cold state",
                );
                // Already have persisted the state summary, don't persist anything else
            }
            StorageStrategy::Snapshot => {
                debug!(
                    strategy = "snapshot",
                    %slot,
                    "Storing cold state"
                );
                self.store_cold_state_as_snapshot(state, ops)?;
            }
            StorageStrategy::DiffFrom(from) => {
                debug!(
                    strategy = "diff",
                    from_slot = %from,
                    %slot,
                    "Storing cold state"
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

        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconStateSnapshot,
            state.slot().as_u64().to_be_bytes().to_vec(),
            compressed_value,
        ));
        Ok(())
    }

    fn load_cold_state_bytes_as_snapshot(&self, slot: Slot) -> Result<Option<Vec<u8>>, Error> {
        match self
            .cold_db
            .get_bytes(DBColumn::BeaconStateSnapshot, &slot.as_u64().to_be_bytes())?
        {
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

    pub fn store_hot_state_as_snapshot(
        &self,
        state_root: &Hash256,
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

        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconStateHotSnapshot,
            state_root.as_slice().to_vec(),
            compressed_value,
        ));
        Ok(())
    }

    fn load_hot_state_bytes_as_snapshot(
        &self,
        state_root: Hash256,
    ) -> Result<Option<Vec<u8>>, Error> {
        match self
            .hot_db
            .get_bytes(DBColumn::BeaconStateHotSnapshot, state_root.as_slice())?
        {
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

    fn load_hot_state_as_snapshot(
        &self,
        state_root: Hash256,
    ) -> Result<Option<BeaconState<E>>, Error> {
        Ok(self
            .load_hot_state_bytes_as_snapshot(state_root)?
            .map(|bytes| BeaconState::from_ssz_bytes(&bytes, &self.spec))
            .transpose()?)
    }

    fn load_hot_state_snapshot_roots(&self) -> Result<Vec<Hash256>, Error> {
        self.hot_db
            .iter_column_keys::<Hash256>(DBColumn::BeaconStateHotSnapshot)
            .collect()
    }

    pub fn store_cold_state_as_diff(
        &self,
        state: &BeaconState<E>,
        from_slot: Slot,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        // Load diff base state bytes.
        let (_, base_buffer) = {
            let _t = metrics::start_timer_vec(
                &metrics::BEACON_HDIFF_BUFFER_LOAD_BEFORE_STORE_TIME,
                COLD_METRIC,
            );
            self.load_hdiff_buffer_for_slot(from_slot)?
        };
        let target_buffer = HDiffBuffer::from_state(state.clone());
        let diff = {
            let _timer = metrics::start_timer_vec(&metrics::BEACON_HDIFF_COMPUTE_TIME, COLD_METRIC);
            HDiff::compute(&base_buffer, &target_buffer, &self.config)?
        };
        let diff_bytes = diff.as_ssz_bytes();
        let layer = HierarchyConfig::exponent_for_slot(state.slot());
        metrics::observe_vec(
            &metrics::BEACON_HDIFF_SIZES,
            &[&layer.to_string()],
            diff_bytes.len() as f64,
        );

        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconStateDiff,
            state.slot().as_u64().to_be_bytes().to_vec(),
            diff_bytes,
        ));
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
        let storage_strategy = self.cold_storage_strategy(slot)?;

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
        match self.cold_storage_strategy(slot)? {
            StorageStrategy::Snapshot | StorageStrategy::DiffFrom(_) => {
                let buffer_timer =
                    metrics::start_timer_vec(&metrics::BEACON_HDIFF_BUFFER_LOAD_TIME, COLD_METRIC);
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
                target_slot = %slot,
                build_time_ms = metrics::stop_timer_with_duration(cache_timer).as_millis(),
                "Built caches for historic state"
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
            target_slot = %slot,
            replay_time_ms = metrics::stop_timer_with_duration(replay_timer).as_millis(),
            "Replayed blocks for historic state"
        );

        self.historic_state_cache
            .lock()
            .put_state(slot, state.clone());
        Ok(state)
    }

    fn load_hdiff_for_slot(&self, slot: Slot) -> Result<HDiff, Error> {
        let bytes = {
            let _t = metrics::start_timer_vec(&metrics::BEACON_HDIFF_READ_TIME, COLD_METRIC);
            self.cold_db
                .get_bytes(DBColumn::BeaconStateDiff, &slot.as_u64().to_be_bytes())?
                .ok_or(HotColdDBError::MissingHDiff(slot))?
        };
        let hdiff = {
            let _t = metrics::start_timer_vec(&metrics::BEACON_HDIFF_DECODE_TIME, COLD_METRIC);
            HDiff::from_ssz_bytes(&bytes)?
        };
        Ok(hdiff)
    }

    /// Returns `HDiffBuffer` for the specified slot, or `HDiffBuffer` for the `ReplayFrom` slot if
    /// the diff for the specified slot is not stored.
    fn load_hdiff_buffer_for_slot(&self, slot: Slot) -> Result<(Slot, HDiffBuffer), Error> {
        if let Some(buffer) = self.historic_state_cache.lock().get_hdiff_buffer(slot) {
            debug!(
                %slot,
                "Hit hdiff buffer cache"
            );
            metrics::inc_counter_vec(&metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_HIT, COLD_METRIC);
            return Ok((slot, buffer));
        }
        metrics::inc_counter_vec(&metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_MISS, COLD_METRIC);

        // Load buffer for the previous state.
        // This amount of recursion (<10 levels) should be OK.
        let t = std::time::Instant::now();
        match self.cold_storage_strategy(slot)? {
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
                    load_time_ms,
                    %slot,
                    "Cached state and hdiff buffer"
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
                        metrics::start_timer_vec(&metrics::BEACON_HDIFF_APPLY_TIME, COLD_METRIC);
                    diff.apply(&mut buffer, &self.config)?;
                }

                self.historic_state_cache
                    .lock()
                    .put_hdiff_buffer(slot, buffer.clone());

                let load_time_ms = t.elapsed().as_millis();
                debug!(
                    load_time_ms,
                    %slot,
                    "Cached hdiff buffer"
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
                        slot = %target_slot,
                        "State root cache miss during block replay"
                    );
                }
                block_replayer.into_state()
            })
    }

    /// Fetch custody info from the cache.
    /// If custody info doesn't exist in the cache,
    /// try to fetch from the DB and prime the cache.
    pub fn get_data_column_custody_info(&self) -> Result<Option<DataColumnCustodyInfo>, Error> {
        if let Some(cache) = &self.block_cache
            && let Some(data_column_custody_info) = cache.lock().get_data_column_custody_info()
        {
            return Ok(Some(data_column_custody_info));
        }
        let data_column_custody_info = self
            .blobs_db
            .get::<DataColumnCustodyInfo>(&DATA_COLUMN_CUSTODY_INFO_KEY)?;

        // Update the cache
        self.block_cache.as_ref().inspect(|cache| {
            cache
                .lock()
                .put_data_column_custody_info(data_column_custody_info.clone())
        });

        Ok(data_column_custody_info)
    }

    /// Fetch all columns for a given block from the store.
    pub fn get_data_columns(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<DataColumnSidecarList<E>>, Error> {
        let column_indices = self.get_data_column_keys(*block_root)?;

        let columns: DataColumnSidecarList<E> = column_indices
            .into_iter()
            .filter_map(|col_index| self.get_data_column(block_root, &col_index).transpose())
            .collect::<Result<_, _>>()?;

        Ok((!columns.is_empty()).then_some(columns))
    }

    /// Fetch blobs for a given block from the store.
    pub fn get_blobs(&self, block_root: &Hash256) -> Result<BlobSidecarListFromRoot<E>, Error> {
        // Check the cache.
        if let Some(blobs) = self
            .block_cache
            .as_ref()
            .and_then(|cache| cache.lock().get_blobs(block_root).cloned())
        {
            metrics::inc_counter(&metrics::BEACON_BLOBS_CACHE_HIT_COUNT);
            return Ok(blobs.into());
        }

        match self
            .blobs_db
            .get_bytes(DBColumn::BeaconBlob, block_root.as_slice())?
        {
            Some(ref blobs_bytes) => {
                // We insert a VariableList of BlobSidecars into the db, but retrieve
                // a plain vec since we don't know the length limit of the list without
                // knowing the slot.
                // The encoding of a VariableList is the same as a regular vec.
                let blobs: Vec<Arc<BlobSidecar<E>>> = Vec::<_>::from_ssz_bytes(blobs_bytes)?;
                if let Some(max_blobs_per_block) = blobs
                    .first()
                    .map(|blob| self.spec.max_blobs_per_block(blob.epoch()))
                {
                    let blobs = BlobSidecarList::new(blobs, max_blobs_per_block as usize)?;
                    self.block_cache
                        .as_ref()
                        .inspect(|cache| cache.lock().put_blobs(*block_root, blobs.clone()));

                    Ok(BlobSidecarListFromRoot::Blobs(blobs))
                } else {
                    // This always implies that there were no blobs for this block_root
                    Ok(BlobSidecarListFromRoot::NoBlobs)
                }
            }
            None => Ok(BlobSidecarListFromRoot::NoRoot),
        }
    }

    /// Fetch all keys in the data_column column with prefix `block_root`
    pub fn get_data_column_keys(&self, block_root: Hash256) -> Result<Vec<ColumnIndex>, Error> {
        self.blobs_db
            .iter_column_from::<Vec<u8>>(DBColumn::BeaconDataColumn, block_root.as_slice())
            .take_while(|res| {
                res.as_ref()
                    .is_ok_and(|(key, _)| key.starts_with(block_root.as_slice()))
            })
            .map(|key| key.and_then(|(key, _)| parse_data_column_key(key).map(|key| key.1)))
            .collect()
    }

    /// Fetch all possible data column keys for a given `block_root`.
    ///
    /// Unlike `get_data_column_keys`, these keys are not necessarily all present in the database,
    /// due to the node's custody requirements many just store a subset.
    pub fn get_all_data_column_keys(&self, block_root: Hash256) -> Vec<Vec<u8>> {
        (0..E::number_of_columns() as u64)
            .map(|column_index| get_data_column_key(&block_root, &column_index))
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
            .as_ref()
            .and_then(|cache| cache.lock().get_data_column(block_root, column_index))
        {
            metrics::inc_counter(&metrics::BEACON_DATA_COLUMNS_CACHE_HIT_COUNT);
            return Ok(Some(data_column));
        }

        match self.blobs_db.get_bytes(
            DBColumn::BeaconDataColumn,
            &get_data_column_key(block_root, column_index),
        )? {
            Some(ref data_column_bytes) => {
                let data_column = Arc::new(DataColumnSidecar::from_ssz_bytes(data_column_bytes)?);
                self.block_cache.as_ref().inspect(|cache| {
                    cache
                        .lock()
                        .put_data_column(*block_root, data_column.clone())
                });
                Ok(Some(data_column))
            }
            None => Ok(None),
        }
    }

    /// Get a reference to the `ChainSpec` used by the database.
    pub fn get_chain_spec(&self) -> &Arc<ChainSpec> {
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
        let key = SCHEMA_VERSION_KEY.as_slice();
        let op = KeyValueStoreOp::PutKeyValue(
            SchemaVersion::db_column(),
            key.to_vec(),
            schema_version.as_store_bytes(),
        );
        ops.push(op);

        self.hot_db.do_atomically(ops)
    }

    /// Initialise the anchor info for checkpoint sync starting from `block`.
    pub fn init_anchor_info(
        &self,
        oldest_block_parent: Hash256,
        oldest_block_slot: Slot,
        anchor_slot: Slot,
        retain_historic_states: bool,
    ) -> Result<KeyValueStoreOp, Error> {
        // Set the `state_upper_limit` to the slot of the *next* checkpoint.
        let next_snapshot_slot = self.hierarchy.next_snapshot_slot(anchor_slot)?;
        let state_upper_limit = if !retain_historic_states {
            STATE_UPPER_LIMIT_NO_RETAIN
        } else {
            next_snapshot_slot
        };
        let anchor_info = AnchorInfo {
            anchor_slot,
            oldest_block_slot,
            oldest_block_parent,
            state_upper_limit,
            state_lower_limit: self.spec.genesis_slot,
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
            .get(&ANCHOR_INFO_KEY)
            .map_err(|e| Error::LoadAnchorInfo(e.into()))?
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
        let oldest_data_column_slot = self.spec.fulu_fork_epoch.map(|fork_epoch| {
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
        self.hot_db
            .get(&BLOB_INFO_KEY)
            .map_err(|e| Error::LoadBlobInfo(e.into()))
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
        self.hot_db
            .get(&DATA_COLUMN_INFO_KEY)
            .map_err(|e| Error::LoadDataColumnInfo(e.into()))
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
        self.hot_db
            .get(&CONFIG_KEY)
            .map_err(|e| Error::LoadConfig(e.into()))
    }

    /// Write the config to disk.
    fn store_config(&self) -> Result<(), Error> {
        self.hot_db.put(&CONFIG_KEY, &self.config.as_disk_config())
    }

    /// Load the split point from disk, sans block root.
    fn load_split_partial(&self) -> Result<Option<Split>, Error> {
        self.hot_db
            .get(&SPLIT_KEY)
            .map_err(|e| Error::LoadSplit(e.into()))
    }

    /// Load the split point from disk, including block root.
    fn load_split(&self) -> Result<Option<Split>, Error> {
        match self.load_split_partial()? {
            Some(mut split) => {
                debug!(?split, "Loaded split partial");
                // Load the hot state summary to get the block root.
                let latest_block_root = self
                    .load_block_root_from_summary_any_version(&split.state_root)
                    .ok_or(HotColdDBError::MissingSplitState(
                        split.state_root,
                        split.slot,
                    ))?;
                split.block_root = latest_block_root;
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
        self.hot_db
            .get(state_root)
            .map_err(|e| Error::LoadHotStateSummary(*state_root, e.into()))
    }

    /// Load a hot state's summary in V22 format, given its root.
    pub fn load_hot_state_summary_v22(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<HotStateSummaryV22>, Error> {
        self.hot_db
            .get(state_root)
            .map_err(|e| Error::LoadHotStateSummary(*state_root, e.into()))
    }

    /// Load the latest block root for a hot state summary either in modern form, or V22 form.
    ///
    /// This function is required to open a V22 database for migration to V24, or vice versa.
    pub fn load_block_root_from_summary_any_version(
        &self,
        state_root: &Hash256,
    ) -> Option<Hash256> {
        if let Ok(Some(summary)) = self.load_hot_state_summary(state_root) {
            return Some(summary.latest_block_root);
        }
        if let Ok(Some(summary)) = self.load_hot_state_summary_v22(state_root) {
            return Some(summary.latest_block_root);
        }
        None
    }

    /// Load all hot state summaries present in the hot DB
    pub fn load_hot_state_summaries(&self) -> Result<Vec<(Hash256, HotStateSummary)>, Error> {
        self.hot_db
            .iter_column::<Hash256>(DBColumn::BeaconStateHotSummary)
            .map(|res| {
                let (state_root, value) = res?;
                let summary = HotStateSummary::from_ssz_bytes(&value)?;
                Ok((state_root, summary))
            })
            .collect()
    }

    /// Run a compaction pass to free up space used by deleted states.
    pub fn compact(&self) -> Result<(), Error> {
        self.hot_db.compact()?;
        Ok(())
    }

    /// Run a compaction pass on the freezer DB to free up space used by deleted states.
    pub fn compact_freezer(&self) -> Result<(), Error> {
        let columns = vec![
            DBColumn::BeaconColdStateSummary,
            DBColumn::BeaconStateSnapshot,
            DBColumn::BeaconStateDiff,
            DBColumn::BeaconStateRoots,
        ];

        for column in columns {
            info!(?column, "Starting compaction");
            self.cold_db.compact_column(column)?;
            info!(?column, "Finishing compaction");
        }
        Ok(())
    }

    /// Return `true` if compaction on finalization/pruning is enabled.
    pub fn compact_on_prune(&self) -> bool {
        self.config.compact_on_prune
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
                DBColumn::BeaconBlockRoots,
                slot.to_be_bytes().to_vec(),
                block_root.as_slice().to_vec(),
            ));
        }
        Ok(ops)
    }

    /// Return a single block root from the cold DB.
    ///
    /// If the slot is unavailable due to partial block history, `Ok(None)` will be returned.
    pub fn get_cold_block_root(&self, slot: Slot) -> Result<Option<Hash256>, Error> {
        Ok(self
            .cold_db
            .get_bytes(DBColumn::BeaconBlockRoots, &slot.as_u64().to_be_bytes())?
            .map(|bytes| Hash256::from_ssz_bytes(&bytes))
            .transpose()?)
    }

    /// Return a single state root from the cold DB.
    ///
    /// If the slot is unavailable due to partial state history, `Ok(None)` will be returned.
    ///
    /// This function will usually only work on an archive node.
    pub fn get_cold_state_root(&self, slot: Slot) -> Result<Option<Hash256>, Error> {
        Ok(self
            .cold_db
            .get_bytes(DBColumn::BeaconStateRoots, &slot.as_u64().to_be_bytes())?
            .map(|bytes| Hash256::from_ssz_bytes(&bytes))
            .transpose()?)
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

        // Load the split state so we can backtrack to find execution payloads. The split state
        // should be in the state cache as the enshrined finalized state, so this should never
        // cache miss.
        let split_state = self
            .get_state(&split.state_root, Some(split.slot), true)?
            .ok_or(HotColdDBError::MissingSplitState(
                split.state_root,
                split.slot,
            ))?;

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
            info!("Execution payloads are pruned");
            return Ok(());
        }

        // Iterate block roots backwards to the Bellatrix fork or the anchor slot, whichever comes
        // first.
        warn!(
            info = "you may notice degraded I/O performance while this runs",
            "Pruning finalized payloads"
        );
        let anchor_info = self.get_anchor_info();

        let mut ops = vec![];
        let mut last_pruned_block_root = None;

        for res in std::iter::once(Ok((split_block_root, split.slot)))
            .chain(BlockRootsIterator::new(self, &split_state))
        {
            let (block_root, slot) = match res {
                Ok(tuple) => tuple,
                Err(e) => {
                    warn!(
                        error = ?e,
                        "Stopping payload pruning early"
                    );
                    break;
                }
            };

            if slot < bellatrix_fork_slot {
                info!("Payload pruning reached Bellatrix boundary");
                break;
            }

            if Some(block_root) != last_pruned_block_root
                && self.execution_payload_exists(&block_root)?
            {
                debug!(%slot, ?block_root, "Pruning execution payload");
                last_pruned_block_root = Some(block_root);
                ops.push(StoreOp::DeleteExecutionPayload(block_root));
            }

            if slot <= anchor_info.oldest_block_slot {
                info!(%slot, "Payload pruning reached anchor oldest block slot");
                break;
            }
        }
        let payloads_pruned = ops.len();
        self.do_atomically_with_block_and_blobs_cache(ops)?;
        info!(%payloads_pruned, "Execution payload pruning complete");
        Ok(())
    }

    /// Try to prune blobs, approximating the current epoch from the split slot.
    pub fn try_prune_most_blobs(&self, force: bool) -> Result<(), Error> {
        // The current epoch is >= split_epoch + 2. It could be greater if the database is
        // configured to delay updating the split or finalization has ceased. In this instance we
        // choose to also delay the pruning of blobs (we never prune without finalization anyway).
        let min_current_epoch = self.get_split_slot().epoch(E::slots_per_epoch()) + 2;
        let Some(min_data_availability_boundary) = self
            .spec
            .min_epoch_data_availability_boundary(min_current_epoch)
        else {
            debug!("Deneb fork is disabled");
            return Ok(());
        };

        self.try_prune_blobs(force, min_data_availability_boundary)
    }

    /// Try to prune blobs and data columns older than the data availability boundary.
    ///
    /// Blobs from the epoch `data_availability_boundary - blob_prune_margin_epochs` are retained.
    /// This epoch is an _exclusive_ endpoint for the pruning process.
    ///
    /// This function only supports pruning blobs and data columns older than the split point,
    /// which is older than (or equal to) finalization. Pruning blobs and data columns newer than
    /// finalization is not supported.
    ///
    /// This function also assumes that the split is stationary while it runs. It should only be
    /// run from the migrator thread (where `migrate_database` runs) or the database manager.
    pub fn try_prune_blobs(
        &self,
        force: bool,
        data_availability_boundary: Epoch,
    ) -> Result<(), Error> {
        if self.spec.deneb_fork_epoch.is_none() {
            debug!("Deneb fork is disabled");
            return Ok(());
        }

        let pruning_enabled = self.get_config().prune_blobs;
        let margin_epochs = self.get_config().blob_prune_margin_epochs;
        let epochs_per_blob_prune = self.get_config().epochs_per_blob_prune;

        if !force && !pruning_enabled {
            debug!(prune_blobs = pruning_enabled, "Blob pruning is disabled");
            return Ok(());
        }

        let blob_info = self.get_blob_info();
        let data_column_info = self.get_data_column_info();
        let Some(oldest_blob_slot) = blob_info.oldest_blob_slot else {
            error!("Slot of oldest blob is not known");
            return Err(HotColdDBError::BlobPruneLogicError.into());
        };

        // The start epoch is not necessarily iterated back to, but is used for deciding whether we
        // should attempt pruning. We could probably refactor it out eventually (while reducing our
        // dependence on BlobInfo).
        let start_epoch = oldest_blob_slot.epoch(E::slots_per_epoch());

        // Prune blobs up until the `data_availability_boundary - margin` or the split
        // slot's epoch, whichever is older. We can't prune blobs newer than the split.
        // The end epoch is inclusive (blobs in this epoch will be pruned).
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
                %oldest_blob_slot,
                %data_availability_boundary,
                %split.slot,
                %end_epoch,
                %start_epoch,
                "Blobs are pruned"
            );
            return Ok(());
        }

        // Iterate blocks backwards from the `end_epoch` (usually the data availability boundary).
        let Some((end_block_root, _)) = self
            .forwards_block_roots_iterator_until(end_slot, end_slot, || {
                self.get_hot_state(&split.state_root, true)?
                    .ok_or(HotColdDBError::MissingSplitState(
                        split.state_root,
                        split.slot,
                    ))
                    .map(|state| (state, split.state_root))
                    .map_err(Into::into)
            })?
            .next()
            .transpose()?
        else {
            // Can't prune blobs if we don't know the block at `end_slot`. This is expected if we
            // have checkpoint synced and haven't backfilled to the DA boundary yet.
            debug!(
                %end_epoch,
                %data_availability_boundary,
                "No blobs to prune"
            );
            return Ok(());
        };
        debug!(
            %end_epoch,
            %data_availability_boundary,
            "Pruning blobs"
        );

        // We collect block roots of deleted blobs in memory. Even for 10y of blob history this
        // vec won't go beyond 1GB. We can probably optimise this out eventually.
        let mut removed_block_roots = vec![];
        let mut blobs_db_ops = vec![];

        // Iterate blocks backwards until we reach a block for which we've already pruned
        // blobs/columns.
        for tuple in ParentRootBlockIterator::new(self, end_block_root) {
            let (block_root, blinded_block) = tuple?;
            let slot = blinded_block.slot();

            // If the block has no blobs we can't tell if they've been pruned, and there is nothing
            // to prune, so we just skip.
            if !blinded_block.message().body().has_blobs() {
                continue;
            }

            // Check if we have blobs or columns stored. If not, we assume pruning has already
            // reached this point.
            let (db_column, db_keys) = if blinded_block.fork_name_unchecked().fulu_enabled() {
                (
                    DBColumn::BeaconDataColumn,
                    self.get_all_data_column_keys(block_root),
                )
            } else {
                (DBColumn::BeaconBlob, vec![block_root.as_slice().to_vec()])
            };

            // For data columns, consider a block pruned if ALL column indices are absent.
            // In future we might want to refactor this to read the data column indices that *exist*
            // from the DB, which could be slightly more efficient than checking existence for every
            // possible column.
            let mut data_stored_for_block = false;
            for db_key in db_keys {
                if self.blobs_db.key_exists(db_column, &db_key)? {
                    data_stored_for_block = true;
                    blobs_db_ops.push(KeyValueStoreOp::DeleteKey(db_column, db_key));
                }
            }

            if data_stored_for_block {
                debug!(
                    ?block_root,
                    %slot,
                    "Pruning blobs or columns for block"
                );
                removed_block_roots.push(block_root);
            } else {
                debug!(
                    %slot,
                    ?block_root,
                    "Reached slot with blobs or columns already pruned"
                );
                break;
            }
        }

        // Remove deleted blobs from the cache.
        if let Some(mut block_cache) = self.block_cache.as_ref().map(|cache| cache.lock()) {
            for block_root in removed_block_roots {
                block_cache.delete_blobs(&block_root);
                block_cache.delete_data_columns(&block_root);
            }
        }

        // Remove from disk.
        if !blobs_db_ops.is_empty() {
            debug!(
                num_deleted = blobs_db_ops.len(),
                "Deleting blobs and data columns from disk"
            );
            self.blobs_db.do_atomically(blobs_db_ops)?;
        }

        self.update_blob_or_data_column_info(start_epoch, end_slot, blob_info, data_column_info)?;

        debug!("Blob pruning complete");

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

        let columns = vec![
            DBColumn::BeaconColdStateSummary,
            DBColumn::BeaconStateSnapshot,
            DBColumn::BeaconStateDiff,
            DBColumn::BeaconStateRoots,
        ];

        for column in columns {
            for res in self.cold_db.iter_column_keys::<Vec<u8>>(column) {
                let key = res?;
                cold_ops.push(KeyValueStoreOp::DeleteKey(column, key));
            }
        }
        let delete_ops = cold_ops.len();

        // If we just deleted the genesis state, re-store it using the current* schema.
        if self.get_split_slot() > 0 {
            info!(
                state_root = ?genesis_state_root,
                "Re-storing genesis state"
            );
            self.store_cold_state(&genesis_state_root, genesis_state, &mut cold_ops)?;
        }

        info!(delete_ops, "Deleting historic states");
        self.cold_db.do_atomically(cold_ops)?;

        // In order to reclaim space, we need to compact the freezer DB as well.
        self.compact_freezer()?;

        Ok(())
    }

    fn update_blob_or_data_column_info(
        &self,
        start_epoch: Epoch,
        end_slot: Slot,
        blob_info: BlobInfo,
        data_column_info: DataColumnInfo,
    ) -> Result<(), Error> {
        let op = if self.spec.is_peer_das_enabled_for_epoch(start_epoch) {
            let new_data_column_info = DataColumnInfo {
                oldest_data_column_slot: Some(end_slot + 1),
            };
            self.compare_and_set_data_column_info(data_column_info, new_data_column_info)?
        } else {
            let new_blob_info = BlobInfo {
                oldest_blob_slot: Some(end_slot + 1),
                blobs_db: blob_info.blobs_db,
            };
            self.compare_and_set_blob_info(blob_info, new_blob_info)?
        };

        self.do_atomically_with_block_and_blobs_cache(vec![StoreOp::KeyValueOp(op)])?;

        Ok(())
    }
}

/// Advance the split point of the store, copying new finalized states to the freezer.
///
/// This function previously did a combination of freezer migration alongside pruning. Now it is
/// *just* responsible for copying relevant data to the freezer, while pruning is implemented
/// in `prune_hot_db`.
pub fn migrate_database<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: Arc<HotColdDB<E, Hot, Cold>>,
    finalized_state_root: Hash256,
    finalized_block_root: Hash256,
    finalized_state: &BeaconState<E>,
) -> Result<SplitChange, Error> {
    debug!(
        slot = %finalized_state.slot(),
        "Freezer migration started"
    );

    // 0. Check that the migration is sensible.
    // The new finalized state must increase the current split slot, and lie on an epoch
    // boundary (in order for the hot state summary scheme to work).
    let current_split = *store.split.read_recursive();
    let anchor_info = store.anchor_info.read_recursive().clone();

    if finalized_state.slot() < current_split.slot {
        return Err(HotColdDBError::FreezeSlotError {
            current_split_slot: current_split.slot,
            proposed_split_slot: finalized_state.slot(),
        }
        .into());
    }

    // finalized_state.slot() must be at an epoch boundary
    // else we may introduce bugs to the migration/pruning logic
    if finalized_state.slot() % E::slots_per_epoch() != 0 {
        return Err(HotColdDBError::FreezeSlotUnaligned(finalized_state.slot()).into());
    }

    let mut cold_db_block_ops = vec![];

    // Iterate in descending order until the current split slot
    let state_roots: Vec<_> =
        process_results(RootsIterator::new(&store, finalized_state), |iter| {
            iter.take_while(|(_, _, slot)| *slot >= current_split.slot)
                .collect()
        })?;

    // Then, iterate states in slot ascending order, as they are stored wrt previous states.
    for (block_root, state_root, slot) in state_roots.into_iter().rev() {
        // Store the slot to block root mapping.
        cold_db_block_ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconBlockRoots,
            slot.as_u64().to_be_bytes().to_vec(),
            block_root.as_slice().to_vec(),
        ));

        // Do not try to store states if a restore point is yet to be stored, or will never be
        // stored (see `STATE_UPPER_LIMIT_NO_RETAIN`). Make an exception for the genesis state
        // which always needs to be copied from the hot DB to the freezer and should not be deleted.
        if slot != 0 && slot < anchor_info.state_upper_limit {
            continue;
        }

        let mut cold_db_state_ops = vec![];

        // Only store the cold state if it's on a diff boundary.
        // Calling `store_cold_state_summary` instead of `store_cold_state` for those allows us
        // to skip loading many hot states.
        if let StorageStrategy::ReplayFrom(from) = store.cold_storage_strategy(slot)? {
            // Store slot -> state_root and state_root -> slot mappings.
            debug!(
                strategy = "replay",
                from_slot = %from,
                %slot,
                "Storing cold state"
            );
            store.store_cold_state_summary(&state_root, slot, &mut cold_db_state_ops)?;
        } else {
            // This is some state that we want to migrate to the freezer db.
            // There is no reason to cache this state.
            let state: BeaconState<E> = store
                .get_hot_state(&state_root, false)?
                .ok_or(HotColdDBError::MissingStateToFreeze(state_root))?;

            store.store_cold_state(&state_root, &state, &mut cold_db_state_ops)?;
        }

        // Cold states are diffed with respect to each other, so we need to finish writing previous
        // states before storing new ones.
        store.cold_db.do_atomically(cold_db_state_ops)?;
    }

    // Warning: Critical section. We have to take care not to put any of the two databases in an
    //          inconsistent state if the OS process dies at any point during the freezing
    //          procedure.
    //
    // Since it is pretty much impossible to be atomic across more than one database, we trade
    // potentially re-doing the migration to copy data to the freezer, for consistency. If we crash
    // after writing all new block & state data to the freezer but before updating the split, then
    // in the worst case we will restart with the old split and re-run the migration.
    store.cold_db.do_atomically(cold_db_block_ops)?;
    store.cold_db.sync()?;
    let new_split = {
        let mut split_guard = store.split.write();
        let latest_split = *split_guard;

        // Detect a situation where the split point is (erroneously) changed from more than one
        // place in code.
        if latest_split.slot != current_split.slot {
            error!(
                previous_split_slot = %current_split.slot,
                current_split_slot = %latest_split.slot,
                "Race condition detected: Split point changed while copying states to the freezer"
            );

            // Assume the freezing procedure will be retried in case this happens.
            return Err(Error::SplitPointModified(
                current_split.slot,
                latest_split.slot,
            ));
        }

        // Before updating the in-memory split value, we flush it to disk first, so that should the
        // OS process die at this point, we pick up from the right place after a restart.
        let new_split = Split {
            slot: finalized_state.slot(),
            state_root: finalized_state_root,
            block_root: finalized_block_root,
        };
        store.hot_db.put_sync(&SPLIT_KEY, &new_split)?;

        // Split point is now persisted in the hot database on disk. The in-memory split point
        // hasn't been modified elsewhere since we keep a write lock on it. It's safe to update
        // the in-memory split point now.
        *split_guard = new_split;
        new_split
    };

    // Update the cache's view of the finalized state.
    store.update_finalized_state(
        finalized_state_root,
        finalized_block_root,
        finalized_state.clone(),
    )?;

    debug!(
        slot = %finalized_state.slot(),
        "Freezer migration complete"
    );

    Ok(SplitChange {
        previous: current_split,
        new: new_split,
    })
}

#[derive(Debug)]
pub struct SplitChange {
    pub previous: Split,
    pub new: Split,
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

#[derive(Debug)]
#[allow(dead_code)]
pub enum StateSummaryIteratorError {
    MissingSummary(Hash256),
    CircularSummaries {
        state_root: Hash256,
        state_slot: Slot,
        previous_slot: Slot,
    },
    BelowTarget(Slot),
    LoadSummaryError(Box<Error>),
    LoadStateRootError(Box<Error>),
    MissingStateRoot {
        target_slot: Slot,
        state_upper_limit: Slot,
    },
    OutOfBoundsInitialSlot,
}

/// Return the ancestor state root of a state beyond SlotsPerHistoricalRoot using the roots iterator
/// and the store
pub fn get_ancestor_state_root<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: &'a HotColdDB<E, Hot, Cold>,
    from_state: &'a BeaconState<E>,
    target_slot: Slot,
) -> Result<Hash256, StateSummaryIteratorError> {
    // Use the state itself for recent roots
    if let Ok(target_state_root) = from_state.get_state_root(target_slot) {
        return Ok(*target_state_root);
    }

    // Fetch the anchor info prior to obtaining the split lock. We don't need to hold a lock because
    // the `state_upper_limit` can't increase (and rug us) unless state pruning runs, and it never
    // runs concurrently.
    let state_upper_limit = store.get_anchor_info().state_upper_limit;

    // Hold the split lock so that state summaries are not pruned concurrently with this function
    // running.
    let split = store.split.read_recursive();

    // If the state root is in range of the freezer DB's linear state root storage, fetch it
    // directly from there. This is useful on archive nodes to avoid some of the complexity of
    // traversing the sparse portion of the hdiff grid (prior to the split slot). It is also
    // necessary for the v24 schema migration on archive nodes, where there isn't yet any grid
    // to traverse.
    if target_slot < split.slot && target_slot >= state_upper_limit {
        drop(split);
        return store
            .get_cold_state_root(target_slot)
            .map_err(Box::new)
            .map_err(StateSummaryIteratorError::LoadStateRootError)?
            .ok_or(StateSummaryIteratorError::MissingStateRoot {
                target_slot,
                state_upper_limit,
            });
    }

    let mut state_root = {
        // We can not start loading summaries from `state_root` since its summary has not yet been
        // imported. This code path is called during block import.
        //
        // We need to choose a state_root to start that is
        // - An ancestor of `from_state`, AND
        // - Its state summary is already written (and not pruned) in the DB
        // - Its slot is >= target_slot
        //
        // If we get to this codepath, (target_slot not in state's state_roots) it means that
        // `state.slot()` is greater than `SlotsPerHistoricalRoot`, and `target_slot < state.slot()
        // - SlotsPerHistoricalRoot`.
        //
        // Values we could start from:
        // - `state.slot() - 1`: TODO if we don't immediately commit all each state to the DB
        //   individually, we may be attempting to read a state summary that is stored in a DB ops
        //   vector but not yet written to the DB. Also starting from this slot is wasteful as we
        //   know that the target slot is `< state.slot() - SlotsPerHistoricalRoot`.
        // - `state.slot() - SlotsPerHistoricalRoot`: The most efficient slot to start. But we risk
        //   jumping to a state summary that has already been pruned. See the `max(.., split_slot)`
        //   below
        let oldest_slot_in_state_roots = from_state
            .slot()
            .saturating_sub(Slot::new(E::SlotsPerHistoricalRoot::to_u64()));

        // Don't start with a slot that prior to the finalized state slot. We may be attempting to read
        // a hot state summary that has already been pruned as part of the migration and error. HDiffs
        // can reference diffs with a slot prior to the finalized checkpoint. But those are sparse so
        // the probabiliy of hitting `MissingSummary` error is high. Instead, the summary for the
        // finalized state is always available.
        let start_slot = std::cmp::max(oldest_slot_in_state_roots, split.slot);

        *from_state
            .get_state_root(start_slot)
            .map_err(|_| StateSummaryIteratorError::OutOfBoundsInitialSlot)?
    };

    let mut previous_slot = None;

    loop {
        let state_summary = store
            .load_hot_state_summary(&state_root)
            .map_err(|e| StateSummaryIteratorError::LoadSummaryError(Box::new(e)))?
            .ok_or(StateSummaryIteratorError::MissingSummary(state_root))?;

        // Protect against infinite loops if the state summaries are not strictly descending
        if let Some(previous_slot) = previous_slot
            && state_summary.slot >= previous_slot
        {
            drop(split);
            return Err(StateSummaryIteratorError::CircularSummaries {
                state_root,
                state_slot: state_summary.slot,
                previous_slot,
            });
        }
        previous_slot = Some(state_summary.slot);

        match state_summary.slot.cmp(&target_slot) {
            Ordering::Less => {
                drop(split);
                return Err(StateSummaryIteratorError::BelowTarget(state_summary.slot));
            }
            Ordering::Equal => return Ok(state_root),
            Ordering::Greater => {} // keep going
        }

        // Jump to an older state summary that is an ancestor of `state_root`
        if let OptionalDiffBaseState::BaseState(DiffBaseState {
            slot,
            state_root: diff_base_state_root,
        }) = state_summary.diff_base_state
        {
            if target_slot <= slot {
                // As an optimization use the HDiff state root to jump states faster
                state_root = diff_base_state_root;
            }
            continue;
        }
        // Else jump slot by slot
        state_root = state_summary.previous_state_root;
    }
}

/// Struct for summarising a state in the hot database.
///
/// Allows full reconstruction by replaying blocks.
#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct HotStateSummary {
    pub slot: Slot,
    pub latest_block_root: Hash256,
    pub latest_block_slot: Slot,
    pub diff_base_state: OptionalDiffBaseState,
    pub previous_state_root: Hash256,
}

/// Information about the state that a hot state is diffed from or replays blocks from, if any.
///
/// In the case of a snapshot, there is no diff base state, so this value will be
/// `DiffBaseState::Snapshot`.
#[derive(Debug, Clone, Copy, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum OptionalDiffBaseState {
    // The SSZ crate requires *something* in each variant so we just store a u8 set to 0.
    Snapshot(u8),
    BaseState(DiffBaseState),
}

#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct DiffBaseState {
    slot: Slot,
    state_root: Hash256,
}

impl OptionalDiffBaseState {
    pub fn new(slot: Slot, state_root: Hash256) -> Self {
        Self::BaseState(DiffBaseState { slot, state_root })
    }

    pub fn get_root(&self, slot: Slot) -> Result<Hash256, Error> {
        match *self {
            Self::Snapshot(_) => Err(Error::SnapshotDiffBaseState { slot }),
            Self::BaseState(DiffBaseState {
                slot: stored_slot,
                state_root,
            }) => {
                if stored_slot == slot {
                    Ok(state_root)
                } else {
                    Err(Error::MismatchedDiffBaseState {
                        expected_slot: slot,
                        stored_slot,
                    })
                }
            }
        }
    }
}

// Succint rendering of (slot, state_root) pair for "Storing hot state summary and diffs" log
impl std::fmt::Display for OptionalDiffBaseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Snapshot(_) => write!(f, "snapshot"),
            Self::BaseState(base_state) => write!(f, "{base_state}"),
        }
    }
}

impl std::fmt::Display for DiffBaseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{:?}", self.slot, self.state_root)
    }
}

impl StoreItem for HotStateSummary {
    fn db_column() -> DBColumn {
        DBColumn::BeaconStateHotSummary
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
    pub fn new<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        store: &HotColdDB<E, Hot, Cold>,
        state_root: Hash256,
        state: &BeaconState<E>,
        storage_strategy: StorageStrategy,
    ) -> Result<Self, Error> {
        // Fill in the state root on the latest block header if necessary (this happens on all
        // slots where there isn't a skip).
        let latest_block_root = state.get_latest_block_root(state_root);

        let get_state_root = |slot| {
            if slot == state.slot() {
                Ok::<_, Error>(state_root)
            } else {
                Ok(get_ancestor_state_root(store, state, slot).map_err(|e| {
                    Error::StateSummaryIteratorError {
                        error: e,
                        from_state_root: state_root,
                        from_state_slot: state.slot(),
                        target_slot: slot,
                    }
                })?)
            }
        };
        let diff_base_slot = storage_strategy.diff_base_slot();
        let diff_base_state = if let Some(diff_base_slot) = diff_base_slot {
            OptionalDiffBaseState::new(diff_base_slot, get_state_root(diff_base_slot)?)
        } else {
            OptionalDiffBaseState::Snapshot(0)
        };

        let previous_state_root = if state.slot() == 0 {
            // Set to 0x0 for genesis state to prevent any sort of circular reference.
            Hash256::zero()
        } else {
            get_state_root(state.slot().safe_sub(1_u64)?)?
        };

        Ok(HotStateSummary {
            slot: state.slot(),
            latest_block_root,
            latest_block_slot: state.latest_block_header().slot,
            diff_base_state,
            previous_state_root,
        })
    }
}

/// Legacy hot state summary used in schema V22 and before.
///
/// This can be deleted when we remove V22 support.
#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct HotStateSummaryV22 {
    pub slot: Slot,
    pub latest_block_root: Hash256,
    pub epoch_boundary_state_root: Hash256,
}

impl StoreItem for HotStateSummaryV22 {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BytesKey {
    pub key: Vec<u8>,
}

impl db_key::Key for BytesKey {
    fn from_u8(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(self.key.as_slice())
    }
}

impl BytesKey {
    pub fn starts_with(&self, prefix: &Self) -> bool {
        self.key.starts_with(&prefix.key)
    }

    /// Return `true` iff this `BytesKey` was created with the given `column`.
    pub fn matches_column(&self, column: DBColumn) -> bool {
        self.key.starts_with(column.as_bytes())
    }

    /// Remove the column from a key, returning its `Hash256` portion.
    pub fn remove_column(&self, column: DBColumn) -> Option<Hash256> {
        if self.matches_column(column) {
            let subkey = &self.key[column.as_bytes().len()..];
            if subkey.len() == 32 {
                return Some(Hash256::from_slice(subkey));
            }
        }
        None
    }

    /// Remove the column from a key.
    ///
    /// Will return `None` if the value doesn't match the column or has the wrong length.
    pub fn remove_column_variable(&self, column: DBColumn) -> Option<&[u8]> {
        if self.matches_column(column) {
            let subkey = &self.key[column.as_bytes().len()..];
            if subkey.len() == column.key_size() {
                return Some(subkey);
            }
        }
        None
    }

    pub fn from_vec(key: Vec<u8>) -> Self {
        Self { key }
    }
}
