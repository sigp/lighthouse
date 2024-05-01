//! This module implements a LRU cache for storing partially available blocks and blobs.
//! When the cache overflows, the least recently used items are persisted to the database.
//! This prevents lighthouse from using too much memory storing unfinalized blocks and blobs
//! if the chain were to lose finality.
//!
//! ## Deadlock safety
//!
//! The main object in this module is the `OverflowLruCache`. It contains two locks:
//!
//! - `self.critical` is an `RwLock` that protects content stored in memory.
//! - `self.maintenance_lock` is held when moving data between memory and disk.
//!
//! You mostly need to ensure that you don't try to hold the critical lock more than once
//!
//! ## Basic Algorithm
//!
//! As blocks and blobs come in from the network, their components are stored in memory in
//! this cache. When a block becomes fully available, it is removed from the cache and
//! imported into fork-choice. Blocks/blobs that remain unavailable will linger in the
//! cache until they are older than the finalized epoch or older than the data availability
//! cutoff. In the event the chain is not finalizing, the cache will eventually overflow and
//! the least recently used items will be persisted to disk. When this happens, we will still
//! store the hash of the block in memory so we always know we have data for that block
//! without needing to check the database.
//!
//! When the client is shut down, all pending components are persisted in the database.
//! On startup, the keys of these components are stored in memory and will be loaded in
//! the cache when they are accessed.

use super::state_lru_cache::{DietAvailabilityPendingExecutedBlock, StateLRUCache};
use crate::beacon_chain::BeaconStore;
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableBlock, AvailableExecutedBlock,
};
use crate::data_availability_checker::{Availability, AvailabilityCheckError};
use crate::store::{DBColumn, KeyValueStore};
use crate::BeaconChainTypes;
use lru::LruCache;
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use std::num::NonZeroUsize;
use std::{collections::HashSet, sync::Arc};
use types::blob_sidecar::BlobIdentifier;
use types::{BlobSidecar, ChainSpec, Epoch, EthSpec, Hash256};

/// This represents the components of a partially available block
///
/// The blobs are all gossip and kzg verified.
/// The block has completed all verifications except the availability check.
#[derive(Encode, Decode, Clone)]
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub verified_blobs: FixedVector<Option<KzgVerifiedBlob<E>>, E::MaxBlobsPerBlock>,
    pub executed_block: Option<DietAvailabilityPendingExecutedBlock<E>>,
}

impl<E: EthSpec> PendingComponents<E> {
    /// Returns an immutable reference to the cached block.
    pub fn get_cached_block(&self) -> &Option<DietAvailabilityPendingExecutedBlock<E>> {
        &self.executed_block
    }

    /// Returns an immutable reference to the fixed vector of cached blobs.
    pub fn get_cached_blobs(
        &self,
    ) -> &FixedVector<Option<KzgVerifiedBlob<E>>, E::MaxBlobsPerBlock> {
        &self.verified_blobs
    }

    /// Returns a mutable reference to the cached block.
    pub fn get_cached_block_mut(&mut self) -> &mut Option<DietAvailabilityPendingExecutedBlock<E>> {
        &mut self.executed_block
    }

    /// Returns a mutable reference to the fixed vector of cached blobs.
    pub fn get_cached_blobs_mut(
        &mut self,
    ) -> &mut FixedVector<Option<KzgVerifiedBlob<E>>, E::MaxBlobsPerBlock> {
        &mut self.verified_blobs
    }

    /// Checks if a blob exists at the given index in the cache.
    ///
    /// Returns:
    /// - `true` if a blob exists at the given index.
    /// - `false` otherwise.
    pub fn blob_exists(&self, blob_index: usize) -> bool {
        self.get_cached_blobs()
            .get(blob_index)
            .map(|b| b.is_some())
            .unwrap_or(false)
    }

    /// Returns the number of blobs that are expected to be present. Returns `None` if we don't have a
    /// block.
    ///
    /// This corresponds to the number of commitments that are present in a block.
    pub fn num_expected_blobs(&self) -> Option<usize> {
        self.get_cached_block()
            .as_ref()
            .map(|b| b.get_commitments().len())
    }

    /// Returns the number of blobs that have been received and are stored in the cache.
    pub fn num_received_blobs(&self) -> usize {
        self.get_cached_blobs().iter().flatten().count()
    }

    /// Inserts a block into the cache.
    pub fn insert_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        *self.get_cached_block_mut() = Some(block)
    }

    /// Inserts a blob at a specific index in the cache.
    ///
    /// Existing blob at the index will be replaced.
    pub fn insert_blob_at_index(&mut self, blob_index: usize, blob: KzgVerifiedBlob<E>) {
        if let Some(b) = self.get_cached_blobs_mut().get_mut(blob_index) {
            *b = Some(blob);
        }
    }

    /// Merges a given set of blobs into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists.
    /// 2. The block exists and its commitment matches the blob's commitment.
    pub fn merge_blobs(
        &mut self,
        blobs: FixedVector<Option<KzgVerifiedBlob<E>>, E::MaxBlobsPerBlock>,
    ) {
        for (index, blob) in blobs.iter().cloned().enumerate() {
            let Some(blob) = blob else { continue };
            self.merge_single_blob(index, blob);
        }
    }

    /// Merges a single blob into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists, or
    /// 2. The block exists and its commitment matches the blob's commitment.
    pub fn merge_single_blob(&mut self, index: usize, blob: KzgVerifiedBlob<E>) {
        if let Some(cached_block) = self.get_cached_block() {
            let block_commitment_opt = cached_block.get_commitments().get(index).copied();
            if let Some(block_commitment) = block_commitment_opt {
                if block_commitment == *blob.get_commitment() {
                    self.insert_blob_at_index(index, blob)
                }
            }
        } else if !self.blob_exists(index) {
            self.insert_blob_at_index(index, blob)
        }
    }

    /// Inserts a new block and revalidates the existing blobs against it.
    ///
    /// Blobs that don't match the new block's commitments are evicted.
    pub fn merge_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        self.insert_block(block);
        let reinsert = std::mem::take(self.get_cached_blobs_mut());
        self.merge_blobs(reinsert);
    }

    /// Checks if the block and all of its expected blobs are available in the cache.
    ///
    /// Returns `true` if both the block exists and the number of received blobs matches the number
    /// of expected blobs.
    pub fn is_available(&self) -> bool {
        if let Some(num_expected_blobs) = self.num_expected_blobs() {
            num_expected_blobs == self.num_received_blobs()
        } else {
            false
        }
    }

    /// Returns an empty `PendingComponents` object with the given block root.
    pub fn empty(block_root: Hash256) -> Self {
        Self {
            block_root,
            verified_blobs: FixedVector::default(),
            executed_block: None,
        }
    }

    /// Verifies an `SignedBeaconBlock` against a set of KZG verified blobs.
    /// This does not check whether a block *should* have blobs, these checks should have been
    /// completed when producing the `AvailabilityPendingBlock`.
    ///
    /// WARNING: This function can potentially take a lot of time if the state needs to be
    /// reconstructed from disk. Ensure you are not holding any write locks while calling this.
    pub fn make_available<R>(self, recover: R) -> Result<Availability<E>, AvailabilityCheckError>
    where
        R: FnOnce(
            DietAvailabilityPendingExecutedBlock<E>,
        ) -> Result<AvailabilityPendingExecutedBlock<E>, AvailabilityCheckError>,
    {
        let Self {
            block_root,
            verified_blobs,
            executed_block,
        } = self;

        let blobs_available_timestamp = verified_blobs
            .iter()
            .flatten()
            .map(|blob| blob.seen_timestamp())
            .max();

        let Some(diet_executed_block) = executed_block else {
            return Err(AvailabilityCheckError::Unexpected);
        };
        let num_blobs_expected = diet_executed_block.num_blobs_expected();
        let Some(verified_blobs) = verified_blobs
            .into_iter()
            .cloned()
            .map(|b| b.map(|b| b.to_blob()))
            .take(num_blobs_expected)
            .collect::<Option<Vec<_>>>()
        else {
            return Err(AvailabilityCheckError::Unexpected);
        };
        let verified_blobs = VariableList::new(verified_blobs)?;

        let executed_block = recover(diet_executed_block)?;

        let AvailabilityPendingExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        } = executed_block;

        let available_block = AvailableBlock {
            block_root,
            block,
            blobs: Some(verified_blobs),
            blobs_available_timestamp,
        };
        Ok(Availability::Available(Box::new(
            AvailableExecutedBlock::new(available_block, import_data, payload_verification_outcome),
        )))
    }

    /// Returns the epoch of the block if it is cached, otherwise returns the epoch of the first blob.
    pub fn epoch(&self) -> Option<Epoch> {
        self.executed_block
            .as_ref()
            .map(|pending_block| pending_block.as_block().epoch())
            .or_else(|| {
                for maybe_blob in self.verified_blobs.iter() {
                    if maybe_blob.is_some() {
                        return maybe_blob.as_ref().map(|kzg_verified_blob| {
                            kzg_verified_blob
                                .as_blob()
                                .slot()
                                .epoch(E::slots_per_epoch())
                        });
                    }
                }
                None
            })
    }
}

/// Blocks and blobs are stored in the database sequentially so that it's
/// fast to iterate over all the data for a particular block.
#[derive(Debug, PartialEq)]
enum OverflowKey {
    Block(Hash256),
    Blob(Hash256, u8),
}

impl OverflowKey {
    pub fn from_block_root(block_root: Hash256) -> Self {
        Self::Block(block_root)
    }

    pub fn from_blob_id<E: EthSpec>(
        blob_id: BlobIdentifier,
    ) -> Result<Self, AvailabilityCheckError> {
        if blob_id.index > E::max_blobs_per_block() as u64 || blob_id.index > u8::MAX as u64 {
            return Err(AvailabilityCheckError::BlobIndexInvalid(blob_id.index));
        }
        Ok(Self::Blob(blob_id.block_root, blob_id.index as u8))
    }

    pub fn root(&self) -> &Hash256 {
        match self {
            Self::Block(root) => root,
            Self::Blob(root, _) => root,
        }
    }
}

/// A wrapper around BeaconStore<T> that implements various
/// methods used for saving and retrieving blocks / blobs
/// from the store (for organization)
struct OverflowStore<T: BeaconChainTypes>(BeaconStore<T>);

impl<T: BeaconChainTypes> OverflowStore<T> {
    /// Store pending components in the database
    pub fn persist_pending_components(
        &self,
        block_root: Hash256,
        mut pending_components: PendingComponents<T::EthSpec>,
    ) -> Result<(), AvailabilityCheckError> {
        let col = DBColumn::OverflowLRUCache;

        if let Some(block) = pending_components.executed_block.take() {
            let key = OverflowKey::from_block_root(block_root);
            self.0
                .hot_db
                .put_bytes(col.as_str(), &key.as_ssz_bytes(), &block.as_ssz_bytes())?
        }

        for blob in Vec::from(pending_components.verified_blobs)
            .into_iter()
            .flatten()
        {
            let key = OverflowKey::from_blob_id::<T::EthSpec>(BlobIdentifier {
                block_root,
                index: blob.blob_index(),
            })?;

            self.0
                .hot_db
                .put_bytes(col.as_str(), &key.as_ssz_bytes(), &blob.as_ssz_bytes())?
        }

        Ok(())
    }

    /// Load the pending components that we have in the database for a given block root
    pub fn load_pending_components(
        &self,
        block_root: Hash256,
    ) -> Result<Option<PendingComponents<T::EthSpec>>, AvailabilityCheckError> {
        // read everything from disk and reconstruct
        let mut maybe_pending_components = None;
        for res in self
            .0
            .hot_db
            .iter_raw_entries(DBColumn::OverflowLRUCache, block_root.as_bytes())
        {
            let (key_bytes, value_bytes) = res?;
            match OverflowKey::from_ssz_bytes(&key_bytes)? {
                OverflowKey::Block(_) => {
                    maybe_pending_components
                        .get_or_insert_with(|| PendingComponents::empty(block_root))
                        .executed_block =
                        Some(DietAvailabilityPendingExecutedBlock::from_ssz_bytes(
                            value_bytes.as_slice(),
                        )?);
                }
                OverflowKey::Blob(_, index) => {
                    *maybe_pending_components
                        .get_or_insert_with(|| PendingComponents::empty(block_root))
                        .verified_blobs
                        .get_mut(index as usize)
                        .ok_or(AvailabilityCheckError::BlobIndexInvalid(index as u64))? =
                        Some(KzgVerifiedBlob::from_ssz_bytes(value_bytes.as_slice())?);
                }
            }
        }

        Ok(maybe_pending_components)
    }

    /// Returns the hashes of all the blocks we have any data for on disk
    pub fn read_keys_on_disk(&self) -> Result<HashSet<Hash256>, AvailabilityCheckError> {
        let mut disk_keys = HashSet::new();
        for res in self.0.hot_db.iter_raw_keys(DBColumn::OverflowLRUCache, &[]) {
            let key_bytes = res?;
            disk_keys.insert(*OverflowKey::from_ssz_bytes(&key_bytes)?.root());
        }
        Ok(disk_keys)
    }

    /// Load a single blob from the database
    pub fn load_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        let key = OverflowKey::from_blob_id::<T::EthSpec>(*blob_id)?;

        self.0
            .hot_db
            .get_bytes(DBColumn::OverflowLRUCache.as_str(), &key.as_ssz_bytes())?
            .map(|blob_bytes| Arc::<BlobSidecar<T::EthSpec>>::from_ssz_bytes(blob_bytes.as_slice()))
            .transpose()
            .map_err(|e| e.into())
    }

    /// Delete a set of keys from the database
    pub fn delete_keys(&self, keys: &Vec<OverflowKey>) -> Result<(), AvailabilityCheckError> {
        for key in keys {
            self.0
                .hot_db
                .key_delete(DBColumn::OverflowLRUCache.as_str(), &key.as_ssz_bytes())?;
        }
        Ok(())
    }
}

/// This data stores the *critical* data that we need to keep in memory
/// protected by the RWLock
struct Critical<T: BeaconChainTypes> {
    /// This is the LRU cache of pending components
    pub in_memory: LruCache<Hash256, PendingComponents<T::EthSpec>>,
    /// This holds all the roots of the blocks for which we have
    /// `PendingComponents` in the database.
    pub store_keys: HashSet<Hash256>,
}

impl<T: BeaconChainTypes> Critical<T> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            in_memory: LruCache::new(capacity),
            store_keys: HashSet::new(),
        }
    }

    pub fn reload_store_keys(
        &mut self,
        overflow_store: &OverflowStore<T>,
    ) -> Result<(), AvailabilityCheckError> {
        let disk_keys = overflow_store.read_keys_on_disk()?;
        self.store_keys = disk_keys;
        Ok(())
    }

    /// Returns true if the block root is known, without altering the LRU ordering
    pub fn has_block(&self, block_root: &Hash256) -> bool {
        self.in_memory.peek(block_root).is_some() || self.store_keys.contains(block_root)
    }

    /// This only checks for the blobs in memory
    pub fn peek_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        if let Some(pending_components) = self.in_memory.peek(&blob_id.block_root) {
            Ok(pending_components
                .verified_blobs
                .get(blob_id.index as usize)
                .ok_or(AvailabilityCheckError::BlobIndexInvalid(blob_id.index))?
                .as_ref()
                .map(|blob| blob.clone_blob()))
        } else {
            Ok(None)
        }
    }

    pub fn peek_pending_components(
        &self,
        block_root: &Hash256,
    ) -> Option<&PendingComponents<T::EthSpec>> {
        self.in_memory.peek(block_root)
    }

    /// Puts the pending components in the LRU cache. If the cache
    /// is at capacity, the LRU entry is written to the store first
    pub fn put_pending_components(
        &mut self,
        block_root: Hash256,
        pending_components: PendingComponents<T::EthSpec>,
        overflow_store: &OverflowStore<T>,
    ) -> Result<(), AvailabilityCheckError> {
        if self.in_memory.len() == self.in_memory.cap().get() {
            // cache will overflow, must write lru entry to disk
            if let Some((lru_key, lru_value)) = self.in_memory.pop_lru() {
                overflow_store.persist_pending_components(lru_key, lru_value)?;
                self.store_keys.insert(lru_key);
            }
        }
        self.in_memory.put(block_root, pending_components);
        Ok(())
    }

    /// Removes and returns the pending_components corresponding to
    /// the `block_root` or `None` if it does not exist
    pub fn pop_pending_components(
        &mut self,
        block_root: Hash256,
        store: &OverflowStore<T>,
    ) -> Result<Option<PendingComponents<T::EthSpec>>, AvailabilityCheckError> {
        match self.in_memory.pop_entry(&block_root) {
            Some((_, pending_components)) => Ok(Some(pending_components)),
            None => {
                // not in memory, is it in the store?
                if self.store_keys.remove(&block_root) {
                    // We don't need to remove the data from the store as we have removed it from
                    // `store_keys` so we won't go looking for it on disk. The maintenance thread
                    // will remove it from disk the next time it runs.
                    store.load_pending_components(block_root)
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Returns the number of pending component entries in memory.
    pub fn num_blocks(&self) -> usize {
        self.in_memory.len()
    }

    /// Returns the number of entries that have overflowed to disk.
    pub fn num_store_entries(&self) -> usize {
        self.store_keys.len()
    }
}

/// This is the main struct for this module. Outside methods should
/// interact with the cache through this.
pub struct OverflowLRUCache<T: BeaconChainTypes> {
    /// Contains all the data we keep in memory, protected by an RwLock
    critical: RwLock<Critical<T>>,
    /// This is how we read and write components to the disk
    overflow_store: OverflowStore<T>,
    /// This cache holds a limited number of states in memory and reconstructs them
    /// from disk when necessary. This is necessary until we merge tree-states
    state_cache: StateLRUCache<T>,
    /// Mutex to guard maintenance methods which move data between disk and memory
    maintenance_lock: Mutex<()>,
    /// The capacity of the LRU cache
    capacity: NonZeroUsize,
}

impl<T: BeaconChainTypes> OverflowLRUCache<T> {
    pub fn new(
        capacity: NonZeroUsize,
        beacon_store: BeaconStore<T>,
        spec: ChainSpec,
    ) -> Result<Self, AvailabilityCheckError> {
        let overflow_store = OverflowStore(beacon_store.clone());
        let mut critical = Critical::new(capacity);
        critical.reload_store_keys(&overflow_store)?;
        Ok(Self {
            critical: RwLock::new(critical),
            overflow_store,
            state_cache: StateLRUCache::new(beacon_store, spec),
            maintenance_lock: Mutex::new(()),
            capacity,
        })
    }

    /// Returns true if the block root is known, without altering the LRU ordering
    pub fn has_block(&self, block_root: &Hash256) -> bool {
        self.critical.read().has_block(block_root)
    }

    /// Fetch a blob from the cache without affecting the LRU ordering
    pub fn peek_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        let read_lock = self.critical.read();
        if let Some(blob) = read_lock.peek_blob(blob_id)? {
            Ok(Some(blob))
        } else if read_lock.store_keys.contains(&blob_id.block_root) {
            drop(read_lock);
            self.overflow_store.load_blob(blob_id)
        } else {
            Ok(None)
        }
    }

    pub fn peek_pending_components<R, F: FnOnce(Option<&PendingComponents<T::EthSpec>>) -> R>(
        &self,
        block_root: &Hash256,
        f: F,
    ) -> R {
        f(self.critical.read().peek_pending_components(block_root))
    }

    pub fn put_kzg_verified_blobs<I: IntoIterator<Item = KzgVerifiedBlob<T::EthSpec>>>(
        &self,
        block_root: Hash256,
        kzg_verified_blobs: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut fixed_blobs = FixedVector::default();

        for blob in kzg_verified_blobs {
            if let Some(blob_opt) = fixed_blobs.get_mut(blob.blob_index() as usize) {
                *blob_opt = Some(blob);
            }
        }

        let mut write_lock = self.critical.write();

        // Grab existing entry or create a new entry.
        let mut pending_components = write_lock
            .pop_pending_components(block_root, &self.overflow_store)?
            .unwrap_or_else(|| PendingComponents::empty(block_root));

        // Merge in the blobs.
        pending_components.merge_blobs(fixed_blobs);

        if pending_components.is_available() {
            // No need to hold the write lock anymore
            drop(write_lock);
            pending_components.make_available(|diet_block| {
                self.state_cache.recover_pending_executed_block(diet_block)
            })
        } else {
            write_lock.put_pending_components(
                block_root,
                pending_components,
                &self.overflow_store,
            )?;
            Ok(Availability::MissingComponents(block_root))
        }
    }

    /// Check if we have all the blobs for a block. If we do, return the Availability variant that
    /// triggers import of the block.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut write_lock = self.critical.write();
        let block_root = executed_block.import_data.block_root;

        // register the block to get the diet block
        let diet_executed_block = self
            .state_cache
            .register_pending_executed_block(executed_block);

        // Grab existing entry or create a new entry.
        let mut pending_components = write_lock
            .pop_pending_components(block_root, &self.overflow_store)?
            .unwrap_or_else(|| PendingComponents::empty(block_root));

        // Merge in the block.
        pending_components.merge_block(diet_executed_block);

        // Check if we have all components and entire set is consistent.
        if pending_components.is_available() {
            // No need to hold the write lock anymore
            drop(write_lock);
            pending_components.make_available(|diet_block| {
                self.state_cache.recover_pending_executed_block(diet_block)
            })
        } else {
            write_lock.put_pending_components(
                block_root,
                pending_components,
                &self.overflow_store,
            )?;
            Ok(Availability::MissingComponents(block_root))
        }
    }

    /// write all in memory objects to disk
    pub fn write_all_to_disk(&self) -> Result<(), AvailabilityCheckError> {
        let maintenance_lock = self.maintenance_lock.lock();
        let mut critical_lock = self.critical.write();

        let mut swap_lru = LruCache::new(self.capacity);
        std::mem::swap(&mut swap_lru, &mut critical_lock.in_memory);

        for (root, pending_components) in swap_lru.into_iter() {
            self.overflow_store
                .persist_pending_components(root, pending_components)?;
            critical_lock.store_keys.insert(root);
        }

        drop(critical_lock);
        drop(maintenance_lock);
        Ok(())
    }

    /// maintain the cache
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        // ensure memory usage is below threshold
        let threshold = self.capacity.get() * 3 / 4;
        self.maintain_threshold(threshold, cutoff_epoch)?;
        // clean up any keys on the disk that shouldn't be there
        self.prune_disk(cutoff_epoch)?;
        // clean up any lingering states in the state cache
        self.state_cache.do_maintenance(cutoff_epoch);
        Ok(())
    }

    /// Enforce that the size of the cache is below a given threshold by
    /// moving the least recently used items to disk.
    fn maintain_threshold(
        &self,
        threshold: usize,
        cutoff_epoch: Epoch,
    ) -> Result<(), AvailabilityCheckError> {
        // ensure only one thread at a time can be deleting things from the disk or
        // moving things between memory and storage
        let maintenance_lock = self.maintenance_lock.lock();

        let mut stored = self.critical.read().in_memory.len();
        while stored > threshold {
            let read_lock = self.critical.upgradable_read();
            let lru_entry = read_lock
                .in_memory
                .peek_lru()
                .map(|(key, value)| (*key, value.clone()));

            let Some((lru_root, lru_pending_components)) = lru_entry else {
                break;
            };

            if lru_pending_components
                .epoch()
                .map(|epoch| epoch < cutoff_epoch)
                .unwrap_or(true)
            {
                // this data is no longer needed -> delete it
                let mut write_lock = RwLockUpgradableReadGuard::upgrade(read_lock);
                write_lock.in_memory.pop_entry(&lru_root);
                stored = write_lock.in_memory.len();
                continue;
            } else {
                drop(read_lock);
            }

            // write the lru entry to disk (we aren't holding any critical locks while we do this)
            self.overflow_store
                .persist_pending_components(lru_root, lru_pending_components)?;
            // now that we've written to disk, grab the critical write lock
            let mut write_lock = self.critical.write();
            if let Some((new_lru_root_ref, _)) = write_lock.in_memory.peek_lru() {
                // need to ensure the entry we just wrote to disk wasn't updated
                // while we were writing and is still the LRU entry
                if *new_lru_root_ref == lru_root {
                    // it is still LRU entry -> delete it from memory & record that it's on disk
                    write_lock.in_memory.pop_entry(&lru_root);
                    write_lock.store_keys.insert(lru_root);
                }
            }
            stored = write_lock.in_memory.len();
            drop(write_lock);
        }

        drop(maintenance_lock);
        Ok(())
    }

    /// Delete any data on disk that shouldn't be there. This can happen if
    /// 1. The entry has been moved back to memory (or become fully available)
    /// 2. The entry belongs to a block beyond the cutoff epoch
    fn prune_disk(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        // ensure only one thread at a time can be deleting things from the disk or
        // moving things between memory and storage
        let maintenance_lock = self.maintenance_lock.lock();

        struct BlockData {
            keys: Vec<OverflowKey>,
            root: Hash256,
            epoch: Epoch,
        }

        let delete_if_outdated = |cache: &OverflowLRUCache<T>,
                                  block_data: Option<BlockData>|
         -> Result<(), AvailabilityCheckError> {
            let Some(block_data) = block_data else {
                return Ok(());
            };
            let not_in_store_keys = !cache.critical.read().store_keys.contains(&block_data.root);
            if not_in_store_keys {
                // these keys aren't supposed to be on disk
                cache.overflow_store.delete_keys(&block_data.keys)?;
            } else {
                // check this data is still relevant
                if block_data.epoch < cutoff_epoch {
                    // this data is no longer needed -> delete it
                    self.overflow_store.delete_keys(&block_data.keys)?;
                }
            }
            Ok(())
        };

        let mut current_block_data: Option<BlockData> = None;
        for res in self
            .overflow_store
            .0
            .hot_db
            .iter_raw_entries(DBColumn::OverflowLRUCache, &[])
        {
            let (key_bytes, value_bytes) = res?;
            let overflow_key = OverflowKey::from_ssz_bytes(&key_bytes)?;
            let current_root = *overflow_key.root();

            match &mut current_block_data {
                Some(block_data) if block_data.root == current_root => {
                    // still dealing with the same block
                    block_data.keys.push(overflow_key);
                }
                _ => {
                    // first time encountering data for this block
                    delete_if_outdated(self, current_block_data)?;
                    let current_epoch = match &overflow_key {
                        OverflowKey::Block(_) => {
                            DietAvailabilityPendingExecutedBlock::<T::EthSpec>::from_ssz_bytes(
                                value_bytes.as_slice(),
                            )?
                            .as_block()
                            .epoch()
                        }
                        OverflowKey::Blob(_, _) => {
                            KzgVerifiedBlob::<T::EthSpec>::from_ssz_bytes(value_bytes.as_slice())?
                                .as_blob()
                                .slot()
                                .epoch(T::EthSpec::slots_per_epoch())
                        }
                    };
                    current_block_data = Some(BlockData {
                        keys: vec![overflow_key],
                        root: current_root,
                        epoch: current_epoch,
                    });
                }
            }
        }
        // can't fall off the end
        delete_if_outdated(self, current_block_data)?;

        drop(maintenance_lock);
        Ok(())
    }

    #[cfg(test)]
    /// get the state cache for inspection (used only for tests)
    pub fn state_lru_cache(&self) -> &StateLRUCache<T> {
        &self.state_cache
    }

    /// Number of states stored in memory in the cache.
    pub fn state_cache_size(&self) -> usize {
        self.state_cache.lru_cache().read().len()
    }

    /// Number of pending component entries in memory in the cache.
    pub fn block_cache_size(&self) -> usize {
        self.critical.read().num_blocks()
    }

    /// Returns the number of entries in the cache that have overflowed to disk.
    pub fn num_store_entries(&self) -> usize {
        self.critical.read().num_store_entries()
    }
}

impl ssz::Encode for OverflowKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            OverflowKey::Block(block_hash) => {
                block_hash.ssz_append(buf);
                buf.push(0u8)
            }
            OverflowKey::Blob(block_hash, index) => {
                block_hash.ssz_append(buf);
                buf.push(*index + 1)
            }
        }
    }

    fn ssz_fixed_len() -> usize {
        <Hash256 as Encode>::ssz_fixed_len() + 1
    }

    fn ssz_bytes_len(&self) -> usize {
        match self {
            Self::Block(root) => root.ssz_bytes_len() + 1,
            Self::Blob(root, _) => root.ssz_bytes_len() + 1,
        }
    }
}

impl ssz::Decode for OverflowKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        <Hash256 as Decode>::ssz_fixed_len() + 1
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let len = bytes.len();
        let h256_len = <Hash256 as Decode>::ssz_fixed_len();
        let expected = h256_len + 1;

        if len != expected {
            Err(ssz::DecodeError::InvalidByteLength { len, expected })
        } else {
            let root_bytes = bytes
                .get(..h256_len)
                .ok_or(ssz::DecodeError::OutOfBoundsByte { i: 0 })?;
            let block_root = Hash256::from_ssz_bytes(root_bytes)?;
            let id_byte = *bytes
                .get(h256_len)
                .ok_or(ssz::DecodeError::OutOfBoundsByte { i: h256_len })?;
            match id_byte {
                0 => Ok(OverflowKey::Block(block_root)),
                n => Ok(OverflowKey::Blob(block_root, n - 1)),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        blob_verification::GossipVerifiedBlob,
        block_verification::PayloadVerificationOutcome,
        block_verification_types::{AsBlock, BlockImportData},
        data_availability_checker::STATE_LRU_CAPACITY,
        eth1_finalization_cache::Eth1FinalizationData,
        test_utils::{BaseHarnessType, BeaconChainHarness, DiskHarnessType},
    };
    use fork_choice::PayloadVerificationStatus;
    use logging::test_logger;
    use slog::{info, Logger};
    use state_processing::ConsensusContext;
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::ops::AddAssign;
    use store::{HotColdDB, ItemStore, LevelDB, StoreConfig};
    use tempfile::{tempdir, TempDir};
    use types::non_zero_usize::new_non_zero_usize;
    use types::{ExecPayload, MinimalEthSpec};

    const LOW_VALIDATOR_COUNT: usize = 32;

    fn get_store_with_spec<E: EthSpec>(
        db_path: &TempDir,
        spec: ChainSpec,
        log: Logger,
    ) -> Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>> {
        let hot_path = db_path.path().join("hot_db");
        let cold_path = db_path.path().join("cold_db");
        let blobs_path = db_path.path().join("blobs_db");
        let config = StoreConfig::default();

        HotColdDB::open(
            &hot_path,
            &cold_path,
            &blobs_path,
            |_, _, _| Ok(()),
            config,
            spec,
            log,
        )
        .expect("disk store should initialize")
    }

    // get a beacon chain harness advanced to just before deneb fork
    async fn get_deneb_chain<E: EthSpec>(
        log: Logger,
        db_path: &TempDir,
    ) -> BeaconChainHarness<DiskHarnessType<E>> {
        let altair_fork_epoch = Epoch::new(1);
        let bellatrix_fork_epoch = Epoch::new(2);
        let bellatrix_fork_slot = bellatrix_fork_epoch.start_slot(E::slots_per_epoch());
        let capella_fork_epoch = Epoch::new(3);
        let deneb_fork_epoch = Epoch::new(4);
        let deneb_fork_slot = deneb_fork_epoch.start_slot(E::slots_per_epoch());

        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(altair_fork_epoch);
        spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
        spec.capella_fork_epoch = Some(capella_fork_epoch);
        spec.deneb_fork_epoch = Some(deneb_fork_epoch);

        let chain_store = get_store_with_spec::<E>(db_path, spec.clone(), log.clone());
        let validators_keypairs =
            types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .logger(log.clone())
            .keypairs(validators_keypairs)
            .fresh_disk_store(chain_store)
            .mock_execution_layer()
            .build();

        // go to bellatrix slot
        harness.extend_to_slot(bellatrix_fork_slot).await;
        let bellatrix_head = &harness.chain.head_snapshot().beacon_block;
        assert!(bellatrix_head.as_bellatrix().is_ok());
        assert_eq!(bellatrix_head.slot(), bellatrix_fork_slot);
        assert!(
            bellatrix_head
                .message()
                .body()
                .execution_payload()
                .unwrap()
                .is_default_with_empty_roots(),
            "Bellatrix head is default payload"
        );
        // Trigger the terminal PoW block.
        harness
            .execution_block_generator()
            .move_to_terminal_block()
            .unwrap();
        // go right before deneb slot
        harness.extend_to_slot(deneb_fork_slot - 1).await;

        harness
    }

    #[test]
    fn overflow_key_encode_decode_equality() {
        type E = types::MainnetEthSpec;
        let key_block = OverflowKey::Block(Hash256::random());
        let key_blob_0 = OverflowKey::from_blob_id::<E>(BlobIdentifier {
            block_root: Hash256::random(),
            index: 0,
        })
        .expect("should create overflow key 0");
        let key_blob_1 = OverflowKey::from_blob_id::<E>(BlobIdentifier {
            block_root: Hash256::random(),
            index: 1,
        })
        .expect("should create overflow key 1");
        let key_blob_2 = OverflowKey::from_blob_id::<E>(BlobIdentifier {
            block_root: Hash256::random(),
            index: 2,
        })
        .expect("should create overflow key 2");
        let key_blob_3 = OverflowKey::from_blob_id::<E>(BlobIdentifier {
            block_root: Hash256::random(),
            index: 3,
        })
        .expect("should create overflow key 3");

        let keys = vec![key_block, key_blob_0, key_blob_1, key_blob_2, key_blob_3];
        for key in keys {
            let encoded = key.as_ssz_bytes();
            let decoded = OverflowKey::from_ssz_bytes(&encoded).expect("should decode");
            assert_eq!(key, decoded, "Encoded and decoded keys should be equal");
        }
    }

    async fn availability_pending_block<E, Hot, Cold>(
        harness: &BeaconChainHarness<BaseHarnessType<E, Hot, Cold>>,
    ) -> (
        AvailabilityPendingExecutedBlock<E>,
        Vec<GossipVerifiedBlob<BaseHarnessType<E, Hot, Cold>>>,
    )
    where
        E: EthSpec,
        Hot: ItemStore<E>,
        Cold: ItemStore<E>,
    {
        let chain = &harness.chain;
        let log = chain.log.clone();
        let head = chain.head_snapshot();
        let parent_state = head.beacon_state.clone();

        let target_slot = chain.slot().expect("should get slot") + 1;
        let parent_root = head.beacon_block_root;
        let parent_block = chain
            .get_blinded_block(&parent_root)
            .expect("should get block")
            .expect("should have block");

        let parent_eth1_finalization_data = Eth1FinalizationData {
            eth1_data: parent_block.message().body().eth1_data().clone(),
            eth1_deposit_index: 0,
        };

        let (signed_beacon_block_hash, (block, maybe_blobs), state) = harness
            .add_block_at_slot(target_slot, parent_state)
            .await
            .expect("should add block");
        let block_root = signed_beacon_block_hash.into();
        assert_eq!(
            block_root,
            block.canonical_root(),
            "block root should match"
        );

        // log kzg commitments
        info!(log, "printing kzg commitments");
        for comm in Vec::from(
            block
                .message()
                .body()
                .blob_kzg_commitments()
                .expect("should be deneb fork")
                .clone(),
        ) {
            info!(log, "kzg commitment"; "commitment" => ?comm);
        }
        info!(log, "done printing kzg commitments");

        let gossip_verified_blobs = if let Some((kzg_proofs, blobs)) = maybe_blobs {
            let sidecars = BlobSidecar::build_sidecars(blobs, &block, kzg_proofs).unwrap();
            Vec::from(sidecars)
                .into_iter()
                .map(|sidecar| {
                    let subnet = sidecar.index;
                    GossipVerifiedBlob::new(sidecar, subnet, &harness.chain)
                        .expect("should validate blob")
                })
                .collect()
        } else {
            vec![]
        };

        let slot = block.slot();
        let consensus_context = ConsensusContext::<E>::new(slot);
        let import_data: BlockImportData<E> = BlockImportData {
            block_root,
            state,
            parent_block,
            parent_eth1_finalization_data,
            confirmed_state_roots: vec![],
            consensus_context,
        };

        let payload_verification_outcome = PayloadVerificationOutcome {
            payload_verification_status: PayloadVerificationStatus::Verified,
            is_valid_merge_transition_block: false,
        };

        let availability_pending_block = AvailabilityPendingExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        };

        (availability_pending_block, gossip_verified_blobs)
    }

    async fn setup_harness_and_cache<E, T>(
        capacity: usize,
    ) -> (
        BeaconChainHarness<DiskHarnessType<E>>,
        Arc<OverflowLRUCache<T>>,
        TempDir,
    )
    where
        E: EthSpec,
        T: BeaconChainTypes<HotStore = LevelDB<E>, ColdStore = LevelDB<E>, EthSpec = E>,
    {
        let log = test_logger();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness = get_deneb_chain(log.clone(), &chain_db_path).await;
        let spec = harness.spec.clone();
        let test_store = harness.chain.store.clone();
        let capacity_non_zero = new_non_zero_usize(capacity);
        let cache = Arc::new(
            OverflowLRUCache::<T>::new(capacity_non_zero, test_store, spec.clone())
                .expect("should create cache"),
        );
        (harness, cache, chain_db_path)
    }

    #[tokio::test]
    async fn overflow_cache_test_insert_components() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let (pending_block, blobs) = availability_pending_block(&harness).await;
        let root = pending_block.import_data.block_root;

        let blobs_expected = pending_block.num_blobs_expected();
        assert_eq!(
            blobs.len(),
            blobs_expected,
            "should have expected number of blobs"
        );
        assert!(
            cache.critical.read().in_memory.is_empty(),
            "cache should be empty"
        );
        let availability = cache
            .put_pending_executed_block(pending_block)
            .expect("should put block");
        if blobs_expected == 0 {
            assert!(
                matches!(availability, Availability::Available(_)),
                "block doesn't have blobs, should be available"
            );
            assert_eq!(
                cache.critical.read().in_memory.len(),
                0,
                "cache should be empty because we don't have blobs"
            );
        } else {
            assert!(
                matches!(availability, Availability::MissingComponents(_)),
                "should be pending blobs"
            );
            assert_eq!(
                cache.critical.read().in_memory.len(),
                1,
                "cache should have one block"
            );
            assert!(
                cache.critical.read().in_memory.peek(&root).is_some(),
                "newly inserted block should exist in memory"
            );
        }

        let mut kzg_verified_blobs = Vec::new();
        for (blob_index, gossip_blob) in blobs.into_iter().enumerate() {
            kzg_verified_blobs.push(gossip_blob.into_inner());
            let availability = cache
                .put_kzg_verified_blobs(root, kzg_verified_blobs.clone())
                .expect("should put blob");
            if blob_index == blobs_expected - 1 {
                assert!(matches!(availability, Availability::Available(_)));
            } else {
                assert!(matches!(availability, Availability::MissingComponents(_)));
                assert_eq!(cache.critical.read().in_memory.len(), 1);
            }
        }
        assert!(
            cache.critical.read().in_memory.is_empty(),
            "cache should be empty now that all components available"
        );

        let (pending_block, blobs) = availability_pending_block(&harness).await;
        let blobs_expected = pending_block.num_blobs_expected();
        assert_eq!(
            blobs.len(),
            blobs_expected,
            "should have expected number of blobs"
        );
        let root = pending_block.import_data.block_root;
        let mut kzg_verified_blobs = vec![];
        for gossip_blob in blobs {
            kzg_verified_blobs.push(gossip_blob.into_inner());
            let availability = cache
                .put_kzg_verified_blobs(root, kzg_verified_blobs.clone())
                .expect("should put blob");
            assert_eq!(
                availability,
                Availability::MissingComponents(root),
                "should be pending block"
            );
            assert_eq!(cache.critical.read().in_memory.len(), 1);
        }
        let availability = cache
            .put_pending_executed_block(pending_block)
            .expect("should put block");
        assert!(
            matches!(availability, Availability::Available(_)),
            "block should be available: {:?}",
            availability
        );
        assert!(
            cache.critical.read().in_memory.is_empty(),
            "cache should be empty now that all components available"
        );
    }

    #[tokio::test]
    async fn overflow_cache_test_overflow() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let mut pending_blocks = VecDeque::new();
        let mut pending_blobs = VecDeque::new();
        let mut roots = VecDeque::new();
        while pending_blobs.len() < capacity + 1 {
            let (pending_block, blobs) = availability_pending_block(&harness).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let root = pending_block.block.canonical_root();
            pending_blocks.push_back(pending_block);
            pending_blobs.push_back(blobs);
            roots.push_back(root);
        }

        for i in 0..capacity {
            cache
                .put_pending_executed_block(pending_blocks.pop_front().expect("should have block"))
                .expect("should put block");
            assert_eq!(cache.critical.read().in_memory.len(), i + 1);
        }
        for root in roots.iter().take(capacity) {
            assert!(cache.critical.read().in_memory.peek(root).is_some());
        }
        assert_eq!(
            cache.critical.read().in_memory.len(),
            capacity,
            "cache should be full"
        );
        // the first block should be the lru entry
        assert_eq!(
            *cache
                .critical
                .read()
                .in_memory
                .peek_lru()
                .expect("should exist")
                .0,
            roots[0],
            "first block should be lru"
        );

        cache
            .put_pending_executed_block(pending_blocks.pop_front().expect("should have block"))
            .expect("should put block");
        assert_eq!(
            cache.critical.read().in_memory.len(),
            capacity,
            "cache should be full"
        );
        assert!(
            cache.critical.read().in_memory.peek(&roots[0]).is_none(),
            "first block should be evicted"
        );
        assert_eq!(
            *cache
                .critical
                .read()
                .in_memory
                .peek_lru()
                .expect("should exist")
                .0,
            roots[1],
            "second block should be lru"
        );

        assert!(cache
            .overflow_store
            .load_pending_components(roots[0])
            .expect("should exist")
            .is_some());

        let threshold = capacity * 3 / 4;
        cache
            .maintain_threshold(threshold, Epoch::new(0))
            .expect("should maintain threshold");
        assert_eq!(
            cache.critical.read().in_memory.len(),
            threshold,
            "cache should have been maintained"
        );

        let store_keys = cache
            .overflow_store
            .read_keys_on_disk()
            .expect("should read keys");
        assert_eq!(store_keys.len(), 2);
        assert!(store_keys.contains(&roots[0]));
        assert!(store_keys.contains(&roots[1]));
        assert!(cache.critical.read().store_keys.contains(&roots[0]));
        assert!(cache.critical.read().store_keys.contains(&roots[1]));

        let blobs_0 = pending_blobs.pop_front().expect("should have blobs");
        let expected_blobs = blobs_0.len();
        let mut kzg_verified_blobs = vec![];
        for (blob_index, gossip_blob) in blobs_0.into_iter().enumerate() {
            kzg_verified_blobs.push(gossip_blob.into_inner());
            let availability = cache
                .put_kzg_verified_blobs(roots[0], kzg_verified_blobs.clone())
                .expect("should put blob");
            if blob_index == expected_blobs - 1 {
                assert!(matches!(availability, Availability::Available(_)));
            } else {
                // the first block should be brought back into memory
                assert!(
                    cache.critical.read().in_memory.peek(&roots[0]).is_some(),
                    "first block should be in memory"
                );
                assert!(matches!(availability, Availability::MissingComponents(_)));
            }
        }
        assert_eq!(
            cache.critical.read().in_memory.len(),
            threshold,
            "cache should no longer have the first block"
        );
        cache.prune_disk(Epoch::new(0)).expect("should prune disk");
        assert!(
            cache
                .overflow_store
                .load_pending_components(roots[1])
                .expect("no error")
                .is_some(),
            "second block should still be on disk"
        );
        assert!(
            cache
                .overflow_store
                .load_pending_components(roots[0])
                .expect("no error")
                .is_none(),
            "first block should not be on disk"
        );
    }

    #[tokio::test]
    async fn overflow_cache_test_maintenance() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = E::slots_per_epoch() as usize;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let n_epochs = 4;
        let mut pending_blocks = VecDeque::new();
        let mut pending_blobs = VecDeque::new();
        let mut epoch_count = BTreeMap::new();
        while pending_blobs.len() < n_epochs * capacity {
            let (pending_block, blobs) = availability_pending_block(&harness).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let epoch = pending_block
                .block
                .as_block()
                .slot()
                .epoch(E::slots_per_epoch());
            epoch_count.entry(epoch).or_insert_with(|| 0).add_assign(1);

            pending_blocks.push_back(pending_block);
            pending_blobs.push_back(blobs);
        }

        for _ in 0..(n_epochs * capacity) {
            let pending_block = pending_blocks.pop_front().expect("should have block");
            let mut pending_block_blobs = pending_blobs.pop_front().expect("should have blobs");
            let block_root = pending_block.block.as_block().canonical_root();
            let expected_blobs = pending_block.num_blobs_expected();
            if expected_blobs > 1 {
                // might as well add a blob too
                let one_blob = pending_block_blobs
                    .pop()
                    .expect("should have at least one blob");
                let kzg_verified_blobs = vec![one_blob.into_inner()];
                // generate random boolean
                let block_first = (rand::random::<usize>() % 2) == 0;
                if block_first {
                    let availability = cache
                        .put_pending_executed_block(pending_block)
                        .expect("should put block");
                    assert!(
                        matches!(availability, Availability::MissingComponents(_)),
                        "should have pending blobs"
                    );
                    let availability = cache
                        .put_kzg_verified_blobs(block_root, kzg_verified_blobs)
                        .expect("should put blob");
                    assert!(
                        matches!(availability, Availability::MissingComponents(_)),
                        "availabilty should be pending blobs: {:?}",
                        availability
                    );
                } else {
                    let availability = cache
                        .put_kzg_verified_blobs(block_root, kzg_verified_blobs)
                        .expect("should put blob");
                    let root = pending_block.block.as_block().canonical_root();
                    assert_eq!(
                        availability,
                        Availability::MissingComponents(root),
                        "should be pending block"
                    );
                    let availability = cache
                        .put_pending_executed_block(pending_block)
                        .expect("should put block");
                    assert!(
                        matches!(availability, Availability::MissingComponents(_)),
                        "should have pending blobs"
                    );
                }
            } else {
                let availability = cache
                    .put_pending_executed_block(pending_block)
                    .expect("should put block");
                assert!(
                    matches!(availability, Availability::MissingComponents(_)),
                    "should be pending blobs"
                );
            }
        }

        // now we should have a full cache spanning multiple epochs
        // run the maintenance routine for increasing epochs and ensure that the cache is pruned
        assert_eq!(
            cache.critical.read().in_memory.len(),
            capacity,
            "cache memory should be full"
        );
        let store_keys = cache
            .overflow_store
            .read_keys_on_disk()
            .expect("should read keys");
        assert_eq!(
            store_keys.len(),
            capacity * (n_epochs - 1),
            "cache disk should have the rest"
        );
        let mut expected_length = n_epochs * capacity;
        for (epoch, count) in epoch_count {
            cache
                .do_maintenance(epoch + 1)
                .expect("should run maintenance");
            let disk_keys = cache
                .overflow_store
                .read_keys_on_disk()
                .expect("should read keys")
                .len();
            let mem_keys = cache.critical.read().in_memory.len();
            expected_length -= count;
            info!(
                harness.chain.log,
                "EPOCH: {} DISK KEYS: {} MEM KEYS: {} TOTAL: {} EXPECTED: {}",
                epoch,
                disk_keys,
                mem_keys,
                (disk_keys + mem_keys),
                std::cmp::max(expected_length, capacity * 3 / 4),
            );
            assert_eq!(
                (disk_keys + mem_keys),
                std::cmp::max(expected_length, capacity * 3 / 4),
                "cache should be pruned"
            );
        }
    }

    #[tokio::test]
    async fn overflow_cache_test_persist_recover() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = E::slots_per_epoch() as usize;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let n_epochs = 4;
        let mut pending_blocks = VecDeque::new();
        let mut pending_blobs = VecDeque::new();
        let mut epoch_count = BTreeMap::new();
        while pending_blobs.len() < n_epochs * capacity {
            let (pending_block, blobs) = availability_pending_block(&harness).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let epoch = pending_block
                .block
                .as_block()
                .slot()
                .epoch(E::slots_per_epoch());
            epoch_count.entry(epoch).or_insert_with(|| 0).add_assign(1);

            pending_blocks.push_back(pending_block);
            pending_blobs.push_back(blobs);
        }

        let mut remaining_blobs = HashMap::new();
        for _ in 0..(n_epochs * capacity) {
            let pending_block = pending_blocks.pop_front().expect("should have block");
            let mut pending_block_blobs = pending_blobs.pop_front().expect("should have blobs");
            let block_root = pending_block.block.as_block().canonical_root();
            let expected_blobs = pending_block.num_blobs_expected();
            if expected_blobs > 1 {
                // might as well add a blob too
                let one_blob = pending_block_blobs
                    .pop()
                    .expect("should have at least one blob");
                let kzg_verified_blobs = vec![one_blob.into_inner()];
                // generate random boolean
                let block_first = (rand::random::<usize>() % 2) == 0;
                if block_first {
                    let availability = cache
                        .put_pending_executed_block(pending_block)
                        .expect("should put block");
                    assert!(
                        matches!(availability, Availability::MissingComponents(_)),
                        "should have pending blobs"
                    );
                    let availability = cache
                        .put_kzg_verified_blobs(block_root, kzg_verified_blobs)
                        .expect("should put blob");
                    assert!(
                        matches!(availability, Availability::MissingComponents(_)),
                        "availabilty should be pending blobs: {:?}",
                        availability
                    );
                } else {
                    let availability = cache
                        .put_kzg_verified_blobs(block_root, kzg_verified_blobs)
                        .expect("should put blob");
                    let root = pending_block.block.as_block().canonical_root();
                    assert_eq!(
                        availability,
                        Availability::MissingComponents(root),
                        "should be pending block"
                    );
                    let availability = cache
                        .put_pending_executed_block(pending_block)
                        .expect("should put block");
                    assert!(
                        matches!(availability, Availability::MissingComponents(_)),
                        "should have pending blobs"
                    );
                }
            } else {
                let availability = cache
                    .put_pending_executed_block(pending_block)
                    .expect("should put block");
                assert!(
                    matches!(availability, Availability::MissingComponents(_)),
                    "should be pending blobs"
                );
            }
            remaining_blobs.insert(block_root, pending_block_blobs);
        }

        // now we should have a full cache spanning multiple epochs
        // cache should be at capacity
        assert_eq!(
            cache.critical.read().in_memory.len(),
            capacity,
            "cache memory should be full"
        );
        // write all components to disk
        cache.write_all_to_disk().expect("should write all to disk");
        // everything should be on disk now
        assert_eq!(
            cache
                .overflow_store
                .read_keys_on_disk()
                .expect("should read keys")
                .len(),
            capacity * n_epochs,
            "cache disk should have the rest"
        );
        assert_eq!(
            cache.critical.read().in_memory.len(),
            0,
            "cache memory should be empty"
        );
        assert_eq!(
            cache.critical.read().store_keys.len(),
            n_epochs * capacity,
            "cache store should have the rest"
        );
        drop(cache);

        // create a new cache with the same store
        let recovered_cache = OverflowLRUCache::<T>::new(
            new_non_zero_usize(capacity),
            harness.chain.store.clone(),
            harness.chain.spec.clone(),
        )
        .expect("should recover cache");
        // again, everything should be on disk
        assert_eq!(
            recovered_cache
                .overflow_store
                .read_keys_on_disk()
                .expect("should read keys")
                .len(),
            capacity * n_epochs,
            "cache disk should have the rest"
        );
        assert_eq!(
            recovered_cache.critical.read().in_memory.len(),
            0,
            "cache memory should be empty"
        );
        assert_eq!(
            recovered_cache.critical.read().store_keys.len(),
            n_epochs * capacity,
            "cache store should have the rest"
        );

        // now lets insert the remaining blobs until the cache is empty
        for (root, blobs) in remaining_blobs {
            let additional_blobs = blobs.len();
            let mut kzg_verified_blobs = vec![];
            for (i, gossip_blob) in blobs.into_iter().enumerate() {
                kzg_verified_blobs.push(gossip_blob.into_inner());
                let availability = recovered_cache
                    .put_kzg_verified_blobs(root, kzg_verified_blobs.clone())
                    .expect("should put blob");
                if i == additional_blobs - 1 {
                    assert!(matches!(availability, Availability::Available(_)))
                } else {
                    assert!(matches!(availability, Availability::MissingComponents(_)));
                }
            }
        }
    }

    #[tokio::test]
    // ensure the state cache keeps memory usage low and that it can properly recover states
    // THIS TEST CAN BE DELETED ONCE TREE STATES IS MERGED AND WE RIP OUT THE STATE CACHE
    async fn overflow_cache_test_state_cache() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = STATE_LRU_CAPACITY * 2;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let mut pending_blocks = VecDeque::new();
        let mut states = Vec::new();
        let mut state_roots = Vec::new();
        // Get enough blocks to fill the cache to capacity, ensuring all blocks have blobs
        while pending_blocks.len() < capacity {
            let (pending_block, _) = availability_pending_block(&harness).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let state_root = pending_block.import_data.state.canonical_root();
            states.push(pending_block.import_data.state.clone());
            pending_blocks.push_back(pending_block);
            state_roots.push(state_root);
        }

        let state_cache = cache.state_lru_cache().lru_cache();
        let mut pushed_diet_blocks = VecDeque::new();

        for i in 0..capacity {
            let pending_block = pending_blocks.pop_front().expect("should have block");
            let block_root = pending_block.as_block().canonical_root();

            assert_eq!(
                state_cache.read().len(),
                std::cmp::min(i, STATE_LRU_CAPACITY),
                "state cache should be empty at start"
            );

            if i >= STATE_LRU_CAPACITY {
                let lru_root = state_roots[i - STATE_LRU_CAPACITY];
                assert_eq!(
                    state_cache.read().peek_lru().map(|(root, _)| root),
                    Some(&lru_root),
                    "lru block should be in cache"
                );
            }

            // put the block in the cache
            let availability = cache
                .put_pending_executed_block(pending_block)
                .expect("should put block");

            // grab the diet block from the cache for later testing
            let diet_block = cache
                .critical
                .read()
                .in_memory
                .peek(&block_root)
                .map(|pending_components| {
                    pending_components
                        .executed_block
                        .clone()
                        .expect("should exist")
                })
                .expect("should exist");
            pushed_diet_blocks.push_back(diet_block);

            // should be unavailable since we made sure all blocks had blobs
            assert!(
                matches!(availability, Availability::MissingComponents(_)),
                "should be pending blobs"
            );

            if i >= STATE_LRU_CAPACITY {
                let evicted_index = i - STATE_LRU_CAPACITY;
                let evicted_root = state_roots[evicted_index];
                assert!(
                    state_cache.read().peek(&evicted_root).is_none(),
                    "lru root should be evicted"
                );
                // get the diet block via direct conversion (testing only)
                let diet_block = pushed_diet_blocks.pop_front().expect("should have block");
                // reconstruct the pending block by replaying the block on the parent state
                let recovered_pending_block = cache
                    .state_lru_cache()
                    .reconstruct_pending_executed_block(diet_block)
                    .expect("should reconstruct pending block");

                // assert the recovered state is the same as the original
                assert_eq!(
                    recovered_pending_block.import_data.state, states[evicted_index],
                    "recovered state should be the same as the original"
                );
            }
        }

        // now check the last block
        let last_block = pushed_diet_blocks.pop_back().expect("should exist").clone();
        // the state should still be in the cache
        assert!(
            state_cache
                .read()
                .peek(&last_block.as_block().state_root())
                .is_some(),
            "last block state should still be in cache"
        );
        // get the diet block via direct conversion (testing only)
        let diet_block = last_block.clone();
        // recover the pending block from the cache
        let recovered_pending_block = cache
            .state_lru_cache()
            .recover_pending_executed_block(diet_block)
            .expect("should reconstruct pending block");
        // assert the recovered state is the same as the original
        assert_eq!(
            Some(&recovered_pending_block.import_data.state),
            states.last(),
            "recovered state should be the same as the original"
        );
        // the state should no longer be in the cache
        assert!(
            state_cache
                .read()
                .peek(&last_block.as_block().state_root())
                .is_none(),
            "last block state should no longer be in cache"
        );
    }
}

#[cfg(test)]
mod pending_components_tests {
    use super::*;
    use crate::block_verification_types::BlockImportData;
    use crate::eth1_finalization_cache::Eth1FinalizationData;
    use crate::test_utils::{generate_rand_block_and_blobs, NumBlobs};
    use crate::PayloadVerificationOutcome;
    use fork_choice::PayloadVerificationStatus;
    use kzg::KzgCommitment;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use state_processing::ConsensusContext;
    use types::test_utils::TestRandom;
    use types::{BeaconState, ForkName, MainnetEthSpec, SignedBeaconBlock, Slot};

    type E = MainnetEthSpec;

    type Setup<E> = (
        SignedBeaconBlock<E>,
        FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
        FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
    );

    pub fn pre_setup() -> Setup<E> {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
        let (block, blobs_vec) =
            generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Random, &mut rng);
        let mut blobs: FixedVector<_, <E as EthSpec>::MaxBlobsPerBlock> = FixedVector::default();

        for blob in blobs_vec {
            if let Some(b) = blobs.get_mut(blob.index as usize) {
                *b = Some(Arc::new(blob));
            }
        }

        let mut invalid_blobs: FixedVector<
            Option<Arc<BlobSidecar<E>>>,
            <E as EthSpec>::MaxBlobsPerBlock,
        > = FixedVector::default();
        for (index, blob) in blobs.iter().enumerate() {
            if let Some(invalid_blob) = blob {
                let mut blob_copy = invalid_blob.as_ref().clone();
                blob_copy.kzg_commitment = KzgCommitment::random_for_test(&mut rng);
                *invalid_blobs.get_mut(index).unwrap() = Some(Arc::new(blob_copy));
            }
        }

        (block, blobs, invalid_blobs)
    }

    type PendingComponentsSetup<E> = (
        DietAvailabilityPendingExecutedBlock<E>,
        FixedVector<Option<KzgVerifiedBlob<E>>, <E as EthSpec>::MaxBlobsPerBlock>,
        FixedVector<Option<KzgVerifiedBlob<E>>, <E as EthSpec>::MaxBlobsPerBlock>,
    );

    pub fn setup_pending_components(
        block: SignedBeaconBlock<E>,
        valid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
        invalid_blobs: FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>,
    ) -> PendingComponentsSetup<E> {
        let blobs = FixedVector::from(
            valid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let invalid_blobs = FixedVector::from(
            invalid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let dummy_parent = block.clone_as_blinded();
        let block = AvailabilityPendingExecutedBlock {
            block: Arc::new(block),
            import_data: BlockImportData {
                block_root: Default::default(),
                state: BeaconState::new(0, Default::default(), &ChainSpec::minimal()),
                parent_block: dummy_parent,
                parent_eth1_finalization_data: Eth1FinalizationData {
                    eth1_data: Default::default(),
                    eth1_deposit_index: 0,
                },
                confirmed_state_roots: vec![],
                consensus_context: ConsensusContext::new(Slot::new(0)),
            },
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
                is_valid_merge_transition_block: false,
            },
        };
        (block.into(), blobs, invalid_blobs)
    }

    pub fn assert_cache_consistent(cache: PendingComponents<E>) {
        if let Some(cached_block) = cache.get_cached_block() {
            let cached_block_commitments = cached_block.get_commitments();
            for index in 0..E::max_blobs_per_block() {
                let block_commitment = cached_block_commitments.get(index).copied();
                let blob_commitment_opt = cache.get_cached_blobs().get(index).unwrap();
                let blob_commitment = blob_commitment_opt.as_ref().map(|b| *b.get_commitment());
                assert_eq!(block_commitment, blob_commitment);
            }
        } else {
            panic!("No cached block")
        }
    }

    pub fn assert_empty_blob_cache(cache: PendingComponents<E>) {
        for blob in cache.get_cached_blobs().iter() {
            assert!(blob.is_none());
        }
    }

    #[test]
    fn valid_block_invalid_blobs_valid_blobs() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache);
    }

    #[test]
    fn invalid_blobs_block_valid_blobs() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache);
    }

    #[test]
    fn invalid_blobs_valid_blobs_block() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);

        assert_empty_blob_cache(cache);
    }

    #[test]
    fn block_valid_blobs_invalid_blobs() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache);
    }

    #[test]
    fn valid_blobs_block_invalid_blobs() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache);
    }

    #[test]
    fn valid_blobs_invalid_blobs_block() {
        let (block_commitments, blobs, random_blobs) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);

        assert_cache_consistent(cache);
    }
}
