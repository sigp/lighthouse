use crate::beacon_chain::BeaconStore;
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification::{AvailabilityPendingExecutedBlock, AvailableExecutedBlock};
use crate::data_availability_checker::{Availability, AvailabilityCheckError};
use crate::store::{DBColumn, KeyValueStore};
use crate::BeaconChainTypes;
use lru::LruCache;
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard, RwLockWriteGuard};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use std::{collections::HashSet, sync::Arc};
use types::blob_sidecar::BlobIdentifier;
use types::{BlobSidecar, Epoch, EthSpec, Hash256, SignedBeaconBlock};

type MissingBlobInfo<T> = (Option<Arc<SignedBeaconBlock<T>>>, HashSet<usize>);

/// Caches partially available blobs and execution verified blocks corresponding
/// to a given `block_hash` that are received over gossip.
///
/// The blobs are all gossip and kzg verified.
/// The block has completed all verifications except the availability check.
#[derive(Encode, Decode, Clone)]
pub struct PendingComponents<T: EthSpec> {
    verified_blobs: FixedVector<Option<KzgVerifiedBlob<T>>, T::MaxBlobsPerBlock>,
    executed_block: Option<AvailabilityPendingExecutedBlock<T>>,
}

impl<T: EthSpec> PendingComponents<T> {
    pub fn new_from_blobs(blobs: &[KzgVerifiedBlob<T>]) -> Self {
        let mut verified_blobs = FixedVector::<_, _>::default();
        for blob in blobs {
            if let Some(mut_maybe_blob) = verified_blobs.get_mut(blob.blob_index() as usize) {
                *mut_maybe_blob = Some(blob.clone());
            }
        }

        Self {
            verified_blobs,
            executed_block: None,
        }
    }

    pub fn new_from_block(block: AvailabilityPendingExecutedBlock<T>) -> Self {
        Self {
            verified_blobs: <_>::default(),
            executed_block: Some(block),
        }
    }

    /// Returns `true` if the cache has all blobs corresponding to the
    /// kzg commitments in the block.
    pub fn has_all_blobs(&self, block: &AvailabilityPendingExecutedBlock<T>) -> bool {
        for i in 0..block.num_blobs_expected() {
            if self
                .verified_blobs
                .get(i)
                .map(|maybe_blob| maybe_blob.is_none())
                .unwrap_or(true)
            {
                return false;
            }
        }
        true
    }

    pub fn empty() -> Self {
        Self {
            verified_blobs: <_>::default(),
            executed_block: None,
        }
    }

    pub fn epoch(&self) -> Option<Epoch> {
        self.executed_block
            .as_ref()
            .map(|pending_block| pending_block.block.as_block().epoch())
            .or_else(|| {
                for maybe_blob in self.verified_blobs.iter() {
                    if maybe_blob.is_some() {
                        return maybe_blob.as_ref().map(|kzg_verified_blob| {
                            kzg_verified_blob.as_blob().slot.epoch(T::slots_per_epoch())
                        });
                    }
                }
                None
            })
    }

    pub fn get_missing_blob_info(&self) -> MissingBlobInfo<T> {
        let block_opt = self
            .executed_block
            .as_ref()
            .map(|block| block.block.block.clone());
        let blobs = self
            .verified_blobs
            .iter()
            .enumerate()
            .filter_map(|(i, maybe_blob)| maybe_blob.as_ref().map(|_| i))
            .collect::<HashSet<_>>();
        (block_opt, blobs)
    }
}

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

    pub fn get_pending_components(
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
                        .get_or_insert_with(PendingComponents::empty)
                        .executed_block = Some(AvailabilityPendingExecutedBlock::from_ssz_bytes(
                        value_bytes.as_slice(),
                    )?);
                }
                OverflowKey::Blob(_, index) => {
                    *maybe_pending_components
                        .get_or_insert_with(PendingComponents::empty)
                        .verified_blobs
                        .get_mut(index as usize)
                        .ok_or(AvailabilityCheckError::BlobIndexInvalid(index as u64))? =
                        Some(KzgVerifiedBlob::from_ssz_bytes(value_bytes.as_slice())?);
                }
            }
        }

        Ok(maybe_pending_components)
    }

    // returns the hashes of all the blocks we have data for on disk
    pub fn read_keys_on_disk(&self) -> Result<HashSet<Hash256>, AvailabilityCheckError> {
        let mut disk_keys = HashSet::new();
        for res in self.0.hot_db.iter_raw_keys(DBColumn::OverflowLRUCache, &[]) {
            let key_bytes = res?;
            disk_keys.insert(*OverflowKey::from_ssz_bytes(&key_bytes)?.root());
        }
        Ok(disk_keys)
    }

    pub fn load_block(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<AvailabilityPendingExecutedBlock<T::EthSpec>>, AvailabilityCheckError> {
        let key = OverflowKey::from_block_root(*block_root);

        self.0
            .hot_db
            .get_bytes(DBColumn::OverflowLRUCache.as_str(), &key.as_ssz_bytes())?
            .map(|block_bytes| {
                AvailabilityPendingExecutedBlock::from_ssz_bytes(block_bytes.as_slice())
            })
            .transpose()
            .map_err(|e| e.into())
    }

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

    pub fn delete_keys(&self, keys: &Vec<OverflowKey>) -> Result<(), AvailabilityCheckError> {
        for key in keys {
            self.0
                .hot_db
                .key_delete(DBColumn::OverflowLRUCache.as_str(), &key.as_ssz_bytes())?;
        }
        Ok(())
    }
}

// This data is protected by an RwLock
struct Critical<T: BeaconChainTypes> {
    pub in_memory: LruCache<Hash256, PendingComponents<T::EthSpec>>,
    pub store_keys: HashSet<Hash256>,
}

impl<T: BeaconChainTypes> Critical<T> {
    pub fn new(capacity: usize) -> Self {
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

    /// Puts the pending components in the LRU cache. If the cache
    /// is at capacity, the LRU entry is written to the store first
    pub fn put_pending_components(
        &mut self,
        block_root: Hash256,
        pending_components: PendingComponents<T::EthSpec>,
        overflow_store: &OverflowStore<T>,
    ) -> Result<(), AvailabilityCheckError> {
        if self.in_memory.len() == self.in_memory.cap() {
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
                    store.get_pending_components(block_root)
                } else {
                    Ok(None)
                }
            }
        }
    }
}

pub struct OverflowLRUCache<T: BeaconChainTypes> {
    critical: RwLock<Critical<T>>,
    overflow_store: OverflowStore<T>,
    maintenance_lock: Mutex<()>,
    capacity: usize,
}

impl<T: BeaconChainTypes> OverflowLRUCache<T> {
    pub fn new(
        capacity: usize,
        beacon_store: BeaconStore<T>,
    ) -> Result<Self, AvailabilityCheckError> {
        let overflow_store = OverflowStore(beacon_store);
        let mut critical = Critical::new(capacity);
        critical.reload_store_keys(&overflow_store)?;
        Ok(Self {
            critical: RwLock::new(critical),
            overflow_store,
            maintenance_lock: Mutex::new(()),
            capacity,
        })
    }

    pub fn has_block(&self, block_root: &Hash256) -> bool {
        let read_lock = self.critical.read();
        if read_lock
            .in_memory
            .peek(block_root)
            .map_or(false, |cache| cache.executed_block.is_some())
        {
            true
        } else if read_lock.store_keys.contains(block_root) {
            drop(read_lock);
            // I assume if there's some kind of error reading from the store, we should just return false
            self.overflow_store
                .load_block(block_root)
                .map_or(false, |maybe_block| maybe_block.is_some())
        } else {
            false
        }
    }

    pub fn get_missing_blob_info(&self, block_root: Hash256) -> MissingBlobInfo<T::EthSpec> {
        let read_lock = self.critical.read();
        if let Some(cache) = read_lock.in_memory.peek(&block_root) {
            cache.get_missing_blob_info()
        } else if read_lock.store_keys.contains(&block_root) {
            drop(read_lock);
            // return default if there's an error reading from the store
            match self.overflow_store.get_pending_components(block_root) {
                Ok(Some(pending_components)) => pending_components.get_missing_blob_info(),
                _ => Default::default(),
            }
        } else {
            Default::default()
        }
    }

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

    pub fn put_kzg_verified_blobs(
        &self,
        block_root: Hash256,
        kzg_verified_blobs: &[KzgVerifiedBlob<T::EthSpec>],
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        for blob in kzg_verified_blobs {
            let blob_block_root = blob.block_root();
            if blob_block_root != block_root {
                return Err(AvailabilityCheckError::BlockBlobRootMismatch {
                    block_root,
                    blob_block_root,
                });
            }
        }
        let mut write_lock = self.critical.write();

        let availability = if let Some(mut pending_components) =
            write_lock.pop_pending_components(block_root, &self.overflow_store)?
        {
            for kzg_verified_blob in kzg_verified_blobs {
                let blob_index = kzg_verified_blob.blob_index() as usize;
                if let Some(maybe_verified_blob) =
                    pending_components.verified_blobs.get_mut(blob_index)
                {
                    *maybe_verified_blob = Some(kzg_verified_blob.clone())
                } else {
                    return Err(AvailabilityCheckError::BlobIndexInvalid(blob_index as u64));
                }
            }

            if let Some(executed_block) = pending_components.executed_block.take() {
                self.check_block_availability_maybe_cache(
                    write_lock,
                    pending_components,
                    executed_block,
                )?
            } else {
                write_lock.put_pending_components(
                    block_root,
                    pending_components,
                    &self.overflow_store,
                )?;
                Availability::MissingComponents(block_root)
            }
        } else {
            // not in memory or store -> put new in memory
            let new_pending_components = PendingComponents::new_from_blobs(kzg_verified_blobs);
            write_lock.put_pending_components(
                block_root,
                new_pending_components,
                &self.overflow_store,
            )?;
            Availability::MissingComponents(block_root)
        };

        Ok(availability)
    }

    /// Check if we have all the blobs for a block. If we do, return the Availability variant that
    /// triggers import of the block.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut write_lock = self.critical.write();
        let block_root = executed_block.import_data.block_root;

        let availability =
            match write_lock.pop_pending_components(block_root, &self.overflow_store)? {
                Some(pending_components) => self.check_block_availability_maybe_cache(
                    write_lock,
                    pending_components,
                    executed_block,
                )?,
                None => {
                    let all_blob_ids = executed_block.get_all_blob_ids();
                    if all_blob_ids.is_empty() {
                        // no blobs for this block, we can import it
                        let AvailabilityPendingExecutedBlock {
                            block,
                            import_data,
                            payload_verification_outcome,
                        } = executed_block;
                        let available_block = block.make_available(vec![])?;
                        return Ok(Availability::Available(Box::new(
                            AvailableExecutedBlock::new(
                                available_block,
                                import_data,
                                payload_verification_outcome,
                            ),
                        )));
                    }
                    let new_pending_components = PendingComponents::new_from_block(executed_block);
                    write_lock.put_pending_components(
                        block_root,
                        new_pending_components,
                        &self.overflow_store,
                    )?;
                    Availability::MissingComponents(block_root)
                }
            };

        Ok(availability)
    }

    /// Checks if the provided `executed_block` contains all required blobs to be considered an
    /// `AvailableBlock` based on blobs that are cached.
    ///
    /// Returns an error if there was an error when matching the block commitments against blob commitments.
    ///
    /// Returns `Ok(Availability::Available(_))` if all blobs for the block are present in cache.
    /// Returns `Ok(Availability::MissingComponents(_))` if all corresponding blobs have not been received in the cache.
    fn check_block_availability_maybe_cache(
        &self,
        mut write_lock: RwLockWriteGuard<Critical<T>>,
        mut pending_components: PendingComponents<T::EthSpec>,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        if pending_components.has_all_blobs(&executed_block) {
            let num_blobs_expected = executed_block.num_blobs_expected();
            let AvailabilityPendingExecutedBlock {
                block,
                import_data,
                payload_verification_outcome,
            } = executed_block;

            let Some(verified_blobs) = Vec::from(pending_components.verified_blobs)
                .into_iter()
                .take(num_blobs_expected)
                .collect::<Option<Vec<_>>>() else {
                 return Ok(Availability::MissingComponents(import_data.block_root))
            };

            let available_block = block.make_available(verified_blobs)?;
            Ok(Availability::Available(Box::new(
                AvailableExecutedBlock::new(
                    available_block,
                    import_data,
                    payload_verification_outcome,
                ),
            )))
        } else {
            let block_root = executed_block.import_data.block_root;
            let _ = pending_components.executed_block.insert(executed_block);
            write_lock.put_pending_components(
                block_root,
                pending_components,
                &self.overflow_store,
            )?;

            Ok(Availability::MissingComponents(block_root))
        }
    }

    // writes all in_memory objects to disk
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

    // maintain the cache
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        // ensure memory usage is below threshold
        let threshold = self.capacity * 3 / 4;
        self.maintain_threshold(threshold, cutoff_epoch)?;
        // clean up any keys on the disk that shouldn't be there
        self.prune_disk(cutoff_epoch)?;
        Ok(())
    }

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

            let (lru_root, lru_pending_components) = match lru_entry {
                Some((r, p)) => (r, p),
                None => break,
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
                    stored = write_lock.in_memory.len();
                }
            }
            drop(write_lock);
        }

        drop(maintenance_lock);
        Ok(())
    }

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
            let block_data = match block_data {
                Some(block_data) => block_data,
                None => return Ok(()),
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
                            AvailabilityPendingExecutedBlock::<T::EthSpec>::from_ssz_bytes(
                                value_bytes.as_slice(),
                            )?
                            .block
                            .as_block()
                            .epoch()
                        }
                        OverflowKey::Blob(_, _) => {
                            KzgVerifiedBlob::<T::EthSpec>::from_ssz_bytes(value_bytes.as_slice())?
                                .as_blob()
                                .slot
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
    #[cfg(feature = "spec-minimal")]
    use crate::{
        blob_verification::{
            validate_blob_sidecar_for_gossip, verify_kzg_for_blob, GossipVerifiedBlob,
        },
        block_verification::{BlockImportData, PayloadVerificationOutcome},
        data_availability_checker::AvailabilityPendingBlock,
        eth1_finalization_cache::Eth1FinalizationData,
        test_utils::{BaseHarnessType, BeaconChainHarness, DiskHarnessType},
    };
    #[cfg(feature = "spec-minimal")]
    use fork_choice::PayloadVerificationStatus;
    #[cfg(feature = "spec-minimal")]
    use logging::test_logger;
    #[cfg(feature = "spec-minimal")]
    use slog::{info, Logger};
    #[cfg(feature = "spec-minimal")]
    use state_processing::ConsensusContext;
    #[cfg(feature = "spec-minimal")]
    use std::collections::{BTreeMap, HashMap, VecDeque};
    #[cfg(feature = "spec-minimal")]
    use std::ops::AddAssign;
    #[cfg(feature = "spec-minimal")]
    use store::{HotColdDB, ItemStore, LevelDB, StoreConfig};
    #[cfg(feature = "spec-minimal")]
    use tempfile::{tempdir, TempDir};
    #[cfg(feature = "spec-minimal")]
    use types::beacon_state::ssz_tagged_beacon_state;
    #[cfg(feature = "spec-minimal")]
    use types::{ChainSpec, ExecPayload, MinimalEthSpec};

    #[cfg(feature = "spec-minimal")]
    const LOW_VALIDATOR_COUNT: usize = 32;

    #[cfg(feature = "spec-minimal")]
    fn get_store_with_spec<E: EthSpec>(
        db_path: &TempDir,
        spec: ChainSpec,
        log: Logger,
    ) -> Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>> {
        let hot_path = db_path.path().join("hot_db");
        let cold_path = db_path.path().join("cold_db");
        let config = StoreConfig::default();

        HotColdDB::open(
            &hot_path,
            &cold_path,
            None,
            |_, _, _| Ok(()),
            config,
            spec,
            log,
        )
        .expect("disk store should initialize")
    }

    // get a beacon chain harness advanced to just before deneb fork
    #[cfg(feature = "spec-minimal")]
    async fn get_deneb_chain<E: EthSpec>(
        log: Logger,
        db_path: &TempDir,
    ) -> BeaconChainHarness<BaseHarnessType<E, LevelDB<E>, LevelDB<E>>> {
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
        let merge_head = &harness.chain.head_snapshot().beacon_block;
        assert!(merge_head.as_merge().is_ok());
        assert_eq!(merge_head.slot(), bellatrix_fork_slot);
        assert!(
            merge_head
                .message()
                .body()
                .execution_payload()
                .unwrap()
                .is_default_with_empty_roots(),
            "Merge head is default payload"
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

    #[tokio::test]
    #[cfg(feature = "spec-minimal")]
    async fn ssz_tagged_beacon_state_encode_decode_equality() {
        type E = MinimalEthSpec;
        let altair_fork_epoch = Epoch::new(1);
        let altair_fork_slot = altair_fork_epoch.start_slot(E::slots_per_epoch());
        let bellatrix_fork_epoch = Epoch::new(2);
        let merge_fork_slot = bellatrix_fork_epoch.start_slot(E::slots_per_epoch());
        let capella_fork_epoch = Epoch::new(3);
        let capella_fork_slot = capella_fork_epoch.start_slot(E::slots_per_epoch());
        let deneb_fork_epoch = Epoch::new(4);
        let deneb_fork_slot = deneb_fork_epoch.start_slot(E::slots_per_epoch());

        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(altair_fork_epoch);
        spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
        spec.capella_fork_epoch = Some(capella_fork_epoch);
        spec.deneb_fork_epoch = Some(deneb_fork_epoch);

        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec)
            .logger(logging::test_logger())
            .deterministic_keypairs(LOW_VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        let mut state = harness.get_current_state();
        assert!(state.as_base().is_ok());
        let encoded = ssz_tagged_beacon_state::encode::as_ssz_bytes(&state);
        let decoded =
            ssz_tagged_beacon_state::decode::from_ssz_bytes(&encoded).expect("should decode");
        state.drop_all_caches().expect("should drop caches");
        assert_eq!(state, decoded, "Encoded and decoded states should be equal");

        harness.extend_to_slot(altair_fork_slot).await;

        let mut state = harness.get_current_state();
        assert!(state.as_altair().is_ok());
        let encoded = ssz_tagged_beacon_state::encode::as_ssz_bytes(&state);
        let decoded =
            ssz_tagged_beacon_state::decode::from_ssz_bytes(&encoded).expect("should decode");
        state.drop_all_caches().expect("should drop caches");
        assert_eq!(state, decoded, "Encoded and decoded states should be equal");

        harness.extend_to_slot(merge_fork_slot).await;

        let mut state = harness.get_current_state();
        assert!(state.as_merge().is_ok());
        let encoded = ssz_tagged_beacon_state::encode::as_ssz_bytes(&state);
        let decoded =
            ssz_tagged_beacon_state::decode::from_ssz_bytes(&encoded).expect("should decode");
        state.drop_all_caches().expect("should drop caches");
        assert_eq!(state, decoded, "Encoded and decoded states should be equal");

        harness.extend_to_slot(capella_fork_slot).await;

        let mut state = harness.get_current_state();
        assert!(state.as_capella().is_ok());
        let encoded = ssz_tagged_beacon_state::encode::as_ssz_bytes(&state);
        let decoded =
            ssz_tagged_beacon_state::decode::from_ssz_bytes(&encoded).expect("should decode");
        state.drop_all_caches().expect("should drop caches");
        assert_eq!(state, decoded, "Encoded and decoded states should be equal");

        harness.extend_to_slot(deneb_fork_slot).await;

        let mut state = harness.get_current_state();
        assert!(state.as_deneb().is_ok());
        let encoded = ssz_tagged_beacon_state::encode::as_ssz_bytes(&state);
        let decoded =
            ssz_tagged_beacon_state::decode::from_ssz_bytes(&encoded).expect("should decode");
        state.drop_all_caches().expect("should drop caches");
        assert_eq!(state, decoded, "Encoded and decoded states should be equal");
    }

    #[cfg(feature = "spec-minimal")]
    async fn availability_pending_block<E, Hot, Cold>(
        harness: &BeaconChainHarness<BaseHarnessType<E, Hot, Cold>>,
        log: Logger,
    ) -> (
        AvailabilityPendingExecutedBlock<E>,
        Vec<GossipVerifiedBlob<E>>,
    )
    where
        E: EthSpec,
        Hot: ItemStore<E>,
        Cold: ItemStore<E>,
    {
        let chain = &harness.chain;
        let head = chain.head_snapshot();
        let parent_state = head.beacon_state.clone_with_only_committee_caches();

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

        let gossip_verified_blobs = if let Some(blobs) = maybe_blobs {
            Vec::from(blobs)
                .into_iter()
                .map(|signed_blob| {
                    let subnet = signed_blob.message.index;
                    validate_blob_sidecar_for_gossip(signed_blob, subnet, &harness.chain)
                        .expect("should validate blob")
                })
                .collect()
        } else {
            vec![]
        };

        let slot = block.slot();
        let apb: AvailabilityPendingBlock<E> = AvailabilityPendingBlock {
            block: Arc::new(block),
        };

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
            block: apb,
            import_data,
            payload_verification_outcome,
        };

        (availability_pending_block, gossip_verified_blobs)
    }

    #[tokio::test]
    #[cfg(feature = "spec-minimal")]
    async fn overflow_cache_test_insert_components() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let log = test_logger();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness: BeaconChainHarness<T> = get_deneb_chain(log.clone(), &chain_db_path).await;
        let spec = harness.spec.clone();
        let capacity = 4;
        let db_path = tempdir().expect("should get temp dir");
        let test_store = get_store_with_spec::<E>(&db_path, spec.clone(), log.clone());
        let cache = Arc::new(
            OverflowLRUCache::<T>::new(capacity, test_store).expect("should create cache"),
        );

        let (pending_block, blobs) = availability_pending_block(&harness, log.clone()).await;
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

        let kzg = harness
            .chain
            .kzg
            .as_ref()
            .cloned()
            .expect("kzg should exist");
        let mut kzg_verified_blobs = Vec::new();
        for (blob_index, gossip_blob) in blobs.into_iter().enumerate() {
            let kzg_verified_blob = verify_kzg_for_blob(gossip_blob.to_blob(), kzg.as_ref())
                .expect("kzg should verify");
            kzg_verified_blobs.push(kzg_verified_blob);
            let availability = cache
                .put_kzg_verified_blobs(root, kzg_verified_blobs.as_slice())
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

        let (pending_block, blobs) = availability_pending_block(&harness, log.clone()).await;
        let blobs_expected = pending_block.num_blobs_expected();
        assert_eq!(
            blobs.len(),
            blobs_expected,
            "should have expected number of blobs"
        );
        let root = pending_block.import_data.block_root;
        let mut kzg_verified_blobs = vec![];
        for gossip_blob in blobs {
            let kzg_verified_blob = verify_kzg_for_blob(gossip_blob.to_blob(), kzg.as_ref())
                .expect("kzg should verify");
            kzg_verified_blobs.push(kzg_verified_blob);
            let availability = cache
                .put_kzg_verified_blobs(root, kzg_verified_blobs.as_slice())
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
    #[cfg(feature = "spec-minimal")]
    async fn overflow_cache_test_overflow() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let log = test_logger();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness: BeaconChainHarness<T> = get_deneb_chain(log.clone(), &chain_db_path).await;
        let spec = harness.spec.clone();
        let capacity = 4;
        let db_path = tempdir().expect("should get temp dir");
        let test_store = get_store_with_spec::<E>(&db_path, spec.clone(), log.clone());
        let cache = Arc::new(
            OverflowLRUCache::<T>::new(capacity, test_store).expect("should create cache"),
        );

        let mut pending_blocks = VecDeque::new();
        let mut pending_blobs = VecDeque::new();
        let mut roots = VecDeque::new();
        while pending_blobs.len() < capacity + 1 {
            let (pending_block, blobs) = availability_pending_block(&harness, log.clone()).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let root = pending_block.block.block.canonical_root();
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
            .get_pending_components(roots[0])
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

        let kzg = harness
            .chain
            .kzg
            .as_ref()
            .cloned()
            .expect("kzg should exist");

        let blobs_0 = pending_blobs.pop_front().expect("should have blobs");
        let expected_blobs = blobs_0.len();
        let mut kzg_verified_blobs = vec![];
        for (blob_index, gossip_blob) in blobs_0.into_iter().enumerate() {
            let kzg_verified_blob = verify_kzg_for_blob(gossip_blob.to_blob(), kzg.as_ref())
                .expect("kzg should verify");
            kzg_verified_blobs.push(kzg_verified_blob);
            let availability = cache
                .put_kzg_verified_blobs(roots[0], kzg_verified_blobs.as_slice())
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
                .get_pending_components(roots[1])
                .expect("no error")
                .is_some(),
            "second block should still be on disk"
        );
        assert!(
            cache
                .overflow_store
                .get_pending_components(roots[0])
                .expect("no error")
                .is_none(),
            "first block should not be on disk"
        );
    }

    #[tokio::test]
    #[cfg(feature = "spec-minimal")]
    async fn overflow_cache_test_maintenance() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let log = test_logger();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness: BeaconChainHarness<T> = get_deneb_chain(log.clone(), &chain_db_path).await;
        let spec = harness.spec.clone();
        let n_epochs = 4;
        let capacity = E::slots_per_epoch() as usize;
        let db_path = tempdir().expect("should get temp dir");
        let test_store = get_store_with_spec::<E>(&db_path, spec.clone(), log.clone());
        let cache = Arc::new(
            OverflowLRUCache::<T>::new(capacity, test_store).expect("should create cache"),
        );

        let mut pending_blocks = VecDeque::new();
        let mut pending_blobs = VecDeque::new();
        let mut roots = VecDeque::new();
        let mut epoch_count = BTreeMap::new();
        while pending_blobs.len() < n_epochs * capacity {
            let (pending_block, blobs) = availability_pending_block(&harness, log.clone()).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let root = pending_block.block.as_block().canonical_root();
            let epoch = pending_block
                .block
                .as_block()
                .slot()
                .epoch(E::slots_per_epoch());
            epoch_count.entry(epoch).or_insert_with(|| 0).add_assign(1);

            pending_blocks.push_back(pending_block);
            pending_blobs.push_back(blobs);
            roots.push_back(root);
        }

        let kzg = harness
            .chain
            .kzg
            .as_ref()
            .cloned()
            .expect("kzg should exist");

        let mut kzg_verified_blobs = vec![];
        for _ in 0..(n_epochs * capacity) {
            let pending_block = pending_blocks.pop_front().expect("should have block");
            let block_root = pending_block.block.as_block().canonical_root();
            let expected_blobs = pending_block.num_blobs_expected();
            if expected_blobs > 1 {
                // might as well add a blob too
                let mut pending_blobs = pending_blobs.pop_front().expect("should have blobs");
                let one_blob = pending_blobs.pop().expect("should have at least one blob");
                let kzg_verified_blob = verify_kzg_for_blob(one_blob.to_blob(), kzg.as_ref())
                    .expect("kzg should verify");
                kzg_verified_blobs.push(kzg_verified_blob);
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
                        .put_kzg_verified_blobs(block_root, kzg_verified_blobs.as_slice())
                        .expect("should put blob");
                    assert!(
                        matches!(availability, Availability::MissingComponents(_)),
                        "availabilty should be pending blobs: {:?}",
                        availability
                    );
                } else {
                    let availability = cache
                        .put_kzg_verified_blobs(block_root, kzg_verified_blobs.as_slice())
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
                // still need to pop front so the blob count is correct
                pending_blobs.pop_front().expect("should have blobs");
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
                log,
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
    #[cfg(feature = "spec-minimal")]
    async fn overflow_cache_test_persist_recover() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let log = test_logger();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness: BeaconChainHarness<T> = get_deneb_chain(log.clone(), &chain_db_path).await;
        let spec = harness.spec.clone();
        let n_epochs = 4;
        let capacity = E::slots_per_epoch() as usize;
        let db_path = tempdir().expect("should get temp dir");
        let test_store = get_store_with_spec::<E>(&db_path, spec.clone(), log.clone());
        let cache = Arc::new(
            OverflowLRUCache::<T>::new(capacity, test_store.clone()).expect("should create cache"),
        );

        let mut pending_blocks = VecDeque::new();
        let mut pending_blobs = VecDeque::new();
        let mut roots = VecDeque::new();
        let mut epoch_count = BTreeMap::new();
        while pending_blobs.len() < n_epochs * capacity {
            let (pending_block, blobs) = availability_pending_block(&harness, log.clone()).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let root = pending_block.block.as_block().canonical_root();
            let epoch = pending_block
                .block
                .as_block()
                .slot()
                .epoch(E::slots_per_epoch());
            epoch_count.entry(epoch).or_insert_with(|| 0).add_assign(1);

            pending_blocks.push_back(pending_block);
            pending_blobs.push_back(blobs);
            roots.push_back(root);
        }

        let kzg = harness
            .chain
            .kzg
            .as_ref()
            .cloned()
            .expect("kzg should exist");

        let mut remaining_blobs = HashMap::new();
        let mut kzg_verified_blobs = vec![];
        for _ in 0..(n_epochs * capacity) {
            let pending_block = pending_blocks.pop_front().expect("should have block");
            let block_root = pending_block.block.as_block().canonical_root();
            let expected_blobs = pending_block.num_blobs_expected();
            if expected_blobs > 1 {
                // might as well add a blob too
                let mut pending_blobs = pending_blobs.pop_front().expect("should have blobs");
                let one_blob = pending_blobs.pop().expect("should have at least one blob");
                let kzg_verified_blob = verify_kzg_for_blob(one_blob.to_blob(), kzg.as_ref())
                    .expect("kzg should verify");
                kzg_verified_blobs.push(kzg_verified_blob);
                // generate random boolean
                let block_first = (rand::random::<usize>() % 2) == 0;
                remaining_blobs.insert(block_root, pending_blobs);
                if block_first {
                    let availability = cache
                        .put_pending_executed_block(pending_block)
                        .expect("should put block");
                    assert!(
                        matches!(availability, Availability::MissingComponents(_)),
                        "should have pending blobs"
                    );
                    let availability = cache
                        .put_kzg_verified_blobs(block_root, kzg_verified_blobs.as_slice())
                        .expect("should put blob");
                    assert!(
                        matches!(availability, Availability::MissingComponents(_)),
                        "availabilty should be pending blobs: {:?}",
                        availability
                    );
                } else {
                    let availability = cache
                        .put_kzg_verified_blobs(block_root, kzg_verified_blobs.as_slice())
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
                // still need to pop front so the blob count is correct
                let pending_blobs = pending_blobs.pop_front().expect("should have blobs");
                remaining_blobs.insert(block_root, pending_blobs);
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
        let recovered_cache =
            OverflowLRUCache::<T>::new(capacity, test_store).expect("should recover cache");
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
                let kzg_verified_blob = verify_kzg_for_blob(gossip_blob.to_blob(), kzg.as_ref())
                    .expect("kzg should verify");
                kzg_verified_blobs.push(kzg_verified_blob);
                let availability = recovered_cache
                    .put_kzg_verified_blobs(root, kzg_verified_blobs.as_slice())
                    .expect("should put blob");
                if i == additional_blobs - 1 {
                    assert!(matches!(availability, Availability::Available(_)))
                } else {
                    assert!(matches!(availability, Availability::MissingComponents(_)));
                }
            }
        }
    }
}
