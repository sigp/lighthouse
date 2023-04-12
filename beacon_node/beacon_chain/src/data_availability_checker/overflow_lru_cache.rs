use crate::beacon_chain::BeaconStore;
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification::{AvailabilityPendingExecutedBlock, AvailableExecutedBlock};
use crate::data_availability_checker::{Availability, AvailabilityCheckError};
use crate::store::{DBColumn, KeyValueStore};
use crate::BeaconChainTypes;
use lru::LruCache;
use parking_lot::{Mutex, RwLock, RwLockWriteGuard};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use std::{collections::HashSet, sync::Arc};
use types::blob_sidecar::BlobIdentifier;
use types::{BlobSidecar, EthSpec, Hash256};

/// Caches partially available blobs and execution verified blocks corresponding
/// to a given `block_hash` that are received over gossip.
///
/// The blobs are all gossip and kzg verified.
/// The block has completed all verifications except the availability check.
#[derive(Encode, Decode, Clone)]
pub struct PendingComponents<T: EthSpec> {
    /// We use a `BTreeMap` here to maintain the order of `BlobSidecar`s based on index.
    verified_blobs: FixedVector<Option<KzgVerifiedBlob<T>>, T::MaxBlobsPerBlock>,
    executed_block: Option<AvailabilityPendingExecutedBlock<T>>,
}

impl<T: EthSpec> PendingComponents<T> {
    fn new_from_blob(blob: KzgVerifiedBlob<T>) -> Self {
        let mut verified_blobs = FixedVector::<_, _>::default();
        // TODO: verify that we've already ensured the blob index < T::MaxBlobsPerBlock
        if let Some(mut_maybe_blob) = verified_blobs.get_mut(blob.blob_index() as usize) {
            *mut_maybe_blob = Some(blob);
        }

        Self {
            verified_blobs,
            executed_block: None,
        }
    }

    fn new_from_block(block: AvailabilityPendingExecutedBlock<T>) -> Self {
        Self {
            verified_blobs: <_>::default(),
            executed_block: Some(block),
        }
    }

    /// Returns `true` if the cache has all blobs corresponding to the
    /// kzg commitments in the block.
    fn has_all_blobs(&self, block: &AvailabilityPendingExecutedBlock<T>) -> bool {
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

    fn empty() -> Self {
        Self {
            verified_blobs: <_>::default(),
            executed_block: None,
        }
    }
}

#[derive(PartialEq)]
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

        for maybe_blob in Vec::from(pending_components.verified_blobs) {
            if let Some(blob) = maybe_blob {
                let key = OverflowKey::from_blob_id::<T::EthSpec>(BlobIdentifier {
                    block_root,
                    index: blob.blob_index(),
                })?;

                self.0
                    .hot_db
                    .put_bytes(col.as_str(), &key.as_ssz_bytes(), &blob.as_ssz_bytes())?
            }
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
                        .get_or_insert_with(|| PendingComponents::empty())
                        .executed_block = Some(AvailabilityPendingExecutedBlock::from_ssz_bytes(
                        value_bytes.as_slice(),
                    )?);
                }
                OverflowKey::Blob(_, index) => {
                    *maybe_pending_components
                        .get_or_insert_with(|| PendingComponents::empty())
                        .verified_blobs
                        .get_mut(index as usize)
                        .ok_or(AvailabilityCheckError::BlobIndexInvalid(index as u64))? =
                        Some(KzgVerifiedBlob::from_ssz_bytes(value_bytes.as_slice())?);
                }
            }
        }

        Ok(maybe_pending_components)
    }

    pub fn load_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        let key = OverflowKey::from_blob_id::<T::EthSpec>(blob_id.clone())?;

        self.0
            .hot_db
            .get_bytes(DBColumn::OverflowLRUCache.as_str(), &key.as_ssz_bytes())?
            .and_then(|blob_bytes| {
                Some(Arc::<BlobSidecar<T::EthSpec>>::from_ssz_bytes(
                    blob_bytes.as_slice(),
                ))
            })
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
    store: OverflowStore<T>,
    maintenance_lock: Mutex<()>,
    capacity: usize,
}

impl<T: BeaconChainTypes> OverflowLRUCache<T> {
    pub fn new(capacity: usize, store: BeaconStore<T>) -> Self {
        Self {
            critical: RwLock::new(Critical::new(capacity)),
            store: OverflowStore(store),
            maintenance_lock: Mutex::new(()),
            capacity,
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
            self.store.load_blob(blob_id)
        } else {
            Ok(None)
        }
    }

    pub fn put_kzg_verified_blob(
        &self,
        kzg_verified_blob: KzgVerifiedBlob<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut write_lock = self.critical.write();
        let block_root = kzg_verified_blob.block_root();

        let availability = if let Some(mut pending_components) =
            write_lock.pop_pending_components(block_root, &self.store)?
        {
            let blob_index = kzg_verified_blob.blob_index();
            *pending_components
                .verified_blobs
                .get_mut(blob_index as usize)
                .ok_or(AvailabilityCheckError::BlobIndexInvalid(blob_index))? =
                Some(kzg_verified_blob);

            if let Some(executed_block) = pending_components.executed_block.take() {
                self.check_block_availability_maybe_cache(
                    write_lock,
                    block_root,
                    pending_components,
                    executed_block,
                )?
            } else {
                write_lock.put_pending_components(block_root, pending_components, &self.store)?;
                Availability::PendingBlock(block_root)
            }
        } else {
            // not in memory or store -> put new in memory
            let new_pending_components = PendingComponents::new_from_blob(kzg_verified_blob);
            write_lock.put_pending_components(block_root, new_pending_components, &self.store)?;
            Availability::PendingBlock(block_root)
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

        let availability = match write_lock.pop_pending_components(block_root, &self.store)? {
            Some(pending_components) => self.check_block_availability_maybe_cache(
                write_lock,
                block_root,
                pending_components,
                executed_block,
            )?,
            None => {
                let all_blob_ids = executed_block.get_all_blob_ids();
                let new_pending_components = PendingComponents::new_from_block(executed_block);
                write_lock.put_pending_components(
                    block_root,
                    new_pending_components,
                    &self.store,
                )?;
                Availability::PendingBlobs(all_blob_ids)
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
    /// Returns `Ok(Availability::PendingBlobs(_))` if all corresponding blobs have not been received in the cache.
    fn check_block_availability_maybe_cache(
        &self,
        mut write_lock: RwLockWriteGuard<Critical<T>>,
        block_root: Hash256,
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

            let verified_blobs = Vec::from(pending_components.verified_blobs)
                .into_iter()
                .take(num_blobs_expected)
                .map(|maybe_blob| maybe_blob.ok_or(AvailabilityCheckError::MissingBlobs))
                .collect::<Result<Vec<_>, _>>()?;

            let available_block = block.make_available(verified_blobs)?;
            Ok(Availability::Available(Box::new(
                AvailableExecutedBlock::new(
                    available_block,
                    import_data,
                    payload_verification_outcome,
                ),
            )))
        } else {
            let missing_blob_ids = executed_block.get_filtered_blob_ids(|index| {
                pending_components
                    .verified_blobs
                    .get(index as usize)
                    .map(|maybe_blob| maybe_blob.is_none())
                    .unwrap_or(true)
            });

            let _ = pending_components.executed_block.insert(executed_block);
            write_lock.put_pending_components(block_root, pending_components, &self.store)?;

            Ok(Availability::PendingBlobs(missing_blob_ids))
        }
    }

    // maintain the cache
    pub fn do_maintenance(&self) -> Result<(), AvailabilityCheckError> {
        // ensure memory usage is below threshold
        let threshold = self.capacity * 3 / 4;
        self.maintain_threshold(threshold)?;
        // clean up any keys on the disk that shouldn't be there
        self.prune_disk()?;
        Ok(())
    }

    fn maintain_threshold(&self, threshold: usize) -> Result<(), AvailabilityCheckError> {
        // ensure only one thread at a time can be deleting things from the disk or
        // moving things between memory and storage
        let maintenance_lock = self.maintenance_lock.lock();

        let mut stored = self.critical.read().in_memory.len();
        while stored > threshold {
            // hold the read lock only as long as it takes to clone the LRU component
            let read_lock = self.critical.read();
            let lru_entry = read_lock
                .in_memory
                .peek_lru()
                .map(|(key, value)| (key.clone(), value.clone()));
            drop(read_lock);

            let (root, pending_components) = match lru_entry {
                Some((r, p)) => (r, p),
                None => break,
            };

            // write the lru entry to disk (we aren't holding any critical locks while we do this)
            self.store
                .persist_pending_components(root, pending_components)?;
            // now that we've written to disk, grab the critical write lock
            let mut write_lock = self.critical.write();
            if let Some((lru_root_ref, _)) = write_lock.in_memory.peek_lru() {
                // need to ensure the entry we just wrote to disk wasn't updated
                // while we were writing and is still the LRU entry
                if *lru_root_ref == root {
                    // it is still LRU entry -> delete it from memory & record that it's on disk
                    write_lock.in_memory.pop_lru();
                    write_lock.store_keys.insert(root);
                    stored = write_lock.in_memory.len();
                }
            }
            drop(write_lock);
        }

        drop(maintenance_lock);
        Ok(())
    }

    fn prune_disk(&self) -> Result<(), AvailabilityCheckError> {
        // ensure only one thread at a time can be deleting things from the disk or
        // moving things between memory and storage
        let maintenance_lock = self.maintenance_lock.lock();

        let mut block_keys = vec![];
        let mut current_block = None;
        for res in self
            .store
            .0
            .hot_db
            .iter_raw_entries(DBColumn::OverflowLRUCache, &[])
        {
            let (key_bytes, _) = res?;
            let overflow_key = OverflowKey::from_ssz_bytes(&key_bytes)?;

            if current_block == Some(*overflow_key.root()) {
                block_keys.push(overflow_key);
            } else {
                if let Some(previous_block_root) = current_block {
                    let read_lock = self.critical.read();
                    if !read_lock.store_keys.contains(&previous_block_root) {
                        // these keys aren't supposed to be in the store
                        self.store.delete_keys(&block_keys)?;
                    } else {
                        // TODO: check that this doesn't conflict with finalized block
                    }
                }
                current_block = Some(*overflow_key.root());
                block_keys = vec![overflow_key];
            }
        }

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

    #[test]
    fn cache_added_entries_exist() {
        let mut cache = LRUTimeCache::new(Duration::from_secs(10));

        cache.insert("t");
        cache.insert("e");

        // Should report that 't' and 't' already exists
        assert!(!cache.insert("t"));
        assert!(!cache.insert("e"));
    }

    #[test]
    fn test_reinsertion_updates_timeout() {
        let mut cache = LRUTimeCache::new(Duration::from_millis(100));

        cache.insert("a");
        cache.insert("b");

        std::thread::sleep(Duration::from_millis(20));
        cache.insert("a");
        // a is newer now

        std::thread::sleep(Duration::from_millis(85));
        assert!(cache.contains(&"a"),);
        // b was inserted first but was not as recent it should have been removed
        assert!(!cache.contains(&"b"));

        std::thread::sleep(Duration::from_millis(16));
        assert!(!cache.contains(&"a"));
    }
}
