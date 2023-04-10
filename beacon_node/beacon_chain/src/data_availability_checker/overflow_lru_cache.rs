use crate::beacon_chain::BeaconStore;
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification::{AvailabilityPendingExecutedBlock, AvailableExecutedBlock};
use crate::data_availability_checker::{Availability, AvailabilityCheckError, PendingComponents};
use crate::store::{DBColumn, KeyValueStore};
use crate::BeaconChainTypes;
use lru::LruCache;
use parking_lot::{RawRwLock, RwLock, RwLockWriteGuard};
use ssz_derive::{Decode, Encode};
use std::collections::HashSet;
use types::{EthSpec, Hash256};

// A wrapper around BeaconStore<T> that implements various
// methods used for saving and retrieving objects from the
// store (for organization)
struct OverflowStore<T: BeaconChainTypes>(BeaconStore<T>);

#[derive(Encode, Decode)]
#[ssz(enum_behaviour = "union")]
enum OverflowValue<E: EthSpec> {
    Block(AvailabilityPendingExecutedBlock<E>),
    Blob(KzgVerifiedBlob<E>),
}

impl<T: BeaconChainTypes> OverflowStore<T> {
    pub fn persist_pending_components(
        &self,
        _block_root: Hash256,
        _pending_components: PendingComponents<T::EthSpec>,
    ) {
        // write this to disk
        // let col = DBColumn::OverflowLRUCache;
        // fn put_bytes(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error>;
        // self.0.hot_db.put_bytes()
        todo!()
    }

    pub fn get_pending_components(
        &self,
        _block_root: Hash256,
    ) -> Option<PendingComponents<T::EthSpec>> {
        // read everything from disk and reconstruct
        todo!()
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

    /// Puts the pending components in the LRU cache. If the cache
    /// is at capacity, the LRU entry is written to the store first
    pub fn put_pending_components(
        &mut self,
        block_root: Hash256,
        pending_components: PendingComponents<T::EthSpec>,
        overflow_store: &OverflowStore<T>,
    ) {
        if self.in_memory.len() == self.in_memory.cap() {
            // cache will overflow, must write lru entry to disk
            if let Some((lru_key, lru_value)) = self.in_memory.pop_lru() {
                overflow_store.persist_pending_components(lru_key, lru_value);
                self.store_keys.insert(lru_key);
            }
        }
        self.in_memory.put(block_root, pending_components);
    }

    /// Removes and returns the pending_components corresponding to
    /// the `block_root` or `None` if it does not exist
    pub fn pop_pending_components(
        &mut self,
        block_root: Hash256,
        store: &OverflowStore<T>,
    ) -> Option<PendingComponents<T::EthSpec>> {
        match self.in_memory.pop_entry(&block_root) {
            Some((_, pending_components)) => Some(pending_components),
            None => {
                // not in memory, is it in the store?
                if self.store_keys.remove(&block_root) {
                    store.get_pending_components(block_root)
                } else {
                    None
                }
            }
        }
    }
}

pub struct OverflowLRUCache<T: BeaconChainTypes> {
    critical: RwLock<Critical<T>>,
    store: OverflowStore<T>,
}

impl<T: BeaconChainTypes> OverflowLRUCache<T> {
    pub fn new(capacity: usize, store: BeaconStore<T>) -> Self {
        Self {
            critical: RwLock::new(Critical::new(capacity)),
            store: OverflowStore(store),
        }
    }

    pub fn put_kzg_verified_blob(
        &self,
        kzg_verified_blob: KzgVerifiedBlob<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut write_lock = self.critical.write();
        let block_root = kzg_verified_blob.block_root();

        let availability = if let Some(mut pending_components) =
            write_lock.pop_pending_components(block_root, &self.store)
        {
            if let Some(maybe_verified_blob) = pending_components
                .verified_blobs
                .get_mut(kzg_verified_blob.blob_index() as usize)
            {
                *maybe_verified_blob = Some(kzg_verified_blob)
            }

            if let Some(executed_block) = pending_components.executed_block.take() {
                self.check_block_availability_maybe_cache(
                    write_lock,
                    block_root,
                    pending_components,
                    executed_block,
                )?
            } else {
                write_lock.put_pending_components(block_root, pending_components, &self.store);
                Availability::PendingBlock(block_root)
            }
        } else {
            // not in memory or store -> put new in memory
            let new_pending_components = PendingComponents::new_from_blob(kzg_verified_blob);
            write_lock.put_pending_components(block_root, new_pending_components, &self.store);
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

        let availability = match write_lock.pop_pending_components(block_root, &self.store) {
            Some(pending_components) => self.check_block_availability_maybe_cache(
                write_lock,
                block_root,
                pending_components,
                executed_block,
            )?,
            None => {
                let all_blob_ids = executed_block.get_all_blob_ids();
                let new_pending_components = PendingComponents::new_from_block(executed_block);
                write_lock.put_pending_components(block_root, new_pending_components, &self.store);
                Availability::PendingBlobs(all_blob_ids)
            }
        };

        Ok(availability)
    }

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
            write_lock.put_pending_components(block_root, pending_components, &self.store);

            Ok(Availability::PendingBlobs(missing_blob_ids))
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
