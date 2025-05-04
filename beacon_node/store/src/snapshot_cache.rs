use crate::StoreError as Error;
use lru::LruCache;
use parking_lot::RwLock;
use std::num::NonZeroUsize;
use std::sync::Arc;
use types::{BeaconState, EthSpec, Hash256, Slot};

pub struct SnapshotCache<E: EthSpec> {
    states: RwLock<LruCache<Hash256, Arc<BeaconState<E>>>>,
}

impl<E: EthSpec> SnapshotCache<E> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            states: RwLock::new(LruCache::new(capacity)),
        }
    }

    pub fn get(&self, key: &Hash256) -> Option<Arc<BeaconState<E>>> {
        self.states.write().get(key).cloned()
    }

    pub fn put(&self, key: Hash256, value: Arc<BeaconState<E>>) -> Result<(), Error> {
        self.states.write().put(key, value);
        Ok(())
    }

    pub fn contains(&self, key: &Hash256) -> bool {
        self.states.write().contains(key)
    }

    pub fn clear(&self) {
        self.states.write().clear();
    }
} 