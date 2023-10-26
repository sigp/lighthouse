use eth2::types::FullPayloadContents;
use lru::LruCache;
use parking_lot::Mutex;
use tree_hash::TreeHash;
use types::{EthSpec, Hash256};

pub const DEFAULT_PAYLOAD_CACHE_SIZE: usize = 10;

/// A cache mapping execution payloads by tree hash roots.
pub struct PayloadCache<T: EthSpec> {
    payloads: Mutex<LruCache<PayloadCacheId, FullPayloadContents<T>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct PayloadCacheId(Hash256);

impl<T: EthSpec> Default for PayloadCache<T> {
    fn default() -> Self {
        PayloadCache {
            payloads: Mutex::new(LruCache::new(DEFAULT_PAYLOAD_CACHE_SIZE)),
        }
    }
}

impl<T: EthSpec> PayloadCache<T> {
    pub fn put(&self, payload: FullPayloadContents<T>) -> Option<FullPayloadContents<T>> {
        let root = payload.payload_ref().tree_hash_root();
        self.payloads.lock().put(PayloadCacheId(root), payload)
    }

    pub fn pop(&self, root: &Hash256) -> Option<FullPayloadContents<T>> {
        self.payloads.lock().pop(&PayloadCacheId(*root))
    }

    pub fn get(&self, hash: &Hash256) -> Option<FullPayloadContents<T>> {
        self.payloads.lock().get(&PayloadCacheId(*hash)).cloned()
    }
}
