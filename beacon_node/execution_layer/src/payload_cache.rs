use eth2::types::FullPayloadContents;
use hashlink::lru_cache::LruCache;
use parking_lot::Mutex;
use tree_hash::TreeHash;
use types::{EthSpec, Hash256};

pub const DEFAULT_PAYLOAD_CACHE_SIZE: usize = 10;

/// A cache mapping execution payloads by tree hash roots.
pub struct PayloadCache<E: EthSpec> {
    payloads: Mutex<LruCache<PayloadCacheId, FullPayloadContents<E>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct PayloadCacheId(Hash256);

impl<E: EthSpec> Default for PayloadCache<E> {
    fn default() -> Self {
        PayloadCache {
            payloads: Mutex::new(LruCache::new(DEFAULT_PAYLOAD_CACHE_SIZE)),
        }
    }
}

impl<E: EthSpec> PayloadCache<E> {
    pub fn put(&self, payload: FullPayloadContents<E>) -> Option<FullPayloadContents<E>> {
        let root = payload.payload_ref().tree_hash_root();
        self.payloads.lock().insert(PayloadCacheId(root), payload)
    }

    pub fn pop(&self, root: &Hash256) -> Option<FullPayloadContents<E>> {
        self.payloads.lock().remove(&PayloadCacheId(*root))
    }

    pub fn get(&self, hash: &Hash256) -> Option<FullPayloadContents<E>> {
        self.payloads.lock().get(&PayloadCacheId(*hash)).cloned()
    }
}
