use eth2::types::FullPayloadContents;
use hashlink::lru_cache::LruCache;
use parking_lot::Mutex;
use tree_hash::TreeHash;
use types::Hash256;

pub const DEFAULT_PAYLOAD_CACHE_SIZE: usize = 10;

/// A cache mapping execution payloads by tree hash roots.
pub struct PayloadCache {
    payloads: Mutex<LruCache<PayloadCacheId, FullPayloadContents>>,
}

#[derive(Hash, PartialEq, Eq)]
struct PayloadCacheId(Hash256);

impl Default for PayloadCache {
    fn default() -> Self {
        PayloadCache {
            payloads: Mutex::new(LruCache::new(DEFAULT_PAYLOAD_CACHE_SIZE)),
        }
    }
}

impl PayloadCache {
    pub fn put(&self, payload: FullPayloadContents) -> Option<FullPayloadContents> {
        let root = payload.payload_ref().tree_hash_root();
        self.payloads.lock().insert(PayloadCacheId(root), payload)
    }

    pub fn pop(&self, root: &Hash256) -> Option<FullPayloadContents> {
        self.payloads.lock().remove(&PayloadCacheId(*root))
    }

    pub fn get(&self, hash: &Hash256) -> Option<FullPayloadContents> {
        self.payloads.lock().get(&PayloadCacheId(*hash)).cloned()
    }
}
