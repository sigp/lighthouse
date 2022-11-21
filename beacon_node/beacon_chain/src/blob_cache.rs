use lru::LruCache;
use parking_lot::Mutex;
use tree_hash::TreeHash;
use types::{BlobsSidecar, EthSpec, ExecutionPayload, Hash256};

pub const DEFAULT_BLOB_CACHE_SIZE: usize = 10;

/// A cache blobs by beacon block root.
pub struct BlobCache<T: EthSpec> {
    blobs: Mutex<LruCache<BlobCacheId, BlobsSidecar<T>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct BlobCacheId(Hash256);

impl<T: EthSpec> Default for BlobCache<T> {
    fn default() -> Self {
        BlobCache {
            blobs: Mutex::new(LruCache::new(DEFAULT_BLOB_CACHE_SIZE)),
        }
    }
}

impl<T: EthSpec> BlobCache<T> {
    pub fn put(&self, beacon_block: Hash256, blobs: BlobsSidecar<T>) -> Option<BlobsSidecar<T>> {
        self.blobs.lock().put(BlobCacheId(beacon_block), blobs)
    }

    pub fn pop(&self, root: &Hash256) -> Option<BlobsSidecar<T>> {
        self.blobs.lock().pop(&BlobCacheId(*root))
    }
}
