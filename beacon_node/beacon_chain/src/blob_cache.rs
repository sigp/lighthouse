use lru::LruCache;
use parking_lot::Mutex;
use types::Hash256;

pub const DEFAULT_BLOB_CACHE_SIZE: usize = 10;

/// A cache blobs by beacon block root.
pub struct BlobCache<T> {
    blobs: Mutex<LruCache<BlobCacheId, T>>,
}

#[derive(Hash, PartialEq, Eq)]
struct BlobCacheId(Hash256);

impl<T> Default for BlobCache<T> {
    fn default() -> Self {
        BlobCache {
            blobs: Mutex::new(LruCache::new(DEFAULT_BLOB_CACHE_SIZE)),
        }
    }
}

impl<T> BlobCache<T> {
    pub fn put(&self, beacon_block: Hash256, blobs: T) -> Option<T> {
        self.blobs.lock().put(BlobCacheId(beacon_block), blobs)
    }

    pub fn pop(&self, root: &Hash256) -> Option<T> {
        self.blobs.lock().pop(&BlobCacheId(*root))
    }
}
