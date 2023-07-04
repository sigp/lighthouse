use lru::LruCache;
use parking_lot::Mutex;
use types::{EthSpec, Hash256, Sidecar, SidecarList};

pub const DEFAULT_BLOB_CACHE_SIZE: usize = 10;

/// A cache blobs by beacon block root.
pub struct BlobCache<T: EthSpec, S: Sidecar<T>> {
    blobs: Mutex<LruCache<BlobCacheId, SidecarList<T, S>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct BlobCacheId(Hash256);

impl<T: EthSpec, S: Sidecar<T>> Default for BlobCache<T, S> {
    fn default() -> Self {
        BlobCache {
            blobs: Mutex::new(LruCache::new(DEFAULT_BLOB_CACHE_SIZE)),
        }
    }
}

impl<T: EthSpec, S: Sidecar<T>> BlobCache<T, S> {
    pub fn put(
        &self,
        beacon_block: Hash256,
        blobs: SidecarList<T, S>,
    ) -> Option<SidecarList<T, S>> {
        self.blobs.lock().put(BlobCacheId(beacon_block), blobs)
    }

    pub fn pop(&self, root: &Hash256) -> Option<SidecarList<T, S>> {
        self.blobs.lock().pop(&BlobCacheId(*root))
    }
}
