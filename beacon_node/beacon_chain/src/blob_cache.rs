use lru::LruCache;
use parking_lot::Mutex;
use types::{AbstractSidecar, EthSpec, Hash256, SidecarList};

pub const DEFAULT_BLOB_CACHE_SIZE: usize = 10;

/// A cache blobs by beacon block root.
pub struct BlobCache<T: EthSpec, Sidecar: AbstractSidecar<T>> {
    blobs: Mutex<LruCache<BlobCacheId, SidecarList<T, Sidecar>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct BlobCacheId(Hash256);

impl<T: EthSpec, Sidecar: AbstractSidecar<T>> Default for BlobCache<T, Sidecar> {
    fn default() -> Self {
        BlobCache {
            blobs: Mutex::new(LruCache::new(DEFAULT_BLOB_CACHE_SIZE)),
        }
    }
}

impl<T: EthSpec, Sidecar: AbstractSidecar<T>> BlobCache<T, Sidecar> {
    pub fn put(
        &self,
        beacon_block: Hash256,
        blobs: SidecarList<T, Sidecar>,
    ) -> Option<SidecarList<T, Sidecar>> {
        self.blobs.lock().put(BlobCacheId(beacon_block), blobs)
    }

    pub fn pop(&self, root: &Hash256) -> Option<SidecarList<T, Sidecar>> {
        self.blobs.lock().pop(&BlobCacheId(*root))
    }
}
