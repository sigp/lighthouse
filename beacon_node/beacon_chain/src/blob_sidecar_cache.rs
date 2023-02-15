use lru::LruCache;
use parking_lot::Mutex;
use types::{BlobSidecar, EthSpec, Hash256};

// FIXME(jimmy): Remove this placeholder cache once `blob_cache` is implemented for decoupled `BlobSidecar`

pub const DEFAULT_BLOB_CACHE_SIZE: usize = 10;

/// A cache blobs by beacon block root.
pub struct BlobSidecarsCache<T: EthSpec> {
    pub blobs: Mutex<LruCache<BlobCacheId, Vec<BlobSidecar<T>>>>,
}

#[derive(Hash, PartialEq, Eq)]
pub struct BlobCacheId(Hash256);

impl<T: EthSpec> Default for BlobSidecarsCache<T> {
    fn default() -> Self {
        BlobSidecarsCache {
            blobs: Mutex::new(LruCache::new(DEFAULT_BLOB_CACHE_SIZE)),
        }
    }
}

impl<T: EthSpec> BlobSidecarsCache<T> {
    pub fn put(&self, beacon_block: Hash256, blob: BlobSidecar<T>) -> Option<Vec<BlobSidecar<T>>> {
        let mut cache = self.blobs.lock();
        match cache.get_mut(&BlobCacheId(beacon_block)) {
            Some(existing_blob_sidecars) => {
                existing_blob_sidecars.push(blob);
                None
            }
            None => cache.put(BlobCacheId(beacon_block), vec![blob]),
        }
    }

    pub fn pop(&self, root: &Hash256) -> Option<Vec<BlobSidecar<T>>> {
        self.blobs.lock().pop(&BlobCacheId(*root))
    }
}
