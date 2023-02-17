use lru::LruCache;
use parking_lot::Mutex;
use std::sync::Arc;
use types::{BlobSidecar, EthSpec, Hash256};

pub const DEFAULT_BLOB_CACHE_SIZE: usize = 10;

/// A cache blobs by beacon block root.
pub struct BlobCache<T: EthSpec> {
    blobs: Mutex<LruCache<BlobCacheId, Arc<BlobSidecar<T>>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct BlobCacheId {
    block_root: Hash256,
    blob_index: u64,
}

pub enum BlobCacheError {
    MissingBlobs,
}

impl<T: EthSpec> Default for BlobCache<T> {
    fn default() -> Self {
        BlobCache {
            blobs: Mutex::new(LruCache::new(
                DEFAULT_BLOB_CACHE_SIZE * T::max_blobs_per_block(),
            )),
        }
    }
}

impl<T: EthSpec> BlobCache<T> {
    pub fn put(
        &self,
        block_root: Hash256,
        blob: BlobSidecar<T>,
        blob_index: u64,
    ) -> Option<Arc<BlobSidecar<T>>> {
        self.blobs.lock().put(
            BlobCacheId {
                block_root,
                blob_index,
            },
            Arc::new(blob),
        )
    }

    pub fn pop(&self, block_root: &Hash256, blob_index: u64) -> Option<Arc<BlobSidecar<T>>> {
        self.blobs.lock().pop(&BlobCacheId {
            block_root: *block_root,
            blob_index,
        })
    }

    pub fn peek_blobs_for_block(
        &self,
        block_root: &Hash256,
        expected_blobs_count: usize,
    ) -> Result<Vec<Arc<BlobSidecar<T>>>, BlobCacheError> {
        let guard = self.blobs.lock();
        let blob_sidecars: Vec<Arc<BlobSidecar<T>>> = (0..T::max_blobs_per_block())
            .map(|blob_index| {
                guard
                    .peek(&BlobCacheId {
                        block_root: *block_root,
                        blob_index: blob_index as u64,
                    })
                    .cloned()
            })
            .into_iter()
            .flatten()
            .collect();

        if blob_sidecars.len() != expected_blobs_count {
            Err(BlobCacheError::MissingBlobs)
        } else {
            Ok(blob_sidecars)
        }
    }
}
