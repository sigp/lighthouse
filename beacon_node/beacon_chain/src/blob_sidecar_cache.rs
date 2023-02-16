use lru::LruCache;
use parking_lot::Mutex;
use types::{BlobSidecar, EthSpec, Hash256};

pub const DEFAULT_BLOB_CACHE_SIZE: usize = 10;

/// A cache blobs by beacon block root.
pub struct BlobSidecarsCache<T: EthSpec> {
    pub blobs: Mutex<LruCache<BlobCacheId, BlobSidecar<T>>>,
}

#[derive(Hash, PartialEq, Eq)]
pub struct BlobCacheId {
    block_root: Hash256,
    blob_index: u64,
}

pub enum BlobCacheError {
    MissingBlobs,
}

impl<T: EthSpec> Default for BlobSidecarsCache<T> {
    fn default() -> Self {
        BlobSidecarsCache {
            blobs: Mutex::new(LruCache::new(
                DEFAULT_BLOB_CACHE_SIZE * T::max_blobs_per_block(),
            )),
        }
    }
}

impl<T: EthSpec> BlobSidecarsCache<T> {
    pub fn put(
        &self,
        block_root: Hash256,
        blob: BlobSidecar<T>,
        blob_index: u64,
    ) -> Option<BlobSidecar<T>> {
        self.blobs.lock().put(
            BlobCacheId {
                block_root,
                blob_index,
            },
            blob,
        )
    }

    pub fn pop(&self, block_root: &Hash256, blob_index: u64) -> Option<BlobSidecar<T>> {
        self.blobs.lock().pop(&BlobCacheId {
            block_root: *block_root,
            blob_index,
        })
    }

    pub fn peek_blobs_for_block(
        &self,
        block_root: &Hash256,
        expected_blobs_count: usize,
    ) -> Result<Vec<BlobSidecar<T>>, BlobCacheError> {
        let guard = self.blobs.lock();
        let blob_sidecars: Vec<BlobSidecar<T>> = (0..T::max_blobs_per_block())
            .map(|blob_index| {
                guard
                    .peek(&BlobCacheId {
                        block_root: *block_root,
                        blob_index: blob_index as u64,
                    })
                    // FIXME(jimmy) we should avoid cloning the blob - temporary hack to make it compile
                    .map(|blob| blob.clone())
            })
            .into_iter()
            .filter_map(|blob| blob)
            .collect();

        if blob_sidecars.len() != expected_blobs_count {
            Err(BlobCacheError::MissingBlobs)
        } else {
            Ok(blob_sidecars)
        }
    }
}
