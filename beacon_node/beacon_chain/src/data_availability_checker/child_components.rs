use crate::block_verification_types::RpcBlock;
use bls::Hash256;
use std::sync::Arc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{BlobSidecar, EthSpec, SignedBeaconBlock};

/// For requests triggered by an `UnknownBlockParent` or `UnknownBlobParent`, this struct
/// is used to cache components as they are sent to the network service. We can't use the
/// data availability cache currently because any blocks or blobs without parents
/// won't pass validation and therefore won't make it into the cache.
pub struct ChildComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub downloaded_block: Option<Arc<SignedBeaconBlock<E>>>,
    pub downloaded_blobs: FixedBlobSidecarList<E>,
}

impl<E: EthSpec> From<RpcBlock<E>> for ChildComponents<E> {
    fn from(value: RpcBlock<E>) -> Self {
        let (block_root, block, blobs) = value.deconstruct();
        let fixed_blobs = blobs.map(|blobs| {
            FixedBlobSidecarList::from(blobs.into_iter().map(Some).collect::<Vec<_>>())
        });
        Self::new(block_root, Some(block), fixed_blobs)
    }
}

impl<E: EthSpec> ChildComponents<E> {
    pub fn empty(block_root: Hash256) -> Self {
        Self {
            block_root,
            downloaded_block: None,
            downloaded_blobs: <_>::default(),
        }
    }
    pub fn new(
        block_root: Hash256,
        block: Option<Arc<SignedBeaconBlock<E>>>,
        blobs: Option<FixedBlobSidecarList<E>>,
    ) -> Self {
        let mut cache = Self::empty(block_root);
        if let Some(block) = block {
            cache.merge_block(block);
        }
        if let Some(blobs) = blobs {
            cache.merge_blobs(blobs);
        }
        cache
    }

    pub fn merge_block(&mut self, block: Arc<SignedBeaconBlock<E>>) {
        self.downloaded_block = Some(block);
    }

    pub fn merge_blob(&mut self, blob: Arc<BlobSidecar<E>>) {
        if let Some(blob_ref) = self.downloaded_blobs.get_mut(blob.index as usize) {
            *blob_ref = Some(blob);
        }
    }

    pub fn merge_blobs(&mut self, blobs: FixedBlobSidecarList<E>) {
        for blob in blobs.iter().flatten() {
            self.merge_blob(blob.clone());
        }
    }

    pub fn clear_blobs(&mut self) {
        self.downloaded_blobs = FixedBlobSidecarList::default();
    }
}
