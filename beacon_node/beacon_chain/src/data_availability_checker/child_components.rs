use crate::block_verification_types::RpcBlock;
use crate::data_availability_checker::AvailabilityView;
use std::sync::Arc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{EthSpec, SignedBeaconBlock};

/// For requests triggered by an `UnknownBlockParent` or `UnknownBlobParent`, this struct
/// is used to cache components as they are sent to the network service. We can't use the
/// data availability cache currently because any blocks or blobs without parents
/// won't pass validation and therefore won't make it into the cache.
#[derive(Default)]
pub struct ChildComponents<E: EthSpec> {
    pub downloaded_block: Option<Arc<SignedBeaconBlock<E>>>,
    pub downloaded_blobs: FixedBlobSidecarList<E>,
}

impl<E: EthSpec> From<RpcBlock<E>> for ChildComponents<E> {
    fn from(value: RpcBlock<E>) -> Self {
        let (block, blobs) = value.deconstruct();
        let fixed_blobs = blobs.map(|blobs| {
            FixedBlobSidecarList::from(blobs.into_iter().map(Some).collect::<Vec<_>>())
        });
        Self::new(Some(block), fixed_blobs)
    }
}

impl<E: EthSpec> ChildComponents<E> {
    pub fn new(
        block: Option<Arc<SignedBeaconBlock<E>>>,
        blobs: Option<FixedBlobSidecarList<E>>,
    ) -> Self {
        let mut cache = Self::default();
        if let Some(block) = block {
            cache.merge_block(block);
        }
        if let Some(blobs) = blobs {
            cache.merge_blobs(blobs);
        }
        cache
    }

    pub fn clear_blobs(&mut self) {
        self.downloaded_blobs = FixedBlobSidecarList::default();
    }

    pub fn add_cached_child_block(&mut self, block: Arc<SignedBeaconBlock<E>>) {
        self.merge_block(block)
    }

    pub fn add_cached_child_blobs(&mut self, blobs: FixedBlobSidecarList<E>) {
        self.merge_blobs(blobs)
    }
}
