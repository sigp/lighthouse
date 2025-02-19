use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::BlobsByRangeRequest;
use std::sync::Arc;
use types::{BlobSidecar, EthSpec};

/// Accumulates results of a blobs_by_range request. Only returns items after receiving the
/// stream termination.
pub struct BlobsByRangeRequestItems<E: EthSpec> {
    request: BlobsByRangeRequest,
    items: Vec<Arc<BlobSidecar<E>>>,
    max_blobs_per_block: u64,
}

impl<E: EthSpec> BlobsByRangeRequestItems<E> {
    pub fn new(request: BlobsByRangeRequest, max_blobs_per_block: u64) -> Self {
        Self {
            request,
            items: vec![],
            max_blobs_per_block,
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlobsByRangeRequestItems<E> {
    type Item = Arc<BlobSidecar<E>>;

    fn add(&mut self, blob: Self::Item) -> Result<bool, LookupVerifyError> {
        if blob.slot() < self.request.start_slot
            || blob.slot() >= self.request.start_slot + self.request.count
        {
            return Err(LookupVerifyError::UnrequestedSlot(blob.slot()));
        }
        if blob.index >= self.max_blobs_per_block {
            return Err(LookupVerifyError::UnrequestedIndex(blob.index));
        }
        if !blob.verify_blob_sidecar_inclusion_proof() {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }
        if self
            .items
            .iter()
            .any(|existing| existing.slot() == blob.slot() && existing.index == blob.index)
        {
            return Err(LookupVerifyError::DuplicatedData(blob.slot(), blob.index));
        }

        self.items.push(blob);

        // Skip check if blobs are ready as it's rare that all blocks have max blobs
        Ok(false)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
