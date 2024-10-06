use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::BlobsByRangeRequest;
use std::sync::Arc;
use types::{BlobSidecar, EthSpec};

/// Accumulates results of a blobs_by_range request. Only returns items after receiving the
/// stream termination.
pub struct BlobsByRangeRequestItems<E: EthSpec> {
    request: BlobsByRangeRequest,
    items: Vec<Arc<BlobSidecar<E>>>,
}

impl<E: EthSpec> BlobsByRangeRequestItems<E> {
    pub fn new(request: BlobsByRangeRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlobsByRangeRequestItems<E> {
    type Item = Arc<BlobSidecar<E>>;

    fn add(&mut self, item: Self::Item) -> Result<bool, LookupVerifyError> {
        if item.slot() < self.request.start_slot
            || item.slot() >= self.request.start_slot + self.request.count
        {
            return Err(LookupVerifyError::UnrequestedSlot(item.slot()));
        }
        // TODO: Should check if index is within bounds

        self.items.push(item);

        // Skip check if blobs are ready as it's rare that all blocks have max blobs
        Ok(false)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
