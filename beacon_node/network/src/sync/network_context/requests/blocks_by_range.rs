use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::BlocksByRangeRequest;
use std::sync::Arc;
use types::{EthSpec, SignedBeaconBlock};

/// Accumulates results of a blocks_by_range request. Only returns items after receiving the
/// stream termination.
pub struct BlocksByRangeRequestItems<E: EthSpec> {
    request: BlocksByRangeRequest,
    items: Vec<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlocksByRangeRequestItems<E> {
    pub fn new(request: BlocksByRangeRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlocksByRangeRequestItems<E> {
    type Item = Arc<SignedBeaconBlock<E>>;

    fn add(&mut self, block: Self::Item) -> Result<bool, LookupVerifyError> {
        if block.slot().as_u64() < *self.request.start_slot()
            || block.slot().as_u64() >= self.request.start_slot() + self.request.count()
        {
            return Err(LookupVerifyError::UnrequestedSlot(block.slot()));
        }
        if self
            .items
            .iter()
            .any(|existing| existing.slot() == block.slot())
        {
            // DuplicatedData is a common error for all components, default index to 0
            return Err(LookupVerifyError::DuplicatedData(block.slot(), 0));
        }

        self.items.push(block);

        Ok(self.items.len() >= *self.request.count() as usize)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
