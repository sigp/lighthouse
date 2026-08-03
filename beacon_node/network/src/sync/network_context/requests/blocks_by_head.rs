use super::{ActiveRequestItems, LookupVerifyError};
use beacon_chain::get_block_root;
use std::sync::Arc;
use types::{EthSpec, Hash256, SignedBeaconBlock};

/// Accumulates the response of a `blocks_by_head` request. The responder walks the parent chain of
/// `beacon_root` (inclusive) and emits up to `count` blocks in descending slot order, so the first
/// chunk MUST be `beacon_root` and the rest are its ancestors.
pub struct BlocksByHeadRequestItems<E: EthSpec> {
    beacon_root: Hash256,
    count: usize,
    items: Vec<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlocksByHeadRequestItems<E> {
    pub fn new(beacon_root: Hash256, count: usize) -> Self {
        Self {
            beacon_root,
            count,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlocksByHeadRequestItems<E> {
    type Item = Arc<SignedBeaconBlock<E>>;

    /// Append a response chunk. The blocks must form a parent chain in strictly descending slot
    /// order, with the chain tip (first chunk) equal to the requested `beacon_root`.
    /// The active request SHOULD be dropped after `add` returns an error.
    fn add(&mut self, block: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = get_block_root(&block);
        if let Some(child) = self.items.last() {
            // Each subsequent block must be the parent of the previous one, with a strictly lower
            // slot, so the response forms a contiguous descending chain.
            if child.parent_root() != block_root {
                return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
            }
            if block.slot() >= child.slot() {
                return Err(LookupVerifyError::UnrequestedSlot(block.slot()));
            }
        } else {
            // The first block returned is the chain tip and must match the requested root.
            if self.beacon_root != block_root {
                return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
            }
        }

        self.items.push(block);
        // The peer may return fewer blocks than requested (e.g. reached genesis or finalization),
        // in which case the request completes on stream termination instead.
        Ok(self.items.len() >= self.count)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
