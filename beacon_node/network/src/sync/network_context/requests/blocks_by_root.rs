use beacon_chain::get_block_root;
use lighthouse_network::{rpc::BlocksByRootRequest, PeerId};
use std::sync::Arc;
use types::{ChainSpec, EthSpec, Hash256, SignedBeaconBlock};

use super::LookupVerifyError;

#[derive(Debug, Copy, Clone)]
pub struct BlocksByRootSingleRequest(pub Hash256);

impl BlocksByRootSingleRequest {
    pub fn into_request(self, spec: &ChainSpec) -> BlocksByRootRequest {
        BlocksByRootRequest::new(vec![self.0], spec)
    }
}

pub struct ActiveBlocksByRootRequest {
    request: BlocksByRootSingleRequest,
    resolved: bool,
    pub(crate) peer_id: PeerId,
}

impl ActiveBlocksByRootRequest {
    pub fn new(request: BlocksByRootSingleRequest, peer_id: PeerId) -> Self {
        Self {
            request,
            resolved: false,
            peer_id,
        }
    }

    /// Append a response to the single chunk request. If the chunk is valid, the request is
    /// resolved immediately.
    /// The active request SHOULD be dropped after `add_response` returns an error
    pub fn add_response<E: EthSpec>(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
    ) -> Result<Arc<SignedBeaconBlock<E>>, LookupVerifyError> {
        if self.resolved {
            return Err(LookupVerifyError::TooManyResponses);
        }

        let block_root = get_block_root(&block);
        if self.request.0 != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }

        // Valid data, blocks by root expects a single response
        self.resolved = true;
        Ok(block)
    }

    pub fn terminate(self) -> Result<(), LookupVerifyError> {
        if self.resolved {
            Ok(())
        } else {
            Err(LookupVerifyError::NoResponseReturned)
        }
    }
}
