use lighthouse_network::rpc::methods::PayloadEnvelopesByRootRequest;
use std::sync::Arc;
use types::{ForkContext, Hash256, SignedExecutionPayloadEnvelope};

use super::{ActiveRequestItems, LookupVerifyError};

#[derive(Debug, Clone)]
pub struct PayloadEnvelopesByRootSingleRequest {
    pub block_root: Hash256,
}

impl PayloadEnvelopesByRootSingleRequest {
    pub fn into_request(
        self,
        fork_context: &ForkContext,
    ) -> Result<PayloadEnvelopesByRootRequest, String> {
        PayloadEnvelopesByRootRequest::new(vec![self.block_root], fork_context)
    }
}

pub struct PayloadEnvelopesByRootRequestItems {
    request: PayloadEnvelopesByRootSingleRequest,
    items: Vec<Arc<SignedExecutionPayloadEnvelope>>,
}

impl PayloadEnvelopesByRootRequestItems {
    pub fn new(request: PayloadEnvelopesByRootSingleRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl ActiveRequestItems for PayloadEnvelopesByRootRequestItems {
    type Item = Arc<SignedExecutionPayloadEnvelope>;

    /// Append a response to the single chunk request. We expect exactly one envelope per
    /// block root. Returns `true` when the single expected item has been received.
    fn add(&mut self, envelope: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = envelope.message.beacon_block_root;
        if self.request.block_root != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }

        self.items.push(envelope);
        // Always returns true, we expect a single envelope per block root
        Ok(true)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
