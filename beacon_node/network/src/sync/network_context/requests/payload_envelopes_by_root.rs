use lighthouse_network::rpc::methods::PayloadEnvelopesByRootRequest;
use std::sync::Arc;
use types::{EthSpec, ForkContext, Hash256, SignedExecutionPayloadEnvelope};

use super::{ActiveRequestItems, LookupVerifyError};

#[derive(Debug, Copy, Clone)]
pub struct PayloadEnvelopesByRootSingleRequest(pub Hash256);

impl PayloadEnvelopesByRootSingleRequest {
    pub fn into_request(
        self,
        fork_context: &ForkContext,
    ) -> Result<PayloadEnvelopesByRootRequest, String> {
        PayloadEnvelopesByRootRequest::new(vec![self.0], fork_context)
    }
}

pub struct PayloadEnvelopesByRootRequestItems<E: EthSpec> {
    request: PayloadEnvelopesByRootSingleRequest,
    items: Vec<Arc<SignedExecutionPayloadEnvelope<E>>>,
}

impl<E: EthSpec> PayloadEnvelopesByRootRequestItems<E> {
    pub fn new(request: PayloadEnvelopesByRootSingleRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for PayloadEnvelopesByRootRequestItems<E> {
    type Item = Arc<SignedExecutionPayloadEnvelope<E>>;

    /// Append a response to the single chunk request. If the chunk is valid, the request is
    /// resolved immediately.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add(&mut self, envelope: Self::Item) -> Result<bool, LookupVerifyError> {
        let beacon_block_root = envelope.beacon_block_root();
        if self.request.0 != beacon_block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(beacon_block_root));
        }

        self.items.push(envelope);
        // Always returns true, payload envelopes by root expects a single response
        Ok(true)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
