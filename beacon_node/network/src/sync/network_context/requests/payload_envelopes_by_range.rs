use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::PayloadEnvelopesByRangeRequest;
use std::sync::Arc;
use types::{EthSpec, SignedExecutionPayloadEnvelope};

/// Accumulates results of a payload_envelopes_by_range request. Only returns items after
/// receiving the stream termination.
pub struct PayloadEnvelopesByRangeRequestItems<E: EthSpec> {
    request: PayloadEnvelopesByRangeRequest,
    items: Vec<Arc<SignedExecutionPayloadEnvelope<E>>>,
}

impl<E: EthSpec> PayloadEnvelopesByRangeRequestItems<E> {
    pub fn new(request: PayloadEnvelopesByRangeRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for PayloadEnvelopesByRangeRequestItems<E> {
    type Item = Arc<SignedExecutionPayloadEnvelope<E>>;

    fn add(&mut self, envelope: Self::Item) -> Result<bool, LookupVerifyError> {
        let slot = envelope.slot();
        if slot < self.request.start_slot || slot >= self.request.start_slot + self.request.count {
            return Err(LookupVerifyError::UnrequestedSlot(slot));
        }
        if self.items.iter().any(|existing| existing.slot() == slot) {
            return Err(LookupVerifyError::DuplicatedData(slot, 0));
        }

        self.items.push(envelope);

        Ok(false)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
