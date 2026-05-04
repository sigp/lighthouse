//! Envelope-specific extensions to `SingleBlockLookup`.
//!
//! Envelope-only lookups are created when a block's parent is known and imported but its
//! execution payload envelope has not yet been received. The block download step is skipped
//! (marked complete immediately), and only the envelope — and possibly subsequent custody
//! columns — are fetched.

use super::single_block_lookup::{
    AwaitingParent, ComponentRequests, CustodyRequestState, EnvelopeRequestState, SingleBlockLookup,
};
use beacon_chain::BeaconChainTypes;
use lighthouse_network::PeerId;
use lighthouse_network::service::api_types::Id;
use store::Hash256;

impl<T: BeaconChainTypes> SingleBlockLookup<T> {
    /// Create an envelope-only lookup. The block is already imported; only the envelope (and
    /// potentially custody columns) need to be fetched.
    pub fn new_envelope_only(block_root: Hash256, peers: &[PeerId], id: Id) -> Self {
        let mut lookup = Self::new(block_root, peers, id, None);
        // Block is already imported — advance past the download step immediately.
        lookup
            .block_request_state
            .state
            .on_completed_request("block already imported")
            .expect("block state starts as AwaitingDownload");
        lookup.component_requests =
            ComponentRequests::ActiveEnvelopeRequest(EnvelopeRequestState::new(block_root));
        lookup
    }

    /// Transition from `ActiveEnvelopeRequest` to `ActiveCustodyRequest`.
    ///
    /// Called when envelope processing returns `MissingComponents`: the envelope has been executed
    /// but data columns have not yet arrived and must be fetched separately.
    /// Returns `true` if the transition was made, `false` if state was not an envelope request.
    pub fn transition_envelope_to_custody(&mut self) -> bool {
        if matches!(
            self.component_requests,
            ComponentRequests::ActiveEnvelopeRequest(_)
        ) {
            self.component_requests =
                ComponentRequests::ActiveCustodyRequest(CustodyRequestState::new(self.block_root));
            true
        } else {
            false
        }
    }

    /// Returns the parent root if this lookup is awaiting a parent envelope.
    pub fn awaiting_parent_envelope(&self) -> Option<Hash256> {
        match self.awaiting_parent {
            Some(AwaitingParent::Envelope(root)) => Some(root),
            _ => None,
        }
    }

    /// Mark this lookup as awaiting a parent envelope before processing can resume.
    pub fn set_awaiting_parent_envelope(&mut self, parent_root: Hash256) {
        self.awaiting_parent = Some(AwaitingParent::Envelope(parent_root));
    }
}
