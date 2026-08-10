use serde::Serialize;
use std::sync::Arc;
use types::{
    AbstractExecPayload, BeaconState, FullPayload, Hash256, SignedBeaconBlock,
    SignedBlindedBeaconBlock, SignedExecutionPayloadEnvelope,
};

/// Represents some block and its associated state. Generally, this will be used for tracking the
/// head, justified head and finalized head.
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct BeaconSnapshot<Payload: AbstractExecPayload = FullPayload> {
    pub beacon_block: Arc<SignedBeaconBlock<Payload>>,
    pub execution_envelope: Option<Arc<SignedExecutionPayloadEnvelope>>,
    pub beacon_block_root: Hash256,
    pub beacon_state: BeaconState,
}

/// This snapshot is to be used for verifying a child of `self.beacon_block`.
#[derive(Debug)]
pub struct PreProcessingSnapshot {
    /// This state is equivalent to the `self.beacon_block.state_root()` state that has been
    /// advanced forward one slot using `per_slot_processing`. This state is "primed and ready" for
    /// the application of another block.
    pub pre_state: BeaconState,
    /// This value is only set to `Some` if the `pre_state` was *not* advanced forward.
    pub beacon_state_root: Option<Hash256>,
    pub beacon_block: SignedBlindedBeaconBlock,
    pub beacon_block_root: Hash256,
}

impl<Payload: AbstractExecPayload> BeaconSnapshot<Payload> {
    /// Create a new checkpoint.
    pub fn new(
        beacon_block: Arc<SignedBeaconBlock<Payload>>,
        execution_envelope: Option<Arc<SignedExecutionPayloadEnvelope>>,
        beacon_block_root: Hash256,
        beacon_state: BeaconState,
    ) -> Self {
        Self {
            beacon_block,
            execution_envelope,
            beacon_block_root,
            beacon_state,
        }
    }

    /// Returns the state root from `self.beacon_block`.
    ///
    /// ## Caution
    ///
    /// It is not strictly enforced that `root(self.beacon_state) == self.beacon_state_root()`.
    pub fn beacon_state_root(&self) -> Hash256 {
        self.beacon_block.message().state_root()
    }

    /// Update all fields of the checkpoint.
    pub fn update(
        &mut self,
        beacon_block: Arc<SignedBeaconBlock<Payload>>,
        execution_envelope: Option<Arc<SignedExecutionPayloadEnvelope>>,
        beacon_block_root: Hash256,
        beacon_state: BeaconState,
    ) {
        self.beacon_block = beacon_block;
        self.execution_envelope = execution_envelope;
        self.beacon_block_root = beacon_block_root;
        self.beacon_state = beacon_state;
    }
}
