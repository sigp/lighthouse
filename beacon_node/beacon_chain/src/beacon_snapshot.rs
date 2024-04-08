use serde::Serialize;
use std::sync::Arc;
use types::{
    AbstractExecPayload, BeaconState, EthSpec, FullPayload, Hash256, SignedBeaconBlock,
    SignedBlindedBeaconBlock,
};

/// Represents some block and its associated state. Generally, this will be used for tracking the
/// head, justified head and finalized head.
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct BeaconSnapshot<E: EthSpec, Payload: AbstractExecPayload<E> = FullPayload<E>> {
    pub beacon_block: Arc<SignedBeaconBlock<E, Payload>>,
    pub beacon_block_root: Hash256,
    pub beacon_state: BeaconState<E>,
}

/// This snapshot is to be used for verifying a child of `self.beacon_block`.
#[derive(Debug)]
pub struct PreProcessingSnapshot<T: EthSpec> {
    /// This state is equivalent to the `self.beacon_block.state_root()` state that has been
    /// advanced forward one slot using `per_slot_processing`. This state is "primed and ready" for
    /// the application of another block.
    pub pre_state: BeaconState<T>,
    /// This value is only set to `Some` if the `pre_state` was *not* advanced forward.
    pub beacon_state_root: Option<Hash256>,
    pub beacon_block: SignedBlindedBeaconBlock<T>,
    pub beacon_block_root: Hash256,
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> BeaconSnapshot<E, Payload> {
    /// Create a new checkpoint.
    pub fn new(
        beacon_block: Arc<SignedBeaconBlock<E, Payload>>,
        beacon_block_root: Hash256,
        beacon_state: BeaconState<E>,
    ) -> Self {
        Self {
            beacon_block,
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
        beacon_block: Arc<SignedBeaconBlock<E, Payload>>,
        beacon_block_root: Hash256,
        beacon_state: BeaconState<E>,
    ) {
        self.beacon_block = beacon_block;
        self.beacon_block_root = beacon_block_root;
        self.beacon_state = beacon_state;
    }
}
