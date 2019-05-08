use serde_derive::Serialize;
use types::{BeaconBlock, BeaconState, BeaconStateTypes, Hash256};

/// Represents some block and it's associated state. Generally, this will be used for tracking the
/// head, justified head and finalized head.
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct CheckPoint<B: BeaconStateTypes> {
    pub beacon_block: BeaconBlock,
    pub beacon_block_root: Hash256,
    pub beacon_state: BeaconState<B>,
    pub beacon_state_root: Hash256,
}

impl<B: BeaconStateTypes> CheckPoint<B> {
    /// Create a new checkpoint.
    pub fn new(
        beacon_block: BeaconBlock,
        beacon_block_root: Hash256,
        beacon_state: BeaconState<B>,
        beacon_state_root: Hash256,
    ) -> Self {
        Self {
            beacon_block,
            beacon_block_root,
            beacon_state,
            beacon_state_root,
        }
    }

    /// Update all fields of the checkpoint.
    pub fn update(
        &mut self,
        beacon_block: BeaconBlock,
        beacon_block_root: Hash256,
        beacon_state: BeaconState<B>,
        beacon_state_root: Hash256,
    ) {
        self.beacon_block = beacon_block;
        self.beacon_block_root = beacon_block_root;
        self.beacon_state = beacon_state;
        self.beacon_state_root = beacon_state_root;
    }
}
