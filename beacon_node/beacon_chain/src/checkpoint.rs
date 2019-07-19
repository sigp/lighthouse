use serde_derive::Serialize;
use ssz_derive::{Decode, Encode};
use types::{BeaconBlock, BeaconState, EthSpec, Hash256};

/// Represents some block and it's associated state. Generally, this will be used for tracking the
/// head, justified head and finalized head.
#[derive(Clone, Serialize, PartialEq, Debug, Encode, Decode)]
pub struct CheckPoint<E: EthSpec> {
    pub beacon_block: BeaconBlock<E>,
    pub beacon_block_root: Hash256,
    pub beacon_state: BeaconState<E>,
    pub beacon_state_root: Hash256,
}

impl<E: EthSpec> CheckPoint<E> {
    /// Create a new checkpoint.
    pub fn new(
        beacon_block: BeaconBlock<E>,
        beacon_block_root: Hash256,
        beacon_state: BeaconState<E>,
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
        beacon_block: BeaconBlock<E>,
        beacon_block_root: Hash256,
        beacon_state: BeaconState<E>,
        beacon_state_root: Hash256,
    ) {
        self.beacon_block = beacon_block;
        self.beacon_block_root = beacon_block_root;
        self.beacon_state = beacon_state;
        self.beacon_state_root = beacon_state_root;
    }
}
