use serde_derive::Serialize;
use ssz_derive::{Decode, Encode};
use types::{beacon_state::CloneConfig, BeaconState, EthSpec, Hash256, SignedBeaconBlock};

/// Represents some block and its associated state. Generally, this will be used for tracking the
/// head, justified head and finalized head.
#[derive(Clone, Serialize, PartialEq, Debug, Encode, Decode)]
pub struct BeaconSnapshot<E: EthSpec> {
    pub beacon_block: SignedBeaconBlock<E>,
    pub beacon_block_root: Hash256,
    pub beacon_state: BeaconState<E>,
    pub beacon_state_root: Hash256,
}

impl<E: EthSpec> BeaconSnapshot<E> {
    /// Create a new checkpoint.
    pub fn new(
        beacon_block: SignedBeaconBlock<E>,
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
        beacon_block: SignedBeaconBlock<E>,
        beacon_block_root: Hash256,
        beacon_state: BeaconState<E>,
        beacon_state_root: Hash256,
    ) {
        self.beacon_block = beacon_block;
        self.beacon_block_root = beacon_block_root;
        self.beacon_state = beacon_state;
        self.beacon_state_root = beacon_state_root;
    }

    pub fn clone_with(&self, clone_config: CloneConfig) -> Self {
        Self {
            beacon_block: self.beacon_block.clone(),
            beacon_block_root: self.beacon_block_root,
            beacon_state: self.beacon_state.clone_with(clone_config),
            beacon_state_root: self.beacon_state_root,
        }
    }
}
