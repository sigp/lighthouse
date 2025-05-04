use crate::StoreError as Error;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use types::{BeaconState, EthSpec, Hash256, Slot};

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct RestorePoint<E: EthSpec> {
    pub slot: Slot,
    pub state_root: Hash256,
    pub state: BeaconState<E>,
    pub block_root: Hash256,
}

impl<E: EthSpec> RestorePoint<E> {
    pub fn new(
        slot: Slot,
        state_root: Hash256,
        state: BeaconState<E>,
        block_root: Hash256,
    ) -> Result<Self, Error> {
        Ok(Self {
            slot,
            state_root,
            state,
            block_root,
        })
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn state_root(&self) -> Hash256 {
        self.state_root
    }

    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn into_state(self) -> BeaconState<E> {
        self.state
    }
} 