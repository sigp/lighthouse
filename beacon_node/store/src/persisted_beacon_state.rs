use crate::StoreError as Error;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use types::{BeaconState, EthSpec, Hash256, Slot};

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct PersistedBeaconState<E: EthSpec> {
    pub state: BeaconState<E>,
    pub state_root: Hash256,
}

impl<E: EthSpec> PersistedBeaconState<E> {
    pub fn new(state: BeaconState<E>, state_root: Hash256) -> Result<Self, Error> {
        Ok(Self { state, state_root })
    }

    pub fn from_state_and_root(state: BeaconState<E>, state_root: Hash256) -> Result<Self, Error> {
        Ok(Self { state, state_root })
    }

    pub fn as_state(&self) -> &BeaconState<E> {
        &self.state
    }

    pub fn into_state(self) -> BeaconState<E> {
        self.state
    }

    pub fn state_root(&self) -> Hash256 {
        self.state_root
    }
} 