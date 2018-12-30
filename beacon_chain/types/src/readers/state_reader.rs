use crate::{BeaconState, Hash256};

pub trait BeaconStateReader {
    fn slot(&self) -> u64;
    fn canonical_root(&self) -> Hash256;
    fn to_beacon_state(self) -> BeaconState;
}

impl BeaconStateReader for BeaconState {
    fn slot(&self) -> u64 {
        self.slot
    }

    fn canonical_root(&self) -> Hash256 {
        self.canonical_root()
    }

    fn to_beacon_state(self) -> BeaconState {
        self
    }
}
