use crate::{BeaconState, Hash256};

pub trait BeaconStateReader {
    fn slot(&self) -> u64;
    fn canonical_root(&self) -> Hash256;
    fn into_beacon_state(self) -> Option<BeaconState>;
}

impl BeaconStateReader for BeaconState {
    fn slot(&self) -> u64 {
        self.slot
    }

    fn canonical_root(&self) -> Hash256 {
        self.canonical_root()
    }

    fn into_beacon_state(self) -> Option<BeaconState> {
        Some(self)
    }
}
