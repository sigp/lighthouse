use crate::{BeaconState, Hash256, Slot};
use std::fmt::Debug;

/// The `BeaconStateReader` provides interfaces for reading a subset of fields of a `BeaconState`.
///
/// The purpose of this trait is to allow reading from either;
///  - a standard `BeaconState` struct, or
///  - a SSZ serialized byte array.
///
/// Note: presently, direct SSZ reading has not been implemented so this trait is being used for
/// "future proofing".
pub trait BeaconStateReader: Debug + PartialEq {
    fn slot(&self) -> Slot;
    fn canonical_root(&self) -> Hash256;
    fn into_beacon_state(self) -> Option<BeaconState>;
}

impl BeaconStateReader for BeaconState {
    fn slot(&self) -> Slot {
        self.slot
    }

    fn canonical_root(&self) -> Hash256 {
        self.canonical_root()
    }

    fn into_beacon_state(self) -> Option<BeaconState> {
        Some(self)
    }
}
