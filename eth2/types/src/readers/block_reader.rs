use crate::{BeaconBlock, Hash256, Slot};
use std::fmt::Debug;

/// The `BeaconBlockReader` provides interfaces for reading a subset of fields of a `BeaconBlock`.
///
/// The purpose of this trait is to allow reading from either;
///  - a standard `BeaconBlock` struct, or
///  - a SSZ serialized byte array.
///
/// Note: presently, direct SSZ reading has not been implemented so this trait is being used for
/// "future proofing".
pub trait BeaconBlockReader: Debug + PartialEq {
    fn slot(&self) -> Slot;
    fn parent_root(&self) -> Hash256;
    fn state_root(&self) -> Hash256;
    fn into_beacon_block(self) -> Option<BeaconBlock>;
}

impl BeaconBlockReader for BeaconBlock {
    fn slot(&self) -> Slot {
        self.slot
    }

    fn parent_root(&self) -> Hash256 {
        self.parent_root
    }

    fn state_root(&self) -> Hash256 {
        self.state_root
    }

    fn into_beacon_block(self) -> Option<BeaconBlock> {
        Some(self)
    }
}
