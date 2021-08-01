use crate::Slot;

/// A trait providing a `Slot` getter for messages that are related to a single slot. Useful in
/// making parts of attestation and sync committee processing generic.
pub trait SlotData {
    fn get_slot(&self) -> Slot;
}

impl SlotData for Slot {
    fn get_slot(&self) -> Slot {
        *self
    }
}
