use crate::{BeaconChain, CheckPoint, ClientDB, SlotClock};
use parking_lot::RwLockReadGuard;
use types::{beacon_state::SlotProcessingError, BeaconBlock, BeaconState, Hash256};

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotProcessingError(SlotProcessingError),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    /// Update the canonical head to some new values.
    pub fn update_canonical_head(
        &self,
        new_beacon_block: BeaconBlock,
        new_beacon_block_root: Hash256,
        new_beacon_state: BeaconState,
        new_beacon_state_root: Hash256,
    ) {
        let mut head = self.canonical_head.write();
        head.update(
            new_beacon_block,
            new_beacon_block_root,
            new_beacon_state,
            new_beacon_state_root,
        );
    }

    /// Returns a read-lock guarded `CheckPoint` struct for reading the head (as chosen by the
    /// fork-choice rule).
    ///
    /// It is important to note that the `beacon_state` returned may not match the present slot. It
    /// is the state as it was when the head block was recieved, which could be some slots prior to
    /// now.
    pub fn head(&self) -> RwLockReadGuard<CheckPoint> {
        self.canonical_head.read()
    }
}

impl From<SlotProcessingError> for Error {
    fn from(e: SlotProcessingError) -> Error {
        Error::SlotProcessingError(e)
    }
}
