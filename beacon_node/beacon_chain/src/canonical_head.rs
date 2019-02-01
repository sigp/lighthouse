use crate::{BeaconChain, CheckPoint, ClientDB, SlotClock};
use parking_lot::RwLockReadGuard;
use types::{beacon_state::SlotProcessingError, BeaconBlock, BeaconState, Hash256};

#[derive(Debug, PartialEq)]
pub enum Error {
    PastSlot,
    SlotProcessingError(SlotProcessingError),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
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

    pub fn head(&self) -> RwLockReadGuard<CheckPoint> {
        self.canonical_head.read()
    }

    pub fn advance_state(&self, slot: u64) -> Result<(), SlotProcessingError> {
        let state_slot = self.state.read().slot;
        let head_block_root = self.head().beacon_block_root;
        for _ in state_slot..slot {
            self.state
                .write()
                .per_slot_processing(head_block_root.clone(), &self.spec)?;
        }
        Ok(())
    }
}

impl From<SlotProcessingError> for Error {
    fn from(e: SlotProcessingError) -> Error {
        Error::SlotProcessingError(e)
    }
}
