use crate::{BeaconChain, CheckPoint, ClientDB, SlotClock};
use std::sync::RwLockReadGuard;
use types::{beacon_state::CommitteesError, BeaconBlock, BeaconState, Hash256};

#[derive(Debug, PartialEq)]
pub enum Error {
    PastSlot,
    CommitteesError(CommitteesError),
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
        let mut head = self
            .canonical_head
            .write()
            .expect("CRITICAL: CanonicalHead poisioned.");
        head.update(
            new_beacon_block,
            new_beacon_block_root,
            new_beacon_state,
            new_beacon_state_root,
        );
    }

    pub fn head(&self) -> RwLockReadGuard<CheckPoint> {
        self.canonical_head
            .read()
            .expect("CRITICAL: CanonicalHead poisioned.")
    }

    pub fn state(&self, slot: u64) -> Result<BeaconState, Error> {
        let mut state = self
            .canonical_head
            .read()
            .expect("CRITICAL: CanonicalHead poisioned.")
            .beacon_state
            .clone();
        let previous_block_root = self
            .canonical_head
            .read()
            .expect("CRITICAL: CanonicalHead poisioned.")
            .beacon_block_root
            .clone();

        match slot.checked_sub(state.slot) {
            None => Err(Error::PastSlot),
            Some(distance) => {
                for _ in 0..distance {
                    state.per_slot_processing(previous_block_root.clone(), &self.spec)?
                }
                Ok(state)
            }
        }
    }
}

impl From<CommitteesError> for Error {
    fn from(e: CommitteesError) -> Error {
        Error::CommitteesError(e)
    }
}
