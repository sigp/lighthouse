use super::{BeaconChain, ClientDB, DBError, SlotClock};
use slot_clock::TestingSlotClockError;
use types::{
    readers::{BeaconBlockReader, BeaconStateReader},
    BeaconBlock, BeaconState, Hash256,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    DBError(String),
    PresentSlotIsNone,
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
    Error: From<<U as SlotClock>::Error>,
{
    pub fn produce_block(&mut self) -> Result<(BeaconBlock, BeaconState), Error> {
        let present_slot = self
            .slot_clock
            .present_slot()?
            .ok_or(Error::PresentSlotIsNone)?;
        let parent_root = self.canonical_leaf_block;
        let parent_block = self
            .block_store
            .get_deserialized(&parent_root)?
            .ok_or(Error::DBError("Block not found.".to_string()))?;
        let parent_state = self
            .state_store
            .get_deserialized(&parent_block.state_root())?
            .ok_or(Error::DBError("State not found.".to_string()))?;

        let mut block = BeaconBlock {
            slot: present_slot,
            parent_root,
            state_root: Hash256::zero(), // Updated after the state is calculated.
            ..parent_block.to_beacon_block()
        };

        let state = BeaconState {
            slot: present_slot,
            ..parent_state.to_beacon_state()
        };
        let state_root = state.canonical_root();

        block.state_root = state_root;

        Ok((block, state))
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e.message)
    }
}

impl From<TestingSlotClockError> for Error {
    fn from(_: TestingSlotClockError) -> Error {
        unreachable!(); // Testing clock never throws an error.
    }
}
