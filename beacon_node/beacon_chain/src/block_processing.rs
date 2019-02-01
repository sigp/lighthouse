use super::{BeaconChain, ClientDB, DBError, SlotClock};
use log::debug;
use slot_clock::{SystemTimeSlotClockError, TestingSlotClockError};
use ssz::{ssz_encode, Encodable};
use types::{
    beacon_state::{BlockProcessingError, SlotProcessingError},
    readers::{BeaconBlockReader, BeaconStateReader},
    Hash256,
};

#[derive(Debug, PartialEq)]
pub enum ValidBlock {
    Processed,
}

#[derive(Debug, PartialEq)]
pub enum InvalidBlock {
    FutureSlot,
    StateRootMismatch,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    ValidBlock(ValidBlock),
    InvalidBlock(InvalidBlock),
}

#[derive(Debug, PartialEq)]
pub enum Error {
    DBError(String),
    UnableToDecodeBlock,
    SlotClockError(SystemTimeSlotClockError),
    MissingParentState(Hash256),
    InvalidParentState(Hash256),
    MissingBeaconBlock(Hash256),
    InvalidBeaconBlock(Hash256),
    MissingParentBlock(Hash256),
    SlotProcessingError(SlotProcessingError),
    PerBlockProcessingError(BlockProcessingError),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
    Error: From<<U as SlotClock>::Error>,
{
    pub fn process_block<V>(&self, block: V) -> Result<Outcome, Error>
    where
        V: BeaconBlockReader + Encodable + Sized,
    {
        debug!("Processing block with slot {}...", block.slot());

        let block = block
            .into_beacon_block()
            .ok_or(Error::UnableToDecodeBlock)?;
        let block_root = block.canonical_root();

        let present_slot = self.present_slot();

        if block.slot() > present_slot {
            return Ok(Outcome::InvalidBlock(InvalidBlock::FutureSlot));
        }

        let parent_block_root = block.parent_root();
        let parent_block = self
            .block_store
            .get_reader(&parent_block_root)?
            .ok_or(Error::MissingParentBlock(parent_block_root))?;

        let parent_state_root = parent_block.state_root();
        let parent_state = self
            .state_store
            .get_reader(&parent_state_root)?
            .ok_or(Error::MissingParentState(parent_state_root))?
            .into_beacon_state()
            .ok_or(Error::InvalidParentState(parent_state_root))?;

        let mut state = parent_state;

        for _ in state.slot..present_slot {
            state.per_slot_processing(parent_block_root.clone(), &self.spec)?;
        }

        state.per_block_processing(&block, &self.spec)?;

        let state_root = state.canonical_root();

        if block.state_root != state_root {
            return Ok(Outcome::InvalidBlock(InvalidBlock::StateRootMismatch));
        }

        // Store the block and state.
        self.block_store.put(&block_root, &ssz_encode(&block)[..])?;
        self.state_store.put(&state_root, &ssz_encode(&state)[..])?;

        self.block_graph
            .add_leaf(&parent_block_root, block_root.clone());

        // If the parent block was the parent_block, automatically update the canonical head.
        //
        // TODO: this is a first-in-best-dressed scenario that is not ideal -- find a solution.
        if self.head().beacon_block_root == parent_block_root {
            self.update_canonical_head(
                block.clone(),
                block_root.clone(),
                state.clone(),
                state_root.clone(),
            );
            *self.state.write() = state.clone();
        }

        // The block was sucessfully processed.
        Ok(Outcome::ValidBlock(ValidBlock::Processed))
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e.message)
    }
}

impl From<SlotProcessingError> for Error {
    fn from(e: SlotProcessingError) -> Error {
        Error::SlotProcessingError(e)
    }
}

impl From<BlockProcessingError> for Error {
    fn from(e: BlockProcessingError) -> Error {
        Error::PerBlockProcessingError(e)
    }
}

impl From<TestingSlotClockError> for Error {
    fn from(_: TestingSlotClockError) -> Error {
        unreachable!(); // Testing clock never throws an error.
    }
}

impl From<SystemTimeSlotClockError> for Error {
    fn from(e: SystemTimeSlotClockError) -> Error {
        Error::SlotClockError(e)
    }
}
