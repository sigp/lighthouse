use super::state_transition::Error as TransitionError;
use super::{BeaconChain, ClientDB, DBError, SlotClock};
use slot_clock::{SystemTimeSlotClockError, TestingSlotClockError};
use ssz::{ssz_encode, Encodable};
use types::{
    readers::{BeaconBlockReader, BeaconStateReader},
    Hash256,
};

#[derive(Debug, PartialEq)]
pub enum Outcome {
    FutureSlot,
    Processed,
    NewCanonicalBlock,
    NewReorgBlock,
    NewForkBlock,
    StateTransitionFailed(TransitionError),
    StateRootMismatch,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    DBError(String),
    SlotClockError(SystemTimeSlotClockError),

    NotImplemented,
    PresentSlotIsNone,
    UnableToDecodeBlock,
    MissingParentState(Hash256),
    InvalidParentState(Hash256),
    MissingBeaconBlock(Hash256),
    InvalidBeaconBlock(Hash256),
    MissingParentBlock(Hash256),
    NoBlockProducer,
    StateSlotMismatch,
    BadBlockSignature,
    BadRandaoSignature,
    MaxProposerSlashingsExceeded,
    BadProposerSlashing,
    MaxAttestationsExceeded,
    BadAttestation,
    NoBlockRoot,
    MaxDepositsExceeded,
    MaxExitsExceeded,
    BadExit,
    BadCustodyReseeds,
    BadCustodyChallenges,
    BadCustodyResponses,
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
    Error: From<<U as SlotClock>::Error>,
{
    pub fn process_block<V>(&mut self, block: V) -> Result<Outcome, Error>
    where
        V: BeaconBlockReader + Encodable + Sized,
    {
        let block = block
            .into_beacon_block()
            .ok_or(Error::UnableToDecodeBlock)?;
        let block_root = block.canonical_root();

        let present_slot = self
            .slot_clock
            .present_slot()?
            .ok_or(Error::PresentSlotIsNone)?;

        // Block from future slots (i.e., greater than the present slot) should not be processed.
        if block.slot() > present_slot {
            return Ok(Outcome::FutureSlot);
        }

        let parent_block_root = block.parent_root();

        let parent_block = self
            .block_store
            .get_reader(&parent_block_root)?
            .ok_or(Error::MissingParentBlock(parent_block_root))?;

        let parent_state_root = parent_block.parent_root();
        let parent_state = self
            .state_store
            .get_reader(&parent_state_root)?
            .ok_or(Error::MissingParentState(parent_state_root))?
            .into_beacon_state()
            .ok_or(Error::InvalidParentState(parent_state_root))?;

        let state = match self.state_transition(parent_state, &block) {
            Ok(state) => state,
            Err(error) => return Ok(Outcome::StateTransitionFailed(error)),
        };

        let state_root = state.canonical_root();

        if block.state_root != state_root {
            return Ok(Outcome::StateRootMismatch);
        }

        // Store the block and state.
        self.block_store.put(&block_root, &ssz_encode(&block)[..])?;
        self.state_store.put(&state_root, &ssz_encode(&state)[..])?;

        // Update leaf blocks so the implementation can track the chain heads.
        if self.leaf_blocks.contains(&block.parent_root()) {
            self.leaf_blocks.remove(&block.parent_root());
        }
        if self.canonical_leaf_block == block.parent_root() {
            self.canonical_leaf_block = block_root;
        }
        self.leaf_blocks.insert(block_root);

        // The block was sucessfully processed.
        Ok(Outcome::Processed)
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

impl From<SystemTimeSlotClockError> for Error {
    fn from(e: SystemTimeSlotClockError) -> Error {
        Error::SlotClockError(e)
    }
}
