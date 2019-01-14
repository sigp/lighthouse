use super::{BeaconChain, ClientDB, DBError, SlotClock};
use slot_clock::TestingSlotClockError;
use ssz::{ssz_encode, Encodable};
use types::{readers::BeaconBlockReader, Hash256};

#[derive(Debug, PartialEq)]
pub enum Outcome {
    FutureSlot,
    Processed,

    NewCanonicalBlock,
    NewReorgBlock,
    NewForkBlock,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    DBError(String),
    NotImplemented,
    PresentSlotIsNone,
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
    Error: From<<U as SlotClock>::Error>,
{
    pub fn process_block<V>(&mut self, block: &V) -> Result<(Outcome, Hash256), Error>
    where
        V: BeaconBlockReader + Encodable + Sized,
    {
        let block_root = block.canonical_root();

        let present_slot = self
            .slot_clock
            .present_slot()?
            .ok_or(Error::PresentSlotIsNone)?;

        // Block from future slots (i.e., greater than the present slot) should not be processed.
        if block.slot() > present_slot {
            return Ok((Outcome::FutureSlot, block_root));
        }

        // TODO: block processing has been removed.
        // https://github.com/sigp/lighthouse/issues/98

        // Update leaf blocks.
        self.block_store.put(&block_root, &ssz_encode(block)[..])?;
        if self.leaf_blocks.contains(&block.parent_root()) {
            self.leaf_blocks.remove(&block.parent_root());
        }
        if self.canonical_leaf_block == block.parent_root() {
            self.canonical_leaf_block = block_root;
        }
        self.leaf_blocks.insert(block_root);

        Ok((Outcome::Processed, block_root))
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
