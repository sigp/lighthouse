use super::state_transition::Error as TransitionError;
use super::{BeaconChain, ClientDB, DBError, SlotClock};
use bls::Signature;
use slot_clock::TestingSlotClockError;
use types::{
    readers::{BeaconBlockReader, BeaconStateReader},
    BeaconBlock, BeaconBlockBody, BeaconState, Hash256,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    DBError(String),
    StateTransitionError(TransitionError),
    PresentSlotIsNone,
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
    Error: From<<U as SlotClock>::Error>,
{
    pub fn produce_block(
        &mut self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState), Error> {
        let present_slot = self
            .slot_clock
            .present_slot()?
            .ok_or(Error::PresentSlotIsNone)?;

        let parent_root = self.canonical_leaf_block;
        let parent_block_reader = self
            .block_store
            .get_reader(&parent_root)?
            .ok_or_else(|| Error::DBError("Block not found.".to_string()))?;
        let parent_state = self
            .state_store
            .get_reader(&parent_block_reader.state_root())?
            .ok_or_else(|| Error::DBError("State not found.".to_string()))?
            .into_beacon_state()
            .ok_or_else(|| Error::DBError("State invalid.".to_string()))?;

        let mut block = BeaconBlock {
            slot: present_slot,
            parent_root,
            state_root: Hash256::zero(), // Updated after the state is calculated.
            randao_reveal: randao_reveal,
            candidate_pow_receipt_root: Hash256::zero(), // TODO: replace w/ eth1 data.
            signature: self.spec.empty_signature.clone(), // To be completed by a validator.
            body: BeaconBlockBody {
                proposer_slashings: vec![],
                casper_slashings: vec![],
                attestations: vec![],
                custody_reseeds: vec![],
                custody_challenges: vec![],
                custody_responses: vec![],
                deposits: vec![],
                exits: vec![],
            },
        };

        let state = self.state_transition(parent_state, &block)?;

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

impl From<TransitionError> for Error {
    fn from(e: TransitionError) -> Error {
        Error::StateTransitionError(e)
    }
}

impl From<TestingSlotClockError> for Error {
    fn from(_: TestingSlotClockError) -> Error {
        unreachable!(); // Testing clock never throws an error.
    }
}
