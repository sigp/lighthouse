use super::state_transition::Error as TransitionError;
use super::{BeaconChain, ClientDB, DBError, SlotClock};
use bls::Signature;
use slot_clock::TestingSlotClockError;
use types::{
    readers::{BeaconBlockReader, BeaconStateReader},
    BeaconBlock, BeaconBlockBody, BeaconState, Eth1Data, Hash256,
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
{
    pub fn produce_block(
        &self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState), Error>
    where
        Error: From<<U>::Error>,
    {
        // TODO: allow producing a block from a previous (or future?) slot.
        let present_slot = self
            .slot_clock
            .present_slot()
            .map_err(|e| e.into())?
            .ok_or(Error::PresentSlotIsNone)?;

        let parent_root = self.head().beacon_block_root;
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

        let attestations = self
            .attestation_aggregator
            .read()
            .unwrap()
            // TODO: advance the parent_state slot.
            .get_attestations_for_state(&parent_state, &self.spec);

        let mut block = BeaconBlock {
            slot: present_slot,
            parent_root: parent_root.clone(),
            state_root: Hash256::zero(), // Updated after the state is calculated.
            randao_reveal: randao_reveal,
            eth1_data: Eth1Data {
                // TODO: replace with real data
                deposit_root: Hash256::zero(),
                block_hash: Hash256::zero(),
            },
            signature: self.spec.empty_signature.clone(), // To be completed by a validator.
            body: BeaconBlockBody {
                proposer_slashings: vec![],
                casper_slashings: vec![],
                attestations: attestations,
                custody_reseeds: vec![],
                custody_challenges: vec![],
                custody_responses: vec![],
                deposits: vec![],
                exits: vec![],
            },
        };

        let state =
            self.state_transition_without_verifying_block_signature(parent_state, &block)?;
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
