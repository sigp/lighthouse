use super::{BeaconChain, ClientDB, DBError, SlotClock};
use bls::Signature;
use log::debug;
use types::{
    beacon_state::{BlockProcessingError, SlotProcessingError},
    BeaconBlock, BeaconBlockBody, BeaconState, Eth1Data, Hash256,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    DBError(String),
    SlotProcessingError(SlotProcessingError),
    PerBlockProcessingError(BlockProcessingError),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    /// Produce a new block at the present slot.
    ///
    /// The produced block will not be inheriently valid, it must be signed by a block producer.
    /// Block signing is out of the scope of this function and should be done by a separate program.
    pub fn produce_block(
        &self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState), Error> {
        debug!("Starting block production...");

        let mut state = self.state.read().clone();

        debug!("Finding attesatations for new block...");

        let attestations = self
            .attestation_aggregator
            .read()
            .get_attestations_for_state(&state, &self.spec);

        debug!(
            "Inserting {} attestation(s) into new block.",
            attestations.len()
        );

        let parent_root = state
            .get_block_root(state.slot.saturating_sub(1), &self.spec)
            // TODO: fix unwrap
            .unwrap()
            .clone();

        let mut block = BeaconBlock {
            slot: state.slot,
            parent_root,
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

        state.per_block_processing_without_verifying_block_signature(&block, &self.spec)?;

        let state_root = state.canonical_root();

        block.state_root = state_root;

        debug!("Block produced.");

        Ok((block, state))
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
