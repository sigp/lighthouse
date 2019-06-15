use crate::{BeaconChain, BeaconChainTypes};
use lmd_ghost::LmdGhost;
use state_processing::common::get_attesting_indices_unsorted;
use std::sync::Arc;
use store::{Error as StoreError, Store};
use types::{Attestation, BeaconBlock, BeaconState, BeaconStateError, EthSpec, Hash256};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    MissingBlock(Hash256),
    MissingState(Hash256),
    BackendError(String),
    BeaconStateError(BeaconStateError),
    StoreError(StoreError),
}

pub struct ForkChoice<T: BeaconChainTypes> {
    backend: T::LmdGhost,
}

impl<T: BeaconChainTypes> ForkChoice<T> {
    pub fn new(store: Arc<T::Store>) -> Self {
        Self {
            backend: T::LmdGhost::new(store),
        }
    }

    pub fn find_head(&self, chain: &BeaconChain<T>) -> Result<Hash256> {
        // From the specification:
        //
        // Let justified_head be the descendant of finalized_head with the highest epoch that has
        // been justified for at least 1 epoch ... If no such descendant exists,
        // set justified_head to finalized_head.
        let (start_state, start_block_root) = {
            let state = chain.current_state();

            let block_root = if state.current_epoch() + 1 > state.current_justified_epoch {
                state.current_justified_root
            } else {
                state.finalized_root
            };
            let block = chain
                .store
                .get::<BeaconBlock>(&block_root)?
                .ok_or_else(|| Error::MissingBlock(block_root))?;

            let state = chain
                .store
                .get::<BeaconState<T::EthSpec>>(&block.state_root)?
                .ok_or_else(|| Error::MissingState(block.state_root))?;

            (state, block_root)
        };

        // A function that returns the weight for some validator index.
        let weight = |validator_index: usize| -> Option<u64> {
            start_state
                .validator_registry
                .get(validator_index)
                .and_then(|v| Some(v.effective_balance))
        };

        self.backend
            .find_head(start_block_root, weight)
            .map_err(Into::into)
    }

    pub fn process_attestation(
        &self,
        state: &BeaconState<T::EthSpec>,
        attestation: &Attestation,
    ) -> Result<()> {
        // Note: `get_attesting_indices_unsorted` requires that the beacon state caches be built.
        let validator_indices = get_attesting_indices_unsorted(
            state,
            &attestation.data,
            &attestation.aggregation_bitfield,
        )?;

        let block_hash = attestation.data.target_root;

        // TODO: what happens when the target root is not the same slot as the block?
        let block_slot = attestation
            .data
            .target_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        for validator_index in validator_indices {
            self.backend
                .process_message(validator_index, block_hash, block_slot)?;
        }

        Ok(())
    }

    /// A helper function which runs `self.process_attestation` on all `Attestation` in the given `BeaconBlock`.
    ///
    /// Assumes the block (and therefore it's attestations) are valid. It is a logic error to
    /// provide an invalid block.
    pub fn process_block(
        &self,
        state: &BeaconState<T::EthSpec>,
        block: &BeaconBlock,
    ) -> Result<()> {
        // Note: we never count the block as a latest message, only attestations.
        //
        // I (Paul H) do not have an explicit reference to this, however I derive it from this
        // document:
        //
        // https://github.com/ethereum/eth2.0-specs/blob/v0.7.0/specs/core/0_fork-choice.md
        for attestation in &block.body.attestations {
            self.process_attestation(state, attestation)?;
        }

        Ok(())
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Error {
        Error::StoreError(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::BackendError(e)
    }
}
