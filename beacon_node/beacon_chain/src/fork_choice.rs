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
    /// Used for resolving the `0x00..00` alias back to genesis.
    ///
    /// Does not necessarily need to be the _actual_ genesis, it suffices to be the finalized root
    /// whenever the struct was instantiated.
    genesis_block_root: Hash256,
}

impl<T: BeaconChainTypes> ForkChoice<T> {
    pub fn new(store: Arc<T::Store>, genesis_block_root: Hash256) -> Self {
        Self {
            backend: T::LmdGhost::new(store, genesis_block_root),
            genesis_block_root,
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

            // Resolve the `0x00.. 00` alias back to genesis
            let block_root = if block_root == Hash256::zero() {
                self.genesis_block_root
            } else {
                block_root
            };

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

    /// Process all attestations in the given `block`.
    ///
    /// Assumes the block (and therefore it's attestations) are valid. It is a logic error to
    /// provide an invalid block.
    pub fn process_block(
        &self,
        state: &BeaconState<T::EthSpec>,
        block: &BeaconBlock,
        block_root: Hash256,
    ) -> Result<()> {
        // Note: we never count the block as a latest message, only attestations.
        //
        // I (Paul H) do not have an explicit reference to this, but I derive it from this
        // document:
        //
        // https://github.com/ethereum/eth2.0-specs/blob/v0.7.0/specs/core/0_fork-choice.md
        for attestation in &block.body.attestations {
            self.process_attestation_from_block(state, attestation)?;
        }

        self.backend.process_block(block_root, block.slot)?;

        Ok(())
    }

    fn process_attestation_from_block(
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

        // Ignore any attestations to the zero hash.
        //
        // This is an edge case that results from the spec aliasing the zero hash to the genesis
        // block. Attesters may attest to the zero hash if they have never seen a block.
        //
        // We have two options here:
        //
        //  1. Apply all zero-hash attestations to the zero hash.
        //  2. Ignore all attestations to the zero hash.
        //
        // (1) becomes weird once we hit finality and fork choice drops the genesis block. (2) is
        // fine becuase votes to the genesis block are not usefully, all validators already
        // implicitly attest to genesis just by being present in the chain.
        if block_hash != Hash256::zero() {
            let block_slot = attestation
                .data
                .target_epoch
                .start_slot(T::EthSpec::slots_per_epoch());

            for validator_index in validator_indices {
                self.backend
                    .process_attestation(validator_index, block_hash, block_slot)?;
            }
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
