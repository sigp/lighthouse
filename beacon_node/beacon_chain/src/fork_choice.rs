use crate::{metrics, BeaconChain, BeaconChainTypes};
use lmd_ghost::LmdGhost;
use state_processing::common::get_attesting_indices;
use std::sync::Arc;
use store::{Error as StoreError, Store};
use types::{
    Attestation, BeaconBlock, BeaconState, BeaconStateError, Epoch, EthSpec, Hash256, Slot,
};

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
    store: Arc<T::Store>,
    backend: T::LmdGhost,
    /// Used for resolving the `0x00..00` alias back to genesis.
    ///
    /// Does not necessarily need to be the _actual_ genesis, it suffices to be the finalized root
    /// whenever the struct was instantiated.
    genesis_block_root: Hash256,
}

impl<T: BeaconChainTypes> ForkChoice<T> {
    /// Instantiate a new fork chooser.
    ///
    /// "Genesis" does not necessarily need to be the absolute genesis, it can be some finalized
    /// block.
    pub fn new(
        store: Arc<T::Store>,
        genesis_block: &BeaconBlock<T::EthSpec>,
        genesis_block_root: Hash256,
    ) -> Self {
        Self {
            store: store.clone(),
            backend: T::LmdGhost::new(store, genesis_block, genesis_block_root),
            genesis_block_root,
        }
    }

    pub fn find_head(&self, chain: &BeaconChain<T>) -> Result<Hash256> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_FIND_HEAD_TIMES);

        let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

        // From the specification:
        //
        // Let justified_head be the descendant of finalized_head with the highest epoch that has
        // been justified for at least 1 epoch ... If no such descendant exists,
        // set justified_head to finalized_head.
        let (start_state, start_block_root, start_block_slot) = {
            let state = &chain.head().beacon_state;

            let (block_root, block_slot) =
                if state.current_epoch() + 1 > state.current_justified_checkpoint.epoch {
                    (
                        state.current_justified_checkpoint.root,
                        start_slot(state.current_justified_checkpoint.epoch),
                    )
                } else {
                    (
                        state.finalized_checkpoint.root,
                        start_slot(state.finalized_checkpoint.epoch),
                    )
                };

            let block = chain
                .store
                .get::<BeaconBlock<T::EthSpec>>(&block_root)?
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

            (state, block_root, block_slot)
        };

        // A function that returns the weight for some validator index.
        let weight = |validator_index: usize| -> Option<u64> {
            start_state
                .validators
                .get(validator_index)
                .map(|v| v.effective_balance)
        };

        let result = self
            .backend
            .find_head(start_block_slot, start_block_root, weight)
            .map_err(Into::into);

        metrics::stop_timer(timer);

        result
    }

    /// Process all attestations in the given `block`.
    ///
    /// Assumes the block (and therefore it's attestations) are valid. It is a logic error to
    /// provide an invalid block.
    pub fn process_block(
        &self,
        state: &BeaconState<T::EthSpec>,
        block: &BeaconBlock<T::EthSpec>,
        block_root: Hash256,
    ) -> Result<()> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_BLOCK_TIMES);
        // Note: we never count the block as a latest message, only attestations.
        //
        // I (Paul H) do not have an explicit reference to this, but I derive it from this
        // document:
        //
        // https://github.com/ethereum/eth2.0-specs/blob/v0.7.0/specs/core/0_fork-choice.md
        for attestation in &block.body.attestations {
            // If the `data.beacon_block_root` block is not known to us, simply ignore the latest
            // vote.
            if let Some(block) = self
                .store
                .get::<BeaconBlock<T::EthSpec>>(&attestation.data.beacon_block_root)?
            {
                self.process_attestation(state, attestation, &block)?;
            }
        }

        // This does not apply a vote to the block, it just makes fork choice aware of the block so
        // it can still be identified as the head even if it doesn't have any votes.
        //
        // A case where a block without any votes can be the head is where it is the only child of
        // a block that has the majority of votes applied to it.
        self.backend.process_block(block, block_root)?;

        metrics::stop_timer(timer);

        Ok(())
    }

    /// Process an attestation which references `block` in `attestation.data.beacon_block_root`.
    ///
    /// Assumes the attestation is valid.
    pub fn process_attestation(
        &self,
        state: &BeaconState<T::EthSpec>,
        attestation: &Attestation<T::EthSpec>,
        block: &BeaconBlock<T::EthSpec>,
    ) -> Result<()> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_ATTESTATION_TIMES);

        let block_hash = attestation.data.beacon_block_root;

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
        // fine because votes to the genesis block are not useful; all validators implicitly attest
        // to genesis just by being present in the chain.
        //
        // Additionally, don't add any block hash to fork choice unless we have imported the block.
        if block_hash != Hash256::zero() {
            let validator_indices =
                get_attesting_indices(state, &attestation.data, &attestation.aggregation_bits)?;

            for validator_index in validator_indices {
                self.backend
                    .process_attestation(validator_index, block_hash, block.slot)?;
            }
        }

        metrics::stop_timer(timer);

        Ok(())
    }

    /// Returns the latest message for a given validator, if any.
    ///
    /// Returns `(block_root, block_slot)`.
    pub fn latest_message(&self, validator_index: usize) -> Option<(Hash256, Slot)> {
        self.backend.latest_message(validator_index)
    }

    /// Runs an integrity verification function on the underlying fork choice algorithm.
    ///
    /// Returns `Ok(())` if the underlying fork choice has maintained it's integrity,
    /// `Err(description)` otherwise.
    pub fn verify_integrity(&self) -> core::result::Result<(), String> {
        self.backend.verify_integrity()
    }

    /// Inform the fork choice that the given block (and corresponding root) have been finalized so
    /// it may prune it's storage.
    ///
    /// `finalized_block_root` must be the root of `finalized_block`.
    pub fn process_finalization(
        &self,
        finalized_block: &BeaconBlock<T::EthSpec>,
        finalized_block_root: Hash256,
    ) -> Result<()> {
        self.backend
            .update_finalized_root(finalized_block, finalized_block_root)
            .map_err(Into::into)
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
