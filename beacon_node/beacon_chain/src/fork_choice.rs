use crate::{errors::BeaconChainError, metrics, BeaconChain, BeaconChainTypes};
use lmd_ghost::LmdGhost;
use parking_lot::RwLock;
use ssz_derive::{Decode, Encode};
use state_processing::{common::get_attesting_indices, per_slot_processing};
use std::sync::Arc;
use store::{Error as StoreError, Store};
use types::{
    Attestation, BeaconBlock, BeaconState, BeaconStateError, Checkpoint, EthSpec, Hash256, Slot,
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    MissingBlock(Hash256),
    MissingState(Hash256),
    BackendError(String),
    BeaconStateError(BeaconStateError),
    StoreError(StoreError),
    BeaconChainError(Box<BeaconChainError>),
}

pub struct ForkChoice<T: BeaconChainTypes> {
    store: Arc<T::Store>,
    backend: T::LmdGhost,
    /// Used for resolving the `0x00..00` alias back to genesis.
    ///
    /// Does not necessarily need to be the _actual_ genesis, it suffices to be the finalized root
    /// whenever the struct was instantiated.
    genesis_block_root: Hash256,
    /// The fork choice rule's current view of the justified checkpoint.
    justified_checkpoint: RwLock<Checkpoint>,
    /// The best justified checkpoint we've seen, which may be ahead of `justified_checkpoint`.
    best_justified_checkpoint: RwLock<Checkpoint>,
}

impl<T: BeaconChainTypes> PartialEq for ForkChoice<T> {
    /// This implementation ignores the `store`.
    fn eq(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.genesis_block_root == other.genesis_block_root
            && *self.justified_checkpoint.read() == *other.justified_checkpoint.read()
            && *self.best_justified_checkpoint.read() == *other.best_justified_checkpoint.read()
    }
}

impl<T: BeaconChainTypes> ForkChoice<T> {
    /// Instantiate a new fork chooser.
    ///
    /// "Genesis" does not necessarily need to be the absolute genesis, it can be some finalized
    /// block.
    pub fn new(
        store: Arc<T::Store>,
        backend: T::LmdGhost,
        genesis_block_root: Hash256,
        genesis_slot: Slot,
    ) -> Self {
        let justified_checkpoint = Checkpoint {
            epoch: genesis_slot.epoch(T::EthSpec::slots_per_epoch()),
            root: genesis_block_root,
        };
        Self {
            store: store.clone(),
            backend,
            genesis_block_root,
            justified_checkpoint: RwLock::new(justified_checkpoint.clone()),
            best_justified_checkpoint: RwLock::new(justified_checkpoint),
        }
    }

    /// Determine whether the fork choice's view of the justified checkpoint should be updated.
    ///
    /// To prevent the bouncing attack, an update is allowed only in these conditions:
    ///
    /// * We're in the first SAFE_SLOTS_TO_UPDATE_JUSTIFIED slots of the epoch, or
    /// * The new justified checkpoint is a descendant of the current justified checkpoint
    fn should_update_justified_checkpoint(
        &self,
        chain: &BeaconChain<T>,
        new_justified_checkpoint: &Checkpoint,
    ) -> Result<bool> {
        if Self::compute_slots_since_epoch_start(chain.slot()?)
            < chain.spec.safe_slots_to_update_justified
        {
            return Ok(true);
        }

        let justified_checkpoint = self.justified_checkpoint.read().clone();

        let current_justified_block = chain
            .get_block(&justified_checkpoint.root)?
            .ok_or_else(|| Error::MissingBlock(justified_checkpoint.root))?;

        let new_justified_block = chain
            .get_block(&new_justified_checkpoint.root)?
            .ok_or_else(|| Error::MissingBlock(new_justified_checkpoint.root))?;

        let slots_per_epoch = T::EthSpec::slots_per_epoch();

        Ok(
            new_justified_block.slot > justified_checkpoint.epoch.start_slot(slots_per_epoch)
                && chain.get_ancestor_block_root(
                    new_justified_checkpoint.root,
                    current_justified_block.slot,
                )? == Some(justified_checkpoint.root),
        )
    }

    /// Calculate how far `slot` lies from the start of its epoch.
    fn compute_slots_since_epoch_start(slot: Slot) -> u64 {
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        (slot - slot.epoch(slots_per_epoch).start_slot(slots_per_epoch)).as_u64()
    }

    /// Run the fork choice rule to determine the head.
    pub fn find_head(&self, chain: &BeaconChain<T>) -> Result<Hash256> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_FIND_HEAD_TIMES);

        let (start_state, start_block_root, start_block_slot) = {
            // Check if we should update our view of the justified checkpoint.
            // Doing this check here should be quasi-equivalent to the update in the `on_tick`
            // function of the spec, so long as `find_head` is called at least once during the first
            // SAFE_SLOTS_TO_UPDATE_JUSTIFIED slots.
            let best_justified_checkpoint = self.best_justified_checkpoint.read();
            if self.should_update_justified_checkpoint(chain, &best_justified_checkpoint)? {
                *self.justified_checkpoint.write() = best_justified_checkpoint.clone();
            }

            let current_justified_checkpoint = self.justified_checkpoint.read().clone();

            let (block_root, block_justified_slot) = (
                current_justified_checkpoint.root,
                current_justified_checkpoint
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch()),
            );

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

            let mut state: BeaconState<T::EthSpec> = chain
                .store
                .get_state(&block.state_root, Some(block.slot))?
                .ok_or_else(|| Error::MissingState(block.state_root))?;

            // Fast-forward the state to the start slot of the epoch where it was justified.
            for _ in block.slot.as_u64()..block_justified_slot.as_u64() {
                per_slot_processing(&mut state, None, &chain.spec)
                    .map_err(BeaconChainError::SlotProcessingError)?
            }

            (state, block_root, block_justified_slot)
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
    /// Assumes the block (and therefore its attestations) are valid. It is a logic error to
    /// provide an invalid block.
    pub fn process_block(
        &self,
        chain: &BeaconChain<T>,
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

        // Check if we should update our view of the justified checkpoint
        if state.current_justified_checkpoint.epoch > self.justified_checkpoint.read().epoch {
            *self.best_justified_checkpoint.write() = state.current_justified_checkpoint.clone();
            if self
                .should_update_justified_checkpoint(chain, &state.current_justified_checkpoint)?
            {
                *self.justified_checkpoint.write() = state.current_justified_checkpoint.clone();
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

    /// Returns a `SszForkChoice` which contains the current state of `Self`.
    pub fn as_ssz_container(&self) -> SszForkChoice {
        SszForkChoice {
            genesis_block_root: self.genesis_block_root.clone(),
            justified_checkpoint: self.justified_checkpoint.read().clone(),
            best_justified_checkpoint: self.best_justified_checkpoint.read().clone(),
            backend_bytes: self.backend.as_bytes(),
        }
    }

    /// Instantiates `Self` from a prior `SszForkChoice`.
    ///
    /// The created `Self` will have the same state as the `Self` that created the `SszForkChoice`.
    pub fn from_ssz_container(ssz_container: SszForkChoice, store: Arc<T::Store>) -> Result<Self> {
        let backend = LmdGhost::from_bytes(&ssz_container.backend_bytes, store.clone())?;

        Ok(Self {
            store,
            backend,
            genesis_block_root: ssz_container.genesis_block_root,
            justified_checkpoint: RwLock::new(ssz_container.justified_checkpoint),
            best_justified_checkpoint: RwLock::new(ssz_container.best_justified_checkpoint),
        })
    }
}

/// Helper struct that is used to encode/decode the state of the `ForkChoice` as SSZ bytes.
///
/// This is used when persisting the state of the `BeaconChain` to disk.
#[derive(Encode, Decode, Clone)]
pub struct SszForkChoice {
    genesis_block_root: Hash256,
    justified_checkpoint: Checkpoint,
    best_justified_checkpoint: Checkpoint,
    backend_bytes: Vec<u8>,
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Error {
        Error::BeaconChainError(Box::new(e))
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
