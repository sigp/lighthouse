use crate::attestation_aggregator::{AttestationAggregator, Outcome as AggregationOutcome};
use crate::cached_beacon_state::CachedBeaconState;
use crate::checkpoint::CheckPoint;
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    ClientDB, DBError,
};
use fork_choice::{ForkChoice, ForkChoiceError};
use log::{debug, trace};
use parking_lot::{RwLock, RwLockReadGuard};
use slot_clock::SlotClock;
use ssz::ssz_encode;
use state_processing::{
    BlockProcessable, BlockProcessingError, SlotProcessable, SlotProcessingError,
};
use std::sync::Arc;
use types::{
    beacon_state::BeaconStateError,
    readers::{BeaconBlockReader, BeaconStateReader},
    AttestationData, BeaconBlock, BeaconBlockBody, BeaconState, ChainSpec, Crosslink, Deposit,
    Epoch, Eth1Data, FreeAttestation, Hash256, PublicKey, Signature, Slot,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    InsufficientValidators,
    BadRecentBlockRoots,
    BeaconStateError(BeaconStateError),
    DBInconsistent(String),
    DBError(String),
    ForkChoiceError(ForkChoiceError),
    MissingBeaconBlock(Hash256),
    MissingBeaconState(Hash256),
}

#[derive(Debug, PartialEq)]
pub enum ValidBlock {
    /// The block was successfully processed.
    Processed,
}

#[derive(Debug, PartialEq)]
pub enum InvalidBlock {
    /// The block slot is greater than the present slot.
    FutureSlot,
    /// The block state_root does not match the generated state.
    StateRootMismatch,
    /// The blocks parent_root is unknown.
    ParentUnknown,
    /// There was an error whilst advancing the parent state to the present slot. This condition
    /// should not occur, it likely represents an internal error.
    SlotProcessingError(SlotProcessingError),
    /// The block could not be applied to the state, it is invalid.
    PerBlockProcessingError(BlockProcessingError),
}

#[derive(Debug, PartialEq)]
pub enum BlockProcessingOutcome {
    /// The block was successfully validated.
    ValidBlock(ValidBlock),
    /// The block was not successfully validated.
    InvalidBlock(InvalidBlock),
}

pub struct BeaconChain<T: ClientDB + Sized, U: SlotClock, F: ForkChoice> {
    pub block_store: Arc<BeaconBlockStore<T>>,
    pub state_store: Arc<BeaconStateStore<T>>,
    pub slot_clock: U,
    pub attestation_aggregator: RwLock<AttestationAggregator>,
    canonical_head: RwLock<CheckPoint>,
    finalized_head: RwLock<CheckPoint>,
    pub state: RwLock<BeaconState>,
    pub cached_state: RwLock<CachedBeaconState>,
    pub spec: ChainSpec,
    pub fork_choice: RwLock<F>,
}

impl<T, U, F> BeaconChain<T, U, F>
where
    T: ClientDB,
    U: SlotClock,
    F: ForkChoice,
{
    /// Instantiate a new Beacon Chain, from genesis.
    pub fn genesis(
        state_store: Arc<BeaconStateStore<T>>,
        block_store: Arc<BeaconBlockStore<T>>,
        slot_clock: U,
        genesis_time: u64,
        latest_eth1_data: Eth1Data,
        initial_validator_deposits: Vec<Deposit>,
        spec: ChainSpec,
        fork_choice: F,
    ) -> Result<Self, Error> {
        if initial_validator_deposits.is_empty() {
            return Err(Error::InsufficientValidators);
        }

        let genesis_state = BeaconState::genesis(
            genesis_time,
            initial_validator_deposits,
            latest_eth1_data,
            &spec,
        )?;
        let state_root = genesis_state.canonical_root();
        state_store.put(&state_root, &ssz_encode(&genesis_state)[..])?;

        let genesis_block = BeaconBlock::genesis(state_root, &spec);
        let block_root = genesis_block.canonical_root();
        block_store.put(&block_root, &ssz_encode(&genesis_block)[..])?;

        let cached_state = RwLock::new(CachedBeaconState::from_beacon_state(
            genesis_state.clone(),
            spec.clone(),
        )?);

        let finalized_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            block_root,
            genesis_state.clone(),
            state_root,
        ));
        let canonical_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            block_root,
            genesis_state.clone(),
            state_root,
        ));
        let attestation_aggregator = RwLock::new(AttestationAggregator::new());

        Ok(Self {
            block_store,
            state_store,
            slot_clock,
            attestation_aggregator,
            state: RwLock::new(genesis_state.clone()),
            cached_state,
            finalized_head,
            canonical_head,
            spec,
            fork_choice: RwLock::new(fork_choice),
        })
    }

    /// Update the canonical head to some new values.
    pub fn update_canonical_head(
        &self,
        new_beacon_block: BeaconBlock,
        new_beacon_block_root: Hash256,
        new_beacon_state: BeaconState,
        new_beacon_state_root: Hash256,
    ) {
        let mut head = self.canonical_head.write();
        head.update(
            new_beacon_block,
            new_beacon_block_root,
            new_beacon_state,
            new_beacon_state_root,
        );
    }

    /// Returns a read-lock guarded `CheckPoint` struct for reading the head (as chosen by the
    /// fork-choice rule).
    ///
    /// It is important to note that the `beacon_state` returned may not match the present slot. It
    /// is the state as it was when the head block was recieved, which could be some slots prior to
    /// now.
    pub fn head(&self) -> RwLockReadGuard<CheckPoint> {
        self.canonical_head.read()
    }

    /// Update the justified head to some new values.
    pub fn update_finalized_head(
        &self,
        new_beacon_block: BeaconBlock,
        new_beacon_block_root: Hash256,
        new_beacon_state: BeaconState,
        new_beacon_state_root: Hash256,
    ) {
        let mut finalized_head = self.finalized_head.write();
        finalized_head.update(
            new_beacon_block,
            new_beacon_block_root,
            new_beacon_state,
            new_beacon_state_root,
        );
    }

    /// Returns a read-lock guarded `CheckPoint` struct for reading the justified head (as chosen,
    /// indirectly,  by the fork-choice rule).
    pub fn finalized_head(&self) -> RwLockReadGuard<CheckPoint> {
        self.finalized_head.read()
    }

    /// Advance the `self.state` `BeaconState` to the supplied slot.
    ///
    /// This will perform per_slot and per_epoch processing as required.
    ///
    /// The `previous_block_root` will be set to the root of the current head block (as determined
    /// by the fork-choice rule).
    ///
    /// It is important to note that this is _not_ the state corresponding to the canonical head
    /// block, instead it is that state which may or may not have had additional per slot/epoch
    /// processing applied to it.
    pub fn advance_state(&self, slot: Slot) -> Result<(), SlotProcessingError> {
        let state_slot = self.state.read().slot;
        let head_block_root = self.head().beacon_block_root;
        for _ in state_slot.as_u64()..slot.as_u64() {
            self.state
                .write()
                .per_slot_processing(head_block_root, &self.spec)?;
        }
        Ok(())
    }

    /// Returns the validator index (if any) for the given public key.
    ///
    /// Information is retrieved from the present `beacon_state.validator_registry`.
    pub fn validator_index(&self, pubkey: &PublicKey) -> Option<usize> {
        for (i, validator) in self
            .head()
            .beacon_state
            .validator_registry
            .iter()
            .enumerate()
        {
            if validator.pubkey == *pubkey {
                return Some(i);
            }
        }
        None
    }

    /// Reads the slot clock, returns `None` if the slot is unavailable.
    ///
    /// The slot might be unavailable due to an error with the system clock, or if the present time
    /// is before genesis (i.e., a negative slot).
    ///
    /// This is distinct to `present_slot`, which simply reads the latest state. If a
    /// call to `read_slot_clock` results in a higher slot than a call to `present_slot`,
    /// `self.state` should undergo per slot processing.
    pub fn read_slot_clock(&self) -> Option<Slot> {
        match self.slot_clock.present_slot() {
            Ok(Some(some_slot)) => Some(some_slot),
            Ok(None) => None,
            _ => None,
        }
    }

    /// Returns slot of the present state.
    ///
    /// This is distinct to `read_slot_clock`, which reads from the actual system clock. If
    /// `self.state` has not been transitioned it is possible for the system clock to be on a
    /// different slot to what is returned from this call.
    pub fn present_slot(&self) -> Slot {
        self.state.read().slot
    }

    /// Returns the block proposer for a given slot.
    ///
    /// Information is read from the present `beacon_state` shuffling, so only information from the
    /// present and prior epoch is available.
    pub fn block_proposer(&self, slot: Slot) -> Result<usize, BeaconStateError> {
        trace!("BeaconChain::block_proposer: slot: {}", slot);
        let index = self
            .state
            .read()
            .get_beacon_proposer_index(slot, &self.spec)?;

        Ok(index)
    }

    /// Returns the justified slot for the present state.
    pub fn justified_epoch(&self) -> Epoch {
        self.state.read().justified_epoch
    }

    /// Returns the attestation slot and shard for a given validator index.
    ///
    /// Information is read from the current state, so only information from the present and prior
    /// epoch is available.
    pub fn validator_attestion_slot_and_shard(
        &self,
        validator_index: usize,
    ) -> Result<Option<(Slot, u64)>, BeaconStateError> {
        trace!(
            "BeaconChain::validator_attestion_slot_and_shard: validator_index: {}",
            validator_index
        );
        if let Some((slot, shard, _committee)) = self
            .cached_state
            .read()
            .attestation_slot_and_shard_for_validator(validator_index, &self.spec)?
        {
            Ok(Some((slot, shard)))
        } else {
            Ok(None)
        }
    }

    /// Produce an `AttestationData` that is valid for the present `slot` and given `shard`.
    pub fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, Error> {
        trace!("BeaconChain::produce_attestation_data: shard: {}", shard);
        let justified_epoch = self.justified_epoch();
        let justified_block_root = *self
            .state
            .read()
            .get_block_root(
                justified_epoch.start_slot(self.spec.epoch_length),
                &self.spec,
            )
            .ok_or_else(|| Error::BadRecentBlockRoots)?;

        let epoch_boundary_root = *self
            .state
            .read()
            .get_block_root(
                self.state.read().current_epoch_start_slot(&self.spec),
                &self.spec,
            )
            .ok_or_else(|| Error::BadRecentBlockRoots)?;

        Ok(AttestationData {
            slot: self.state.read().slot,
            shard,
            beacon_block_root: self.head().beacon_block_root,
            epoch_boundary_root,
            shard_block_root: Hash256::zero(),
            latest_crosslink: Crosslink {
                epoch: self.state.read().slot.epoch(self.spec.epoch_length),
                shard_block_root: Hash256::zero(),
            },
            justified_epoch,
            justified_block_root,
        })
    }

    /// Validate a `FreeAttestation` and either:
    ///
    /// - Create a new `Attestation`.
    /// - Aggregate it to an existing `Attestation`.
    pub fn process_free_attestation(
        &self,
        free_attestation: FreeAttestation,
    ) -> Result<AggregationOutcome, Error> {
        let aggregation_outcome = self
            .attestation_aggregator
            .write()
            .process_free_attestation(&self.cached_state.read(), &free_attestation, &self.spec)?;

        // return if the attestation is invalid
        if !aggregation_outcome.valid {
            return Ok(aggregation_outcome);
        }

        // valid attestation, proceed with fork-choice logic
        self.fork_choice.write().add_attestation(
            free_attestation.validator_index,
            &free_attestation.data.beacon_block_root,
            &self.spec,
        )?;
        Ok(aggregation_outcome)
    }

    /// Dumps the entire canonical chain, from the head to genesis to a vector for analysis.
    ///
    /// This could be a very expensive operation and should only be done in testing/analysis
    /// activities.
    pub fn chain_dump(&self) -> Result<Vec<CheckPoint>, Error> {
        let mut dump = vec![];

        let mut last_slot = CheckPoint {
            beacon_block: self.head().beacon_block.clone(),
            beacon_block_root: self.head().beacon_block_root,
            beacon_state: self.head().beacon_state.clone(),
            beacon_state_root: self.head().beacon_state_root,
        };

        dump.push(last_slot.clone());

        loop {
            let beacon_block_root = last_slot.beacon_block.parent_root;

            if beacon_block_root == self.spec.zero_hash {
                break; // Genesis has been reached.
            }

            let beacon_block = self
                .block_store
                .get_deserialized(&beacon_block_root)?
                .ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing block {}", beacon_block_root))
                })?;
            let beacon_state_root = beacon_block.state_root;
            let beacon_state = self
                .state_store
                .get_deserialized(&beacon_state_root)?
                .ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing state {}", beacon_state_root))
                })?;

            let slot = CheckPoint {
                beacon_block,
                beacon_block_root,
                beacon_state,
                beacon_state_root,
            };

            dump.push(slot.clone());
            last_slot = slot;
        }

        Ok(dump)
    }

    /// Accept some block and attempt to add it to block DAG.
    ///
    /// Will accept blocks from prior slots, however it will reject any block from a future slot.
    pub fn process_block(&self, block: BeaconBlock) -> Result<BlockProcessingOutcome, Error> {
        debug!("Processing block with slot {}...", block.slot());

        let block_root = block.canonical_root();

        let present_slot = self.present_slot();

        if block.slot > present_slot {
            return Ok(BlockProcessingOutcome::InvalidBlock(
                InvalidBlock::FutureSlot,
            ));
        }

        // Load the blocks parent block from the database, returning invalid if that block is not
        // found.
        let parent_block_root = block.parent_root;
        let parent_block = match self.block_store.get_reader(&parent_block_root)? {
            Some(parent_root) => parent_root,
            None => {
                return Ok(BlockProcessingOutcome::InvalidBlock(
                    InvalidBlock::ParentUnknown,
                ));
            }
        };

        // Load the parent blocks state from the database, returning an error if it is not found.
        // It is an error because if know the parent block we should also know the parent state.
        let parent_state_root = parent_block.state_root();
        let parent_state = self
            .state_store
            .get_reader(&parent_state_root)?
            .ok_or_else(|| Error::DBInconsistent(format!("Missing state {}", parent_state_root)))?
            .into_beacon_state()
            .ok_or_else(|| {
                Error::DBInconsistent(format!("State SSZ invalid {}", parent_state_root))
            })?;

        // TODO: check the block proposer signature BEFORE doing a state transition. This will
        // significantly lower exposure surface to DoS attacks.

        // Transition the parent state to the present slot.
        let mut state = parent_state;
        for _ in state.slot.as_u64()..present_slot.as_u64() {
            if let Err(e) = state.per_slot_processing(parent_block_root, &self.spec) {
                return Ok(BlockProcessingOutcome::InvalidBlock(
                    InvalidBlock::SlotProcessingError(e),
                ));
            }
        }

        // Apply the received block to its parent state (which has been transitioned into this
        // slot).
        if let Err(e) = state.per_block_processing(&block, &self.spec) {
            return Ok(BlockProcessingOutcome::InvalidBlock(
                InvalidBlock::PerBlockProcessingError(e),
            ));
        }

        let state_root = state.canonical_root();

        if block.state_root != state_root {
            return Ok(BlockProcessingOutcome::InvalidBlock(
                InvalidBlock::StateRootMismatch,
            ));
        }

        // Store the block and state.
        self.block_store.put(&block_root, &ssz_encode(&block)[..])?;
        self.state_store.put(&state_root, &ssz_encode(&state)[..])?;

        // run the fork_choice add_block logic
        self.fork_choice
            .write()
            .add_block(&block, &block_root, &self.spec)?;

        // If the parent block was the parent_block, automatically update the canonical head.
        //
        // TODO: this is a first-in-best-dressed scenario that is not ideal; fork_choice should be
        // run instead.
        if self.head().beacon_block_root == parent_block_root {
            self.update_canonical_head(
                block.clone(),
                block_root.clone(),
                state.clone(),
                state_root,
            );
            // Update the local state variable.
            *self.state.write() = state.clone();
            // Update the cached state variable.
            *self.cached_state.write() =
                CachedBeaconState::from_beacon_state(state.clone(), self.spec.clone())?;
        }

        Ok(BlockProcessingOutcome::ValidBlock(ValidBlock::Processed))
    }

    /// Produce a new block at the present slot.
    ///
    /// The produced block will not be inherently valid, it must be signed by a block producer.
    /// Block signing is out of the scope of this function and should be done by a separate program.
    pub fn produce_block(&self, randao_reveal: Signature) -> Option<(BeaconBlock, BeaconState)> {
        debug!("Producing block at slot {}...", self.state.read().slot);

        let mut state = self.state.read().clone();

        trace!("Finding attestations for new block...");

        let attestations = self
            .attestation_aggregator
            .read()
            .get_attestations_for_state(&state, &self.spec);

        trace!(
            "Inserting {} attestation(s) into new block.",
            attestations.len()
        );

        let parent_root = *state.get_block_root(state.slot.saturating_sub(1_u64), &self.spec)?;

        let mut block = BeaconBlock {
            slot: state.slot,
            parent_root,
            state_root: Hash256::zero(), // Updated after the state is calculated.
            randao_reveal,
            eth1_data: Eth1Data {
                // TODO: replace with real data
                deposit_root: Hash256::zero(),
                block_hash: Hash256::zero(),
            },
            signature: self.spec.empty_signature.clone(), // To be completed by a validator.
            body: BeaconBlockBody {
                proposer_slashings: vec![],
                attester_slashings: vec![],
                attestations,
                deposits: vec![],
                exits: vec![],
            },
        };

        trace!("BeaconChain::produce_block: updating state for new block.",);

        let result =
            state.per_block_processing_without_verifying_block_signature(&block, &self.spec);
        trace!(
            "BeaconNode::produce_block: state processing result: {:?}",
            result
        );
        result.ok()?;

        let state_root = state.canonical_root();

        block.state_root = state_root;

        trace!("Block produced.");

        Some((block, state))
    }

    // TODO: Left this as is, modify later
    pub fn fork_choice(&self) -> Result<(), Error> {
        let present_head = self.finalized_head().beacon_block_root;

        let new_head = self
            .fork_choice
            .write()
            .find_head(&present_head, &self.spec)?;

        if new_head != present_head {
            let block = self
                .block_store
                .get_deserialized(&new_head)?
                .ok_or_else(|| Error::MissingBeaconBlock(new_head))?;
            let block_root = block.canonical_root();

            let state = self
                .state_store
                .get_deserialized(&block.state_root)?
                .ok_or_else(|| Error::MissingBeaconState(block.state_root))?;
            let state_root = state.canonical_root();

            self.update_canonical_head(block, block_root, state, state_root);
        }

        Ok(())
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e.message)
    }
}

impl From<ForkChoiceError> for Error {
    fn from(e: ForkChoiceError) -> Error {
        Error::ForkChoiceError(e)
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}
