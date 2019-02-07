use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    ClientDB, DBError,
};
use genesis::{genesis_beacon_block, genesis_beacon_state};
use log::{debug, trace};
use parking_lot::{RwLock, RwLockReadGuard};
use slot_clock::SlotClock;
use ssz::ssz_encode;
use std::sync::Arc;
use types::{
    beacon_state::{BlockProcessingError, CommitteesError, SlotProcessingError},
    readers::{BeaconBlockReader, BeaconStateReader},
    AttestationData, BeaconBlock, BeaconBlockBody, BeaconState, ChainSpec, Eth1Data,
    FreeAttestation, Hash256, PublicKey, Signature, Slot,
};

use crate::attestation_aggregator::{AttestationAggregator, Outcome as AggregationOutcome};
use crate::attestation_targets::AttestationTargets;
use crate::block_graph::BlockGraph;
use crate::checkpoint::CheckPoint;

#[derive(Debug, PartialEq)]
pub enum Error {
    InsufficientValidators,
    BadRecentBlockRoots,
    CommitteesError(CommitteesError),
    DBInconsistent(String),
    DBError(String),
}

#[derive(Debug, PartialEq)]
pub enum ValidBlock {
    /// The block was sucessfully processed.
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
    /// The block was sucessfully validated.
    ValidBlock(ValidBlock),
    /// The block was not sucessfully validated.
    InvalidBlock(InvalidBlock),
}

pub struct BeaconChain<T: ClientDB + Sized, U: SlotClock> {
    pub block_store: Arc<BeaconBlockStore<T>>,
    pub state_store: Arc<BeaconStateStore<T>>,
    pub slot_clock: U,
    pub block_graph: BlockGraph,
    pub attestation_aggregator: RwLock<AttestationAggregator>,
    canonical_head: RwLock<CheckPoint>,
    finalized_head: RwLock<CheckPoint>,
    justified_head: RwLock<CheckPoint>,
    pub state: RwLock<BeaconState>,
    pub latest_attestation_targets: RwLock<AttestationTargets>,
    pub spec: ChainSpec,
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    /// Instantiate a new Beacon Chain, from genesis.
    pub fn genesis(
        state_store: Arc<BeaconStateStore<T>>,
        block_store: Arc<BeaconBlockStore<T>>,
        slot_clock: U,
        spec: ChainSpec,
    ) -> Result<Self, Error> {
        if spec.initial_validators.is_empty() {
            return Err(Error::InsufficientValidators);
        }

        let genesis_state = genesis_beacon_state(&spec);
        let state_root = genesis_state.canonical_root();
        state_store.put(&state_root, &ssz_encode(&genesis_state)[..])?;

        let genesis_block = genesis_beacon_block(state_root, &spec);
        let block_root = genesis_block.canonical_root();
        block_store.put(&block_root, &ssz_encode(&genesis_block)[..])?;

        let block_graph = BlockGraph::new();
        block_graph.add_leaf(&Hash256::zero(), block_root.clone());

        let finalized_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            block_root.clone(),
            genesis_state.clone(),
            state_root.clone(),
        ));
        let justified_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            block_root.clone(),
            genesis_state.clone(),
            state_root.clone(),
        ));
        let canonical_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            block_root.clone(),
            genesis_state.clone(),
            state_root.clone(),
        ));
        let attestation_aggregator = RwLock::new(AttestationAggregator::new());

        let latest_attestation_targets = RwLock::new(AttestationTargets::new());

        Ok(Self {
            block_store,
            state_store,
            slot_clock,
            block_graph,
            attestation_aggregator,
            state: RwLock::new(genesis_state.clone()),
            justified_head,
            finalized_head,
            canonical_head,
            latest_attestation_targets,
            spec: spec,
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
                .per_slot_processing(head_block_root.clone(), &self.spec)?;
        }
        Ok(())
    }

    /// Returns the the validator index (if any) for the given public key.
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

    /// Returns the number of slots the validator has been required to propose.
    ///
    /// Returns `None` if the `validator_index` is invalid.
    ///
    /// Information is retrieved from the present `beacon_state.validator_registry`.
    pub fn proposer_slots(&self, validator_index: usize) -> Option<u64> {
        if let Some(validator) = self.state.read().validator_registry.get(validator_index) {
            Some(validator.proposer_slots)
        } else {
            None
        }
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
    pub fn block_proposer(&self, slot: Slot) -> Result<usize, CommitteesError> {
        let index = self
            .state
            .read()
            .get_beacon_proposer_index(slot, &self.spec)?;

        Ok(index)
    }

    /// Returns the justified slot for the present state.
    pub fn justified_slot(&self) -> Slot {
        self.state.read().justified_slot
    }

    /// Returns the attestation slot and shard for a given validator index.
    ///
    /// Information is read from the current state, so only information from the present and prior
    /// epoch is available.
    pub fn validator_attestion_slot_and_shard(
        &self,
        validator_index: usize,
    ) -> Result<Option<(Slot, u64)>, CommitteesError> {
        if let Some((slot, shard, _committee)) = self
            .state
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
        let justified_slot = self.justified_slot();
        let justified_block_root = self
            .state
            .read()
            .get_block_root(justified_slot, &self.spec)
            .ok_or_else(|| Error::BadRecentBlockRoots)?
            .clone();

        let epoch_boundary_root = self
            .state
            .read()
            .get_block_root(
                self.state.read().current_epoch_start_slot(&self.spec),
                &self.spec,
            )
            .ok_or_else(|| Error::BadRecentBlockRoots)?
            .clone();

        Ok(AttestationData {
            slot: self.state.read().slot,
            shard,
            beacon_block_root: self.head().beacon_block_root.clone(),
            epoch_boundary_root,
            shard_block_root: Hash256::zero(),
            latest_crosslink_root: Hash256::zero(),
            justified_slot,
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
        self.attestation_aggregator
            .write()
            .process_free_attestation(&self.state.read(), &free_attestation, &self.spec)
            .map_err(|e| e.into())
    }

    /// Set the latest attestation target for some validator.
    pub fn insert_latest_attestation_target(&self, validator_index: u64, block_root: Hash256) {
        let mut targets = self.latest_attestation_targets.write();
        targets.insert(validator_index, block_root);
    }

    /// Get the latest attestation target for some validator.
    pub fn get_latest_attestation_target(&self, validator_index: u64) -> Option<Hash256> {
        let targets = self.latest_attestation_targets.read();

        match targets.get(validator_index) {
            Some(hash) => Some(hash.clone()),
            None => None,
        }
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
            .ok_or(Error::DBInconsistent(format!(
                "Missing state {}",
                parent_state_root
            )))?
            .into_beacon_state()
            .ok_or(Error::DBInconsistent(format!(
                "State SSZ invalid {}",
                parent_state_root
            )))?;

        // TODO: check the block proposer signature BEFORE doing a state transition. This will
        // significantly lower exposure surface to DoS attacks.

        // Transition the parent state to the present slot.
        let mut state = parent_state;
        for _ in state.slot.as_u64()..present_slot.as_u64() {
            if let Err(e) = state.per_slot_processing(parent_block_root.clone(), &self.spec) {
                return Ok(BlockProcessingOutcome::InvalidBlock(
                    InvalidBlock::SlotProcessingError(e),
                ));
            }
        }

        // Apply the recieved block to its parent state (which has been transitioned into this
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

        // Update the block DAG.
        self.block_graph
            .add_leaf(&parent_block_root, block_root.clone());

        // If the parent block was the parent_block, automatically update the canonical head.
        //
        // TODO: this is a first-in-best-dressed scenario that is not ideal; fork_choice should be
        // run instead.
        if self.head().beacon_block_root == parent_block_root {
            self.update_canonical_head(
                block.clone(),
                block_root.clone(),
                state.clone(),
                state_root.clone(),
            );
            // Update the local state variable.
            *self.state.write() = state.clone();
        }

        Ok(BlockProcessingOutcome::ValidBlock(ValidBlock::Processed))
    }

    /// Produce a new block at the present slot.
    ///
    /// The produced block will not be inheriently valid, it must be signed by a block producer.
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

        let parent_root = state
            .get_block_root(state.slot.saturating_sub(1_u64), &self.spec)?
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

        state
            .per_block_processing_without_verifying_block_signature(&block, &self.spec)
            .ok()?;

        let state_root = state.canonical_root();

        block.state_root = state_root;

        trace!("Block produced.");

        Some((block, state))
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e.message)
    }
}

impl From<CommitteesError> for Error {
    fn from(e: CommitteesError) -> Error {
        Error::CommitteesError(e)
    }
}
