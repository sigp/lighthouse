use crate::checkpoint::CheckPoint;
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use crate::iter::{BlockIterator, BlockRootsIterator};
use crate::metrics::Metrics;
use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};
use fork_choice::{ForkChoice, ForkChoiceError};
use log::{debug, trace};
use operation_pool::DepositInsertStatus;
use operation_pool::OperationPool;
use parking_lot::{RwLock, RwLockReadGuard};
use slot_clock::SlotClock;
use state_processing::per_block_processing::errors::{
    AttestationValidationError, AttesterSlashingValidationError, DepositValidationError,
    ExitValidationError, ProposerSlashingValidationError, TransferValidationError,
};
use state_processing::{
    per_block_processing, per_block_processing_without_verifying_block_signature,
    per_slot_processing, BlockProcessingError, SlotProcessingError,
};
use std::sync::Arc;
use store::{Error as DBError, Store};
use tree_hash::TreeHash;
use types::*;

#[derive(Debug, PartialEq)]
pub enum ValidBlock {
    /// The block was successfully processed.
    Processed,
}

#[derive(Debug, PartialEq)]
pub enum InvalidBlock {
    /// Don't re-process the genesis block.
    GenesisBlock,
    /// The block slot is greater than the present slot.
    FutureSlot {
        present_slot: Slot,
        block_slot: Slot,
    },
    /// The block state_root does not match the generated state.
    StateRootMismatch,
    /// The blocks parent_root is unknown.
    ParentUnknown { parent: Hash256 },
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

impl BlockProcessingOutcome {
    /// Returns `true` if the block was objectively invalid and we should disregard the peer who
    /// sent it.
    pub fn is_invalid(&self) -> bool {
        match self {
            BlockProcessingOutcome::ValidBlock(_) => false,
            BlockProcessingOutcome::InvalidBlock(r) => match r {
                InvalidBlock::GenesisBlock { .. } => true,
                InvalidBlock::FutureSlot { .. } => true,
                InvalidBlock::StateRootMismatch => true,
                InvalidBlock::ParentUnknown { .. } => false,
                InvalidBlock::SlotProcessingError(_) => false,
                InvalidBlock::PerBlockProcessingError(e) => match e {
                    BlockProcessingError::Invalid(_) => true,
                    BlockProcessingError::BeaconStateError(_) => false,
                },
            },
        }
    }

    /// Returns `true` if the block was successfully processed and can be removed from any import
    /// queues or temporary storage.
    pub fn sucessfully_processed(&self) -> bool {
        match self {
            BlockProcessingOutcome::ValidBlock(_) => true,
            _ => false,
        }
    }
}

pub trait BeaconChainTypes {
    type Store: store::Store;
    type SlotClock: slot_clock::SlotClock;
    type ForkChoice: fork_choice::ForkChoice<Self::Store>;
    type EthSpec: types::EthSpec;
}

/// Represents the "Beacon Chain" component of Ethereum 2.0. Allows import of blocks and block
/// operations and chooses a canonical head.
pub struct BeaconChain<T: BeaconChainTypes> {
    pub spec: ChainSpec,
    /// Persistent storage for blocks, states, etc. Typically an on-disk store, such as LevelDB.
    pub store: Arc<T::Store>,
    /// Reports the current slot, typically based upon the system clock.
    pub slot_clock: T::SlotClock,
    /// Stores all operations (e.g., `Attestation`, `Deposit`, etc) that are candidates for
    /// inclusion in a block.
    pub op_pool: OperationPool<T::EthSpec>,
    /// Stores a "snapshot" of the chain at the time the head-of-the-chain block was recieved.
    canonical_head: RwLock<CheckPoint<T::EthSpec>>,
    /// The same state from `self.canonical_head`, but updated at the start of each slot with a
    /// skip slot if no block is recieved. This is effectively a cache that avoids repeating calls
    /// to `per_slot_processing`.
    state: RwLock<BeaconState<T::EthSpec>>,
    /// The root of the genesis block.
    genesis_block_root: Hash256,
    /// A state-machine that is updated with information from the network and chooses a canonical
    /// head block.
    pub fork_choice: RwLock<T::ForkChoice>,
    /// Stores metrics about this `BeaconChain`.
    pub metrics: Metrics,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Instantiate a new Beacon Chain, from genesis.
    pub fn from_genesis(
        store: Arc<T::Store>,
        slot_clock: T::SlotClock,
        mut genesis_state: BeaconState<T::EthSpec>,
        genesis_block: BeaconBlock,
        spec: ChainSpec,
        fork_choice: T::ForkChoice,
    ) -> Result<Self, Error> {
        let state_root = genesis_state.canonical_root();
        store.put(&state_root, &genesis_state)?;

        let genesis_block_root = genesis_block.block_header().canonical_root();
        store.put(&genesis_block_root, &genesis_block)?;

        // Also store the genesis block under the `ZERO_HASH` key.
        let genesis_block_root = genesis_block.block_header().canonical_root();
        store.put(&spec.zero_hash, &genesis_block)?;

        let canonical_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            genesis_block_root,
            genesis_state.clone(),
            state_root,
        ));

        genesis_state.build_all_caches(&spec)?;

        Ok(Self {
            spec,
            store,
            slot_clock,
            op_pool: OperationPool::new(),
            state: RwLock::new(genesis_state),
            canonical_head,
            genesis_block_root,
            fork_choice: RwLock::new(fork_choice),
            metrics: Metrics::new()?,
        })
    }

    /// Attempt to load an existing instance from the given `store`.
    pub fn from_store(
        store: Arc<T::Store>,
        spec: ChainSpec,
    ) -> Result<Option<BeaconChain<T>>, Error> {
        let key = Hash256::from_slice(&BEACON_CHAIN_DB_KEY.as_bytes());
        let p: PersistedBeaconChain<T> = match store.get(&key) {
            Err(e) => return Err(e.into()),
            Ok(None) => return Ok(None),
            Ok(Some(p)) => p,
        };

        let slot_clock = T::SlotClock::new(
            spec.genesis_slot,
            p.state.genesis_time,
            spec.seconds_per_slot,
        );

        let fork_choice = T::ForkChoice::new(store.clone());

        Ok(Some(BeaconChain {
            spec,
            store,
            slot_clock,
            op_pool: OperationPool::default(),
            canonical_head: RwLock::new(p.canonical_head),
            state: RwLock::new(p.state),
            fork_choice: RwLock::new(fork_choice),
            genesis_block_root: p.genesis_block_root,
            metrics: Metrics::new()?,
        }))
    }

    /// Attempt to save this instance to `self.store`.
    pub fn persist(&self) -> Result<(), Error> {
        let p: PersistedBeaconChain<T> = PersistedBeaconChain {
            canonical_head: self.canonical_head.read().clone(),
            genesis_block_root: self.genesis_block_root,
            state: self.state.read().clone(),
        };

        let key = Hash256::from_slice(&BEACON_CHAIN_DB_KEY.as_bytes());
        self.store.put(&key, &p)?;

        Ok(())
    }

    /// Returns the beacon block body for each beacon block root in `roots`.
    ///
    /// Fails if any root in `roots` does not have a corresponding block.
    pub fn get_block_bodies(&self, roots: &[Hash256]) -> Result<Vec<BeaconBlockBody>, Error> {
        let bodies: Result<Vec<BeaconBlockBody>, _> = roots
            .iter()
            .map(|root| match self.get_block(root)? {
                Some(block) => Ok(block.body),
                None => Err(Error::DBInconsistent(
                    format!("Missing block: {}", root).into(),
                )),
            })
            .collect();

        Ok(bodies?)
    }

    /// Returns the beacon block header for each beacon block root in `roots`.
    ///
    /// Fails if any root in `roots` does not have a corresponding block.
    pub fn get_block_headers(&self, roots: &[Hash256]) -> Result<Vec<BeaconBlockHeader>, Error> {
        let headers: Result<Vec<BeaconBlockHeader>, _> = roots
            .iter()
            .map(|root| match self.get_block(root)? {
                Some(block) => Ok(block.block_header()),
                None => Err(Error::DBInconsistent("Missing block".into())),
            })
            .collect();

        Ok(headers?)
    }
    /// Iterate in reverse (highest to lowest slot) through all blocks from the block at `slot`
    /// through to the genesis block.
    ///
    /// Returns `None` for headers prior to genesis or when there is an error reading from `Store`.
    ///
    /// Contains duplicate headers when skip slots are encountered.
    pub fn rev_iter_blocks(&self, slot: Slot) -> BlockIterator<T::EthSpec, T::Store> {
        BlockIterator::new(self.store.clone(), self.state.read().clone(), slot)
    }

    /// Iterates in reverse (highest to lowest slot) through all block roots from `slot` through to
    /// genesis.
    ///
    /// Returns `None` for roots prior to genesis or when there is an error reading from `Store`.
    ///
    /// Contains duplicate roots when skip slots are encountered.
    pub fn rev_iter_block_roots(&self, slot: Slot) -> BlockRootsIterator<T::EthSpec, T::Store> {
        BlockRootsIterator::new(self.store.clone(), self.state.read().clone(), slot)
    }

    /*
    /// Returns `count `beacon block roots, starting from `start_slot` with an
    /// interval of `skip` slots between each root.
    ///
    /// ## Errors:
    ///
    /// - `SlotOutOfBounds`: Unable to return the full specified range.
    /// - `SlotOutOfBounds`: Unable to load a state from the DB.
    /// - `SlotOutOfBounds`: Start slot is higher than the first slot.
    /// - Other: BeaconState` is inconsistent.
    pub fn get_block_roots(
        &self,
        earliest_slot: Slot,
        count: usize,
        skip: usize,
    ) -> Result<Vec<Hash256>, Error> {
        let step_by = Slot::from(skip + 1);

        let mut roots: Vec<Hash256> = vec![];

        // The state for reading block roots. Will be updated with an older state if slots go too
        // far back in history.
        let mut state = self.state.read().clone();

        // The final slot in this series, will be reduced by `skip` each loop iteration.
        let mut slot = earliest_slot + Slot::from(count * (skip + 1)) - 1;

        // If the highest slot requested is that of the current state insert the root of the
        // head block, unless the head block's slot is not matching.
        if slot == state.slot && self.head().beacon_block.slot == slot {
            roots.push(self.head().beacon_block_root);

            slot -= step_by;
        } else if slot >= state.slot {
            return Err(BeaconStateError::SlotOutOfBounds.into());
        }

        loop {
            // If the slot is within the range of the current state's block roots, append the root
            // to the output vec.
            //
            // If we get `SlotOutOfBounds` error, load the oldest available historic
            // state from the DB.
            match state.get_block_root(slot) {
                Ok(root) => {
                    if slot < earliest_slot {
                        break;
                    } else {
                        roots.push(*root);
                        slot -= step_by;
                    }
                }
                Err(BeaconStateError::SlotOutOfBounds) => {
                    // Read the earliest historic state in the current slot.
                    let earliest_historic_slot =
                        state.slot - Slot::from(T::EthSpec::slots_per_historical_root());
                    // Load the earlier state from disk.
                    let new_state_root = state.get_state_root(earliest_historic_slot)?;

                    // Break if the DB is unable to load the state.
                    state = match self.store.get(&new_state_root) {
                        Ok(Some(state)) => state,
                        _ => break,
                    }
                }
                Err(e) => return Err(e.into()),
            };
        }

        // Return the results if they pass a sanity check.
        if (slot <= earliest_slot) && (roots.len() == count) {
            // Reverse the ordering of the roots. We extracted them in reverse order to make it
            // simpler to lookup historic states.
            //
            // This is a potential optimisation target.
            Ok(roots.iter().rev().cloned().collect())
        } else {
            Err(BeaconStateError::SlotOutOfBounds.into())
        }
    }
        */

    /// Returns the block at the given root, if any.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn get_block(&self, block_root: &Hash256) -> Result<Option<BeaconBlock>, Error> {
        Ok(self.store.get(block_root)?)
    }

    /// Update the canonical head to `new_head`.
    fn update_canonical_head(&self, new_head: CheckPoint<T::EthSpec>) -> Result<(), Error> {
        // Update the checkpoint that stores the head of the chain at the time it received the
        // block.
        *self.canonical_head.write() = new_head;

        // Update the always-at-the-present-slot state we keep around for performance gains.
        *self.state.write() = {
            let mut state = self.canonical_head.read().beacon_state.clone();

            let present_slot = match self.slot_clock.present_slot() {
                Ok(Some(slot)) => slot,
                _ => return Err(Error::UnableToReadSlot),
            };

            // If required, transition the new state to the present slot.
            for _ in state.slot.as_u64()..present_slot.as_u64() {
                per_slot_processing(&mut state, &self.spec)?;
            }

            state.build_all_caches(&self.spec)?;

            state
        };

        // Save `self` to `self.store`.
        self.persist()?;

        Ok(())
    }

    /// Returns a read-lock guarded `BeaconState` which is the `canonical_head` that has been
    /// updated to match the current slot clock.
    pub fn current_state(&self) -> RwLockReadGuard<BeaconState<T::EthSpec>> {
        self.state.read()
    }

    /// Returns a read-lock guarded `CheckPoint` struct for reading the head (as chosen by the
    /// fork-choice rule).
    ///
    /// It is important to note that the `beacon_state` returned may not match the present slot. It
    /// is the state as it was when the head block was received, which could be some slots prior to
    /// now.
    pub fn head(&self) -> RwLockReadGuard<CheckPoint<T::EthSpec>> {
        self.canonical_head.read()
    }

    /// Returns the slot of the highest block in the canonical chain.
    pub fn best_slot(&self) -> Slot {
        self.canonical_head.read().beacon_block.slot
    }

    /// Ensures the current canonical `BeaconState` has been transitioned to match the `slot_clock`.
    pub fn catchup_state(&self) -> Result<(), Error> {
        let spec = &self.spec;

        let present_slot = match self.slot_clock.present_slot() {
            Ok(Some(slot)) => slot,
            _ => return Err(Error::UnableToReadSlot),
        };

        let mut state = self.state.write();

        // If required, transition the new state to the present slot.
        for _ in state.slot.as_u64()..present_slot.as_u64() {
            // Ensure the next epoch state caches are built in case of an epoch transition.
            state.build_committee_cache(RelativeEpoch::Next, spec)?;

            per_slot_processing(&mut *state, spec)?;
        }

        state.build_all_caches(spec)?;

        Ok(())
    }

    /// Build all of the caches on the current state.
    ///
    /// Ideally this shouldn't be required, however we leave it here for testing.
    pub fn ensure_state_caches_are_built(&self) -> Result<(), Error> {
        self.state.write().build_all_caches(&self.spec)?;

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

    /// Reads the slot clock (see `self.read_slot_clock()` and returns the number of slots since
    /// genesis.
    pub fn slots_since_genesis(&self) -> Option<SlotHeight> {
        let now = self.read_slot_clock()?;
        let genesis_slot = self.spec.genesis_slot;

        if now < genesis_slot {
            None
        } else {
            Some(SlotHeight::from(now.as_u64() - genesis_slot.as_u64()))
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
        self.state
            .write()
            .build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        let index = self.state.read().get_beacon_proposer_index(
            slot,
            RelativeEpoch::Current,
            &self.spec,
        )?;

        Ok(index)
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
        if let Some(attestation_duty) = self
            .state
            .read()
            .get_attestation_duties(validator_index, RelativeEpoch::Current)?
        {
            Ok(Some((attestation_duty.slot, attestation_duty.shard)))
        } else {
            Ok(None)
        }
    }

    /// Produce an `AttestationData` that is valid for the present `slot` and given `shard`.
    pub fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, Error> {
        let slots_per_epoch = T::EthSpec::slots_per_epoch();

        self.metrics.attestation_production_requests.inc();
        let timer = self.metrics.attestation_production_times.start_timer();

        let state = self.state.read();

        let current_epoch_start_slot = self
            .state
            .read()
            .slot
            .epoch(slots_per_epoch)
            .start_slot(slots_per_epoch);

        let target_root = if state.slot == current_epoch_start_slot {
            // If we're on the first slot of the state's epoch.
            if self.head().beacon_block.slot == state.slot {
                // If the current head block is from the current slot, use its block root.
                self.head().beacon_block_root
            } else {
                // If the current head block is not from this slot, use the slot from the previous
                // epoch.
                *self
                    .state
                    .read()
                    .get_block_root(current_epoch_start_slot - slots_per_epoch)?
            }
        } else {
            // If we're not on the first slot of the epoch.
            *self.state.read().get_block_root(current_epoch_start_slot)?
        };

        let previous_crosslink_root =
            Hash256::from_slice(&state.get_current_crosslink(shard)?.tree_hash_root());

        self.metrics.attestation_production_successes.inc();
        timer.observe_duration();

        Ok(AttestationData {
            beacon_block_root: self.head().beacon_block_root,
            source_epoch: state.current_justified_epoch,
            source_root: state.current_justified_root,
            target_epoch: state.current_epoch(),
            target_root,
            shard,
            previous_crosslink_root,
            crosslink_data_root: Hash256::zero(),
        })
    }

    /// Accept a new attestation from the network.
    ///
    /// If valid, the attestation is added to the `op_pool` and aggregated with another attestation
    /// if possible.
    pub fn process_attestation(
        &self,
        attestation: Attestation,
    ) -> Result<(), AttestationValidationError> {
        self.metrics.attestation_processing_requests.inc();
        let timer = self.metrics.attestation_processing_times.start_timer();

        let result = self
            .op_pool
            .insert_attestation(attestation, &*self.state.read(), &self.spec);

        if result.is_ok() {
            self.metrics.attestation_processing_successes.inc();
        }

        timer.observe_duration();

        result
    }

    /// Accept some deposit and queue it for inclusion in an appropriate block.
    pub fn process_deposit(
        &self,
        deposit: Deposit,
    ) -> Result<DepositInsertStatus, DepositValidationError> {
        self.op_pool
            .insert_deposit(deposit, &*self.state.read(), &self.spec)
    }

    /// Accept some exit and queue it for inclusion in an appropriate block.
    pub fn process_voluntary_exit(&self, exit: VoluntaryExit) -> Result<(), ExitValidationError> {
        self.op_pool
            .insert_voluntary_exit(exit, &*self.state.read(), &self.spec)
    }

    /// Accept some transfer and queue it for inclusion in an appropriate block.
    pub fn process_transfer(&self, transfer: Transfer) -> Result<(), TransferValidationError> {
        self.op_pool
            .insert_transfer(transfer, &*self.state.read(), &self.spec)
    }

    /// Accept some proposer slashing and queue it for inclusion in an appropriate block.
    pub fn process_proposer_slashing(
        &self,
        proposer_slashing: ProposerSlashing,
    ) -> Result<(), ProposerSlashingValidationError> {
        self.op_pool
            .insert_proposer_slashing(proposer_slashing, &*self.state.read(), &self.spec)
    }

    /// Accept some attester slashing and queue it for inclusion in an appropriate block.
    pub fn process_attester_slashing(
        &self,
        attester_slashing: AttesterSlashing,
    ) -> Result<(), AttesterSlashingValidationError> {
        self.op_pool
            .insert_attester_slashing(attester_slashing, &*self.state.read(), &self.spec)
    }

    /// Accept some block and attempt to add it to block DAG.
    ///
    /// Will accept blocks from prior slots, however it will reject any block from a future slot.
    pub fn process_block(&self, block: BeaconBlock) -> Result<BlockProcessingOutcome, Error> {
        debug!("Processing block with slot {}...", block.slot);
        self.metrics.block_processing_requests.inc();
        let timer = self.metrics.block_processing_times.start_timer();

        if block.slot == 0 {
            return Ok(BlockProcessingOutcome::InvalidBlock(
                InvalidBlock::GenesisBlock,
            ));
        }

        let block_root = block.block_header().canonical_root();

        if block_root == self.genesis_block_root {
            return Ok(BlockProcessingOutcome::ValidBlock(ValidBlock::Processed));
        }

        let present_slot = self.present_slot();

        if block.slot > present_slot {
            return Ok(BlockProcessingOutcome::InvalidBlock(
                InvalidBlock::FutureSlot {
                    present_slot,
                    block_slot: block.slot,
                },
            ));
        }

        // Load the blocks parent block from the database, returning invalid if that block is not
        // found.
        let parent_block_root = block.previous_block_root;
        let parent_block: BeaconBlock = match self.store.get(&parent_block_root)? {
            Some(previous_block_root) => previous_block_root,
            None => {
                return Ok(BlockProcessingOutcome::InvalidBlock(
                    InvalidBlock::ParentUnknown {
                        parent: parent_block_root,
                    },
                ));
            }
        };

        // Load the parent blocks state from the database, returning an error if it is not found.
        // It is an error because if know the parent block we should also know the parent state.
        let parent_state_root = parent_block.state_root;
        let parent_state = self
            .store
            .get(&parent_state_root)?
            .ok_or_else(|| Error::DBInconsistent(format!("Missing state {}", parent_state_root)))?;

        // TODO: check the block proposer signature BEFORE doing a state transition. This will
        // significantly lower exposure surface to DoS attacks.

        // Transition the parent state to the block slot.
        let mut state: BeaconState<T::EthSpec> = parent_state;
        for _ in state.slot.as_u64()..block.slot.as_u64() {
            if let Err(e) = per_slot_processing(&mut state, &self.spec) {
                return Ok(BlockProcessingOutcome::InvalidBlock(
                    InvalidBlock::SlotProcessingError(e),
                ));
            }
        }

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        // Apply the received block to its parent state (which has been transitioned into this
        // slot).
        if let Err(e) = per_block_processing(&mut state, &block, &self.spec) {
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
        self.store.put(&block_root, &block)?;
        self.store.put(&state_root, &state)?;

        // Register the new block with the fork choice service.
        self.fork_choice
            .write()
            .add_block(&block, &block_root, &self.spec)?;

        // Execute the fork choice algorithm, enthroning a new head if discovered.
        //
        // Note: in the future we may choose to run fork-choice less often, potentially based upon
        // some heuristic around number of attestations seen for the block.
        self.fork_choice()?;

        self.metrics.block_processing_successes.inc();
        self.metrics
            .operations_per_block_attestation
            .observe(block.body.attestations.len() as f64);
        timer.observe_duration();

        Ok(BlockProcessingOutcome::ValidBlock(ValidBlock::Processed))
    }

    /// Produce a new block at the present slot.
    ///
    /// The produced block will not be inherently valid, it must be signed by a block producer.
    /// Block signing is out of the scope of this function and should be done by a separate program.
    pub fn produce_block(
        &self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState<T::EthSpec>), BlockProductionError> {
        debug!("Producing block at slot {}...", self.state.read().slot);
        self.metrics.block_production_requests.inc();
        let timer = self.metrics.block_production_times.start_timer();

        let mut state = self.state.read().clone();

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        trace!("Finding attestations for new block...");

        let previous_block_root = if state.slot > 0 {
            *state
                .get_block_root(state.slot - 1)
                .map_err(|_| BlockProductionError::UnableToGetBlockRootFromState)?
        } else {
            state.latest_block_header.canonical_root()
        };

        let (proposer_slashings, attester_slashings) =
            self.op_pool.get_slashings(&*self.state.read(), &self.spec);

        let mut block = BeaconBlock {
            slot: state.slot,
            previous_block_root,
            state_root: Hash256::zero(), // Updated after the state is calculated.
            signature: Signature::empty_signature(), // To be completed by a validator.
            body: BeaconBlockBody {
                randao_reveal,
                eth1_data: Eth1Data {
                    // TODO: replace with real data
                    deposit_count: 0,
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                },
                // TODO: badass Lighthouse graffiti
                graffiti: [0; 32],
                proposer_slashings,
                attester_slashings,
                attestations: self
                    .op_pool
                    .get_attestations(&*self.state.read(), &self.spec),
                deposits: self.op_pool.get_deposits(&*self.state.read(), &self.spec),
                voluntary_exits: self
                    .op_pool
                    .get_voluntary_exits(&*self.state.read(), &self.spec),
                transfers: self.op_pool.get_transfers(&*self.state.read(), &self.spec),
            },
        };

        debug!(
            "Produced block with {} attestations, updating state.",
            block.body.attestations.len()
        );

        per_block_processing_without_verifying_block_signature(&mut state, &block, &self.spec)?;

        let state_root = state.canonical_root();

        block.state_root = state_root;

        self.metrics.block_production_successes.inc();
        timer.observe_duration();

        Ok((block, state))
    }

    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
    pub fn fork_choice(&self) -> Result<(), Error> {
        self.metrics.fork_choice_requests.inc();

        // Start fork choice metrics timer.
        let timer = self.metrics.fork_choice_times.start_timer();

        let justified_root = {
            let root = self.head().beacon_state.current_justified_root;
            if root == self.spec.zero_hash {
                self.genesis_block_root
            } else {
                root
            }
        };

        // Determine the root of the block that is the head of the chain.
        let beacon_block_root = self
            .fork_choice
            .write()
            .find_head(&justified_root, &self.spec)?;

        // End fork choice metrics timer.
        timer.observe_duration();

        // If a new head was chosen.
        if beacon_block_root != self.head().beacon_block_root {
            self.metrics.fork_choice_changed_head.inc();

            let beacon_block: BeaconBlock = self
                .store
                .get(&beacon_block_root)?
                .ok_or_else(|| Error::MissingBeaconBlock(beacon_block_root))?;

            let beacon_state_root = beacon_block.state_root;
            let beacon_state: BeaconState<T::EthSpec> = self
                .store
                .get(&beacon_state_root)?
                .ok_or_else(|| Error::MissingBeaconState(beacon_state_root))?;

            // If we switched to a new chain (instead of building atop the present chain).
            if self.head().beacon_block_root != beacon_block.previous_block_root {
                self.metrics.fork_choice_reorg_count.inc();
            };

            self.update_canonical_head(CheckPoint {
                beacon_block,
                beacon_block_root,
                beacon_state,
                beacon_state_root,
            })?;
        }

        Ok(())
    }

    /// Returns `true` if the given block root has not been processed.
    pub fn is_new_block_root(&self, beacon_block_root: &Hash256) -> Result<bool, Error> {
        Ok(!self.store.exists::<BeaconBlock>(beacon_block_root)?)
    }

    /// Dumps the entire canonical chain, from the head to genesis to a vector for analysis.
    ///
    /// This could be a very expensive operation and should only be done in testing/analysis
    /// activities.
    pub fn chain_dump(&self) -> Result<Vec<CheckPoint<T::EthSpec>>, Error> {
        let mut dump = vec![];

        let mut last_slot = CheckPoint {
            beacon_block: self.head().beacon_block.clone(),
            beacon_block_root: self.head().beacon_block_root,
            beacon_state: self.head().beacon_state.clone(),
            beacon_state_root: self.head().beacon_state_root,
        };

        dump.push(last_slot.clone());

        loop {
            let beacon_block_root = last_slot.beacon_block.previous_block_root;

            if beacon_block_root == self.spec.zero_hash {
                break; // Genesis has been reached.
            }

            let beacon_block: BeaconBlock =
                self.store.get(&beacon_block_root)?.ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing block {}", beacon_block_root))
                })?;
            let beacon_state_root = beacon_block.state_root;
            let beacon_state = self.store.get(&beacon_state_root)?.ok_or_else(|| {
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

        dump.reverse();

        Ok(dump)
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e)
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
