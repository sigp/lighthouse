use crate::checkpoint::CheckPoint;
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use crate::fork_choice::{Error as ForkChoiceError, ForkChoice};
use crate::metrics::Metrics;
use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};
use lmd_ghost::LmdGhost;
use log::trace;
use operation_pool::DepositInsertStatus;
use operation_pool::{OperationPool, PersistedOperationPool};
use parking_lot::{RwLock, RwLockReadGuard};
use slot_clock::SlotClock;
use state_processing::per_block_processing::errors::{
    AttestationValidationError, AttesterSlashingValidationError, DepositValidationError,
    ExitValidationError, ProposerSlashingValidationError, TransferValidationError,
};
use state_processing::{
    per_block_processing, per_block_processing_without_verifying_block_signature,
    per_slot_processing, BlockProcessingError, common
};
use std::sync::Arc;
use store::iter::{BlockIterator, BlockRootsIterator, StateRootsIterator};
use store::{Error as DBError, Store};
use tree_hash::TreeHash;
use types::*;

// Text included in blocks.
// Must be 32-bytes or panic.
//
//                          |-------must be this long------|
pub const GRAFFITI: &str = "sigp/lighthouse-0.0.0-prerelease";

#[derive(Debug, PartialEq)]
pub enum BlockProcessingOutcome {
    /// Block was valid and imported into the block graph.
    Processed { block_root: Hash256 },
    /// The blocks parent_root is unknown.
    ParentUnknown { parent: Hash256 },
    /// The block slot is greater than the present slot.
    FutureSlot {
        present_slot: Slot,
        block_slot: Slot,
    },
    /// The block state_root does not match the generated state.
    StateRootMismatch,
    /// The block was a genesis block, these blocks cannot be re-imported.
    GenesisBlock,
    /// The slot is finalized, no need to import.
    FinalizedSlot,
    /// Block is already known, no need to re-import.
    BlockIsAlreadyKnown,
    /// The block could not be applied to the state, it is invalid.
    PerBlockProcessingError(BlockProcessingError),
}

pub trait BeaconChainTypes {
    type Store: store::Store;
    type SlotClock: slot_clock::SlotClock;
    type LmdGhost: LmdGhost<Self::Store, Self::EthSpec>;
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
    pub fork_choice: ForkChoice<T>,
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
    ) -> Result<Self, Error> {
        genesis_state.build_all_caches(&spec)?;

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

        Ok(Self {
            spec,
            slot_clock,
            op_pool: OperationPool::new(),
            state: RwLock::new(genesis_state),
            canonical_head,
            genesis_block_root,
            fork_choice: ForkChoice::new(store.clone(), &genesis_block, genesis_block_root),
            metrics: Metrics::new()?,
            store,
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

        let last_finalized_root = p.canonical_head.beacon_state.finalized_root;
        let last_finalized_block = &p.canonical_head.beacon_block;

        let op_pool = p.op_pool.into_operation_pool(&p.state, &spec);

        Ok(Some(BeaconChain {
            spec,
            slot_clock,
            fork_choice: ForkChoice::new(store.clone(), last_finalized_block, last_finalized_root),
            op_pool,
            canonical_head: RwLock::new(p.canonical_head),
            state: RwLock::new(p.state),
            genesis_block_root: p.genesis_block_root,
            metrics: Metrics::new()?,
            store,
        }))
    }

    /// Attempt to save this instance to `self.store`.
    pub fn persist(&self) -> Result<(), Error> {
        let p: PersistedBeaconChain<T> = PersistedBeaconChain {
            canonical_head: self.canonical_head.read().clone(),
            op_pool: PersistedOperationPool::from_operation_pool(&self.op_pool),
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
                None => Err(Error::DBInconsistent(format!("Missing block: {}", root))),
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
        BlockIterator::owned(self.store.clone(), self.state.read().clone(), slot)
    }

    /// Iterates in reverse (highest to lowest slot) through all block roots from `slot` through to
    /// genesis.
    ///
    /// Returns `None` for roots prior to genesis or when there is an error reading from `Store`.
    ///
    /// Contains duplicate roots when skip slots are encountered.
    pub fn rev_iter_block_roots(&self, slot: Slot) -> BlockRootsIterator<T::EthSpec, T::Store> {
        BlockRootsIterator::owned(self.store.clone(), self.state.read().clone(), slot)
    }

    /// Iterates in reverse (highest to lowest slot) through all state roots from `slot` through to
    /// genesis.
    ///
    /// Returns `None` for roots prior to genesis or when there is an error reading from `Store`.
    pub fn rev_iter_state_roots(&self, slot: Slot) -> StateRootsIterator<T::EthSpec, T::Store> {
        StateRootsIterator::owned(self.store.clone(), self.state.read().clone(), slot)
    }

    /// Returns the block at the given root, if any.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn get_block(&self, block_root: &Hash256) -> Result<Option<BeaconBlock>, Error> {
        Ok(self.store.get(block_root)?)
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

        if self.state.read().slot < present_slot {
            let mut state = self.state.write();

            // If required, transition the new state to the present slot.
            for _ in state.slot.as_u64()..present_slot.as_u64() {
                // Ensure the next epoch state caches are built in case of an epoch transition.
                state.build_committee_cache(RelativeEpoch::Next, spec)?;

                per_slot_processing(&mut *state, spec)?;
            }

            state.build_all_caches(spec)?;
        }

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
    /// Information is read from the present `beacon_state` shuffling, only information from the
    /// present epoch is available.
    pub fn block_proposer(&self, slot: Slot) -> Result<usize, Error> {
        // Ensures that the present state has been advanced to the present slot, skipping slots if
        // blocks are not present.
        self.catchup_state()?;

        // TODO: permit lookups of the proposer at any slot.
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
    ///
    /// Attests to the canonical chain.
    pub fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, Error> {
        let state = self.state.read();
        let head_block_root = self.head().beacon_block_root;
        let head_block_slot = self.head().beacon_block.slot;

        self.produce_attestation_data_for_block(shard, head_block_root, head_block_slot, &*state)
    }

    /// Produce an `AttestationData` that attests to the chain denoted by `block_root` and `state`.
    ///
    /// Permits attesting to any arbitrary chain. Generally, the `produce_attestation_data`
    /// function should be used as it attests to the canonical chain.
    pub fn produce_attestation_data_for_block(
        &self,
        shard: u64,
        head_block_root: Hash256,
        head_block_slot: Slot,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<AttestationData, Error> {
        // Collect some metrics.
        self.metrics.attestation_production_requests.inc();
        let timer = self.metrics.attestation_production_times.start_timer();

        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let current_epoch_start_slot = state.current_epoch().start_slot(slots_per_epoch);

        // The `target_root` is the root of the first block of the current epoch.
        //
        // The `state` does not know the root of the block for it's current slot (it only knows
        // about blocks from prior slots). This creates an edge-case when the state is on the first
        // slot of the epoch -- we're unable to obtain the `target_root` because it is not a prior
        // root.
        //
        // This edge case is handled in two ways:
        //
        // - If the head block is on the same slot as the state, we use it's root.
        // - Otherwise, assume the current slot has been skipped and use the block root from the
        // prior slot.
        //
        // For all other cases, we simply read the `target_root` from `state.latest_block_roots`.
        let target_root = if state.slot == current_epoch_start_slot {
            if head_block_slot == current_epoch_start_slot {
                head_block_root
            } else {
                *state.get_block_root(current_epoch_start_slot - 1)?
            }
        } else {
            *state.get_block_root(current_epoch_start_slot)?
        };

        let previous_crosslink_root =
            Hash256::from_slice(&state.get_current_crosslink(shard)?.tree_hash_root());

        // Collect some metrics.
        self.metrics.attestation_production_successes.inc();
        timer.observe_duration();

        Ok(AttestationData {
            beacon_block_root: head_block_root,
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

        // Retrieve the attestation's state from `store` if necessary.
        let attestation_state = match attestation.data.beacon_block_root == self.canonical_head.read().beacon_block_root {
            true => Some(self.state.read().clone()),
            false => match self.store.get::<BeaconBlock>(&attestation.data.beacon_block_root) {
                Ok(Some(block)) => match self.store.get::<BeaconState<T::EthSpec>>(&block.state_root) {
                    Ok(state) => state,
                    _ => None
                },
                _ => None
            }
        };

        if let Some(state) = attestation_state {
            let indexed_attestation = common::convert_to_indexed(&state, &attestation)?;
            per_block_processing::verify_indexed_attestation(&state, &indexed_attestation, &self.spec)?;
            self.fork_choice.process_attestation(&state, &attestation);
        }

        let result = self
            .op_pool
            .insert_attestation(attestation, &*self.state.read(), &self.spec);

        timer.observe_duration();

        if result.is_ok() {
            self.metrics.attestation_processing_successes.inc();
        }

        // TODO: process attestation. Please consider:
        //
        //  - Because a block was not added to the op pool does not mean it's invalid (it might
        //  just be old).
        //  - The attestation should be rejected if we don't know the block (ideally it should be
        //  queued, but this may be overkill).
        //  - The attestation _must_ be validated against it's state before being added to fork
        //  choice.
        //  - You can avoid verifying some attestations by first checking if they're a latest
        //  message. This would involve expanding the `LmdGhost` API.

        result
    }

    /// Accept some deposit and queue it for inclusion in an appropriate block.
    pub fn process_deposit(
        &self,
        deposit: Deposit,
    ) -> Result<DepositInsertStatus, DepositValidationError> {
        self.op_pool.insert_deposit(deposit)
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
        self.metrics.block_processing_requests.inc();
        let timer = self.metrics.block_processing_times.start_timer();

        let finalized_slot = self
            .state
            .read()
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        if block.slot <= finalized_slot {
            return Ok(BlockProcessingOutcome::FinalizedSlot);
        }

        if block.slot == 0 {
            return Ok(BlockProcessingOutcome::GenesisBlock);
        }

        let block_root = block.block_header().canonical_root();

        if block_root == self.genesis_block_root {
            return Ok(BlockProcessingOutcome::GenesisBlock);
        }

        let present_slot = self
            .read_slot_clock()
            .ok_or_else(|| Error::UnableToReadSlot)?;

        if block.slot > present_slot {
            return Ok(BlockProcessingOutcome::FutureSlot {
                present_slot,
                block_slot: block.slot,
            });
        }

        if self.store.exists::<BeaconBlock>(&block_root)? {
            return Ok(BlockProcessingOutcome::BlockIsAlreadyKnown);
        }

        // Load the blocks parent block from the database, returning invalid if that block is not
        // found.
        let parent_block_root = block.previous_block_root;
        let parent_block: BeaconBlock = match self.store.get(&parent_block_root)? {
            Some(previous_block_root) => previous_block_root,
            None => {
                return Ok(BlockProcessingOutcome::ParentUnknown {
                    parent: parent_block_root,
                });
            }
        };

        // Load the parent blocks state from the database, returning an error if it is not found.
        // It is an error because if know the parent block we should also know the parent state.
        let parent_state_root = parent_block.state_root;
        let parent_state = self
            .store
            .get(&parent_state_root)?
            .ok_or_else(|| Error::DBInconsistent(format!("Missing state {}", parent_state_root)))?;

        // Transition the parent state to the block slot.
        let mut state: BeaconState<T::EthSpec> = parent_state;
        for _ in state.slot.as_u64()..block.slot.as_u64() {
            per_slot_processing(&mut state, &self.spec)?;
        }

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        // Apply the received block to its parent state (which has been transitioned into this
        // slot).
        match per_block_processing(&mut state, &block, &self.spec) {
            Err(BlockProcessingError::BeaconStateError(e)) => {
                return Err(Error::BeaconStateError(e))
            }
            Err(e) => return Ok(BlockProcessingOutcome::PerBlockProcessingError(e)),
            _ => {}
        }

        let state_root = state.canonical_root();

        if block.state_root != state_root {
            return Ok(BlockProcessingOutcome::StateRootMismatch);
        }

        // Store the block and state.
        self.store.put(&block_root, &block)?;
        self.store.put(&state_root, &state)?;

        // Register the new block with the fork choice service.
        self.fork_choice.process_block(&state, &block, block_root)?;

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

        Ok(BlockProcessingOutcome::Processed { block_root })
    }

    /// Produce a new block at the present slot.
    ///
    /// The produced block will not be inherently valid, it must be signed by a block producer.
    /// Block signing is out of the scope of this function and should be done by a separate program.
    pub fn produce_block(
        &self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState<T::EthSpec>), BlockProductionError> {
        let state = self.state.read().clone();
        let slot = self
            .read_slot_clock()
            .ok_or_else(|| BlockProductionError::UnableToReadSlot)?;

        self.produce_block_on_state(state, slot, randao_reveal)
    }

    /// Produce a block for some `slot` upon the given `state`.
    ///
    /// Typically the `self.produce_block()` function should be used, instead of calling this
    /// function directly. This function is useful for purposefully creating forks or blocks at
    /// non-current slots.
    ///
    /// The given state will be advanced to the given `produce_at_slot`, then a block will be
    /// produced at that slot height.
    pub fn produce_block_on_state(
        &self,
        mut state: BeaconState<T::EthSpec>,
        produce_at_slot: Slot,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState<T::EthSpec>), BlockProductionError> {
        self.metrics.block_production_requests.inc();
        let timer = self.metrics.block_production_times.start_timer();

        // If required, transition the new state to the present slot.
        while state.slot < produce_at_slot {
            per_slot_processing(&mut state, &self.spec)?;
        }

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        let previous_block_root = if state.slot > 0 {
            *state
                .get_block_root(state.slot - 1)
                .map_err(|_| BlockProductionError::UnableToGetBlockRootFromState)?
        } else {
            state.latest_block_header.canonical_root()
        };

        let mut graffiti: [u8; 32] = [0; 32];
        graffiti.copy_from_slice(GRAFFITI.as_bytes());

        let (proposer_slashings, attester_slashings) =
            self.op_pool.get_slashings(&state, &self.spec);

        let mut block = BeaconBlock {
            slot: state.slot,
            previous_block_root,
            state_root: Hash256::zero(), // Updated after the state is calculated.
            signature: Signature::empty_signature(), // To be completed by a validator.
            body: BeaconBlockBody {
                randao_reveal,
                // TODO: replace with real data.
                eth1_data: Eth1Data {
                    deposit_count: 0,
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                },
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations: self.op_pool.get_attestations(&state, &self.spec),
                deposits: self.op_pool.get_deposits(&state, &self.spec),
                voluntary_exits: self.op_pool.get_voluntary_exits(&state, &self.spec),
                transfers: self.op_pool.get_transfers(&state, &self.spec),
            },
        };

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

        // Determine the root of the block that is the head of the chain.
        let beacon_block_root = self.fork_choice.find_head(&self)?;

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

            let old_finalized_epoch = self.head().beacon_state.finalized_epoch;
            let new_finalized_epoch = beacon_state.finalized_epoch;
            let finalized_root = beacon_state.finalized_root;

            // Never revert back past a finalized epoch.
            if new_finalized_epoch < old_finalized_epoch {
                Err(Error::RevertedFinalizedEpoch {
                    previous_epoch: old_finalized_epoch,
                    new_epoch: new_finalized_epoch,
                })
            } else {
                self.update_canonical_head(CheckPoint {
                    beacon_block: beacon_block,
                    beacon_block_root,
                    beacon_state,
                    beacon_state_root,
                })?;

                if new_finalized_epoch != old_finalized_epoch {
                    self.after_finalization(old_finalized_epoch, finalized_root)?;
                }

                Ok(())
            }
        } else {
            Ok(())
        }
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

    /// Called after `self` has had a new block finalized.
    ///
    /// Performs pruning and finality-based optimizations.
    fn after_finalization(
        &self,
        old_finalized_epoch: Epoch,
        finalized_block_root: Hash256,
    ) -> Result<(), Error> {
        let finalized_block = self
            .store
            .get::<BeaconBlock>(&finalized_block_root)?
            .ok_or_else(|| Error::MissingBeaconBlock(finalized_block_root))?;

        let new_finalized_epoch = finalized_block.slot.epoch(T::EthSpec::slots_per_epoch());

        if new_finalized_epoch < old_finalized_epoch {
            Err(Error::RevertedFinalizedEpoch {
                previous_epoch: old_finalized_epoch,
                new_epoch: new_finalized_epoch,
            })
        } else {
            self.fork_choice
                .process_finalization(&finalized_block, finalized_block_root)?;

            Ok(())
        }
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
