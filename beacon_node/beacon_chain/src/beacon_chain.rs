use crate::checkpoint::CheckPoint;
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use crate::fork_choice::{Error as ForkChoiceError, ForkChoice};
use crate::iter::{ReverseBlockRootIterator, ReverseStateRootIterator};
use crate::metrics::Metrics;
use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};
use lmd_ghost::LmdGhost;
use log::trace;
use operation_pool::DepositInsertStatus;
use operation_pool::{OperationPool, PersistedOperationPool};
use parking_lot::{RwLock, RwLockReadGuard};
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use state_processing::per_block_processing::errors::{
    AttesterSlashingValidationError, DepositValidationError, ExitValidationError,
    ProposerSlashingValidationError, TransferValidationError,
};
use state_processing::{
    common, per_block_processing, per_block_processing_without_verifying_block_signature,
    per_slot_processing, BlockProcessingError,
};
use std::sync::Arc;
use store::iter::{BlockRootsIterator, StateRootsIterator};
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

#[derive(Debug, PartialEq)]
pub enum AttestationProcessingOutcome {
    Processed,
    UnknownHeadBlock { beacon_block_root: Hash256 },
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
    /// Stores a "snapshot" of the chain at the time the head-of-the-chain block was received.
    canonical_head: RwLock<CheckPoint<T::EthSpec>>,
    /// The same state from `self.canonical_head`, but updated at the start of each slot with a
    /// skip slot if no block is received. This is effectively a cache that avoids repeating calls
    /// to `per_slot_processing`.
    state: RwLock<BeaconState<T::EthSpec>>,
    /// The root of the genesis block.
    pub genesis_block_root: Hash256,
    /// A state-machine that is updated with information from the network and chooses a canonical
    /// head block.
    pub fork_choice: ForkChoice<T>,
    /// Stores metrics about this `BeaconChain`.
    pub metrics: Metrics,
    /// Logging to CLI, etc.
    log: Logger,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Instantiate a new Beacon Chain, from genesis.
    pub fn from_genesis(
        store: Arc<T::Store>,
        slot_clock: T::SlotClock,
        mut genesis_state: BeaconState<T::EthSpec>,
        mut genesis_block: BeaconBlock<T::EthSpec>,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<Self, Error> {
        genesis_state.build_all_caches(&spec)?;

        let genesis_state_root = genesis_state.canonical_root();
        store.put(&genesis_state_root, &genesis_state)?;

        genesis_block.state_root = genesis_state_root;

        let genesis_block_root = genesis_block.block_header().canonical_root();
        store.put(&genesis_block_root, &genesis_block)?;

        // Also store the genesis block under the `ZERO_HASH` key.
        let genesis_block_root = genesis_block.canonical_root();
        store.put(&Hash256::zero(), &genesis_block)?;

        let canonical_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            genesis_block_root,
            genesis_state.clone(),
            genesis_state_root,
        ));

        info!(log, "BeaconChain init";
              "genesis_validator_count" => genesis_state.validators.len(),
              "genesis_state_root" => format!("{}", genesis_state_root),
              "genesis_block_root" => format!("{}", genesis_block_root),
        );

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
            log,
        })
    }

    /// Attempt to load an existing instance from the given `store`.
    pub fn from_store(
        store: Arc<T::Store>,
        spec: ChainSpec,
        log: Logger,
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

        let last_finalized_root = p.canonical_head.beacon_state.finalized_checkpoint.root;
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
            log,
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
    pub fn get_block_bodies(
        &self,
        roots: &[Hash256],
    ) -> Result<Vec<BeaconBlockBody<T::EthSpec>>, Error> {
        let bodies: Result<Vec<_>, _> = roots
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

    /// Iterates through all the `BeaconBlock` roots and slots, first returning
    /// `self.head().beacon_block` then all prior blocks until either genesis or if the database
    /// fails to return a prior block.
    ///
    /// Returns duplicate roots for skip-slots.
    ///
    /// Iterator returns `(Hash256, Slot)`.
    ///
    /// ## Note
    ///
    /// Because this iterator starts at the `head` of the chain (viz., the best block), the first slot
    /// returned may be earlier than the wall-clock slot.
    pub fn rev_iter_block_roots(
        &self,
        slot: Slot,
    ) -> ReverseBlockRootIterator<T::EthSpec, T::Store> {
        let state = &self.head().beacon_state;
        let block_root = self.head().beacon_block_root;
        let block_slot = state.slot;

        let iter = BlockRootsIterator::owned(self.store.clone(), state.clone(), slot);

        ReverseBlockRootIterator::new((block_root, block_slot), iter)
    }

    /// Iterates through all the `BeaconState` roots and slots, first returning
    /// `self.head().beacon_state` then all prior states until either genesis or if the database
    /// fails to return a prior state.
    ///
    /// Iterator returns `(Hash256, Slot)`.
    ///
    /// ## Note
    ///
    /// Because this iterator starts at the `head` of the chain (viz., the best block), the first slot
    /// returned may be earlier than the wall-clock slot.
    pub fn rev_iter_state_roots(
        &self,
        slot: Slot,
    ) -> ReverseStateRootIterator<T::EthSpec, T::Store> {
        let state = &self.head().beacon_state;
        let state_root = self.head().beacon_state_root;
        let state_slot = state.slot;

        let iter = StateRootsIterator::owned(self.store.clone(), state.clone(), slot);

        ReverseStateRootIterator::new((state_root, state_slot), iter)
    }

    /// Returns the block at the given root, if any.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn get_block(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<BeaconBlock<T::EthSpec>>, Error> {
        Ok(self.store.get(block_root)?)
    }

    /// Returns a read-lock guarded `BeaconState` which is the `canonical_head` that has been
    /// updated to match the current slot clock.
    pub fn speculative_state(&self) -> Result<RwLockReadGuard<BeaconState<T::EthSpec>>, Error> {
        // TODO: ensure the state has done a catch-up.

        Ok(self.state.read())
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
    /// Information is retrieved from the present `beacon_state.validators`.
    pub fn validator_index(&self, pubkey: &PublicKey) -> Option<usize> {
        for (i, validator) in self.head().beacon_state.validators.iter().enumerate() {
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
    pub fn validator_attestation_slot_and_shard(
        &self,
        validator_index: usize,
    ) -> Result<Option<(Slot, u64)>, BeaconStateError> {
        trace!(
            "BeaconChain::validator_attestation_slot_and_shard: validator_index: {}",
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
        let target = Checkpoint {
            epoch: state.current_epoch(),
            root: target_root,
        };

        let parent_crosslink = state.get_current_crosslink(shard)?;
        let crosslink = Crosslink {
            shard,
            parent_root: Hash256::from_slice(&parent_crosslink.tree_hash_root()),
            start_epoch: parent_crosslink.end_epoch,
            end_epoch: std::cmp::min(
                target.epoch,
                parent_crosslink.end_epoch + self.spec.max_epochs_per_crosslink,
            ),
            data_root: Hash256::zero(),
        };

        // Collect some metrics.
        self.metrics.attestation_production_successes.inc();
        timer.observe_duration();

        Ok(AttestationData {
            beacon_block_root: head_block_root,
            source: state.current_justified_checkpoint.clone(),
            target,
            crosslink,
        })
    }

    /// Accept a new attestation from the network.
    ///
    /// If valid, the attestation is added to the `op_pool` and aggregated with another attestation
    /// if possible.
    pub fn process_attestation(
        &self,
        attestation: Attestation<T::EthSpec>,
    ) -> Result<AttestationProcessingOutcome, Error> {
        // From the store, load the attestation's "head block".
        //
        // An honest validator would have set this block to be the head of the chain (i.e., the
        // result of running fork choice).
        if let Some(attestation_head_block) = self
            .store
            .get::<BeaconBlock<T::EthSpec>>(&attestation.data.beacon_block_root)?
        {
            // Attempt to process the attestation using the `self.head()` state.
            //
            // This is purely an effort to avoid loading a `BeaconState` unnecessarily from the DB.
            let optional_outcome: Option<Result<AttestationProcessingOutcome, Error>> = {
                // Take a read lock on the head beacon state.
                //
                // The purpose of this whole `let processed ...` block is to ensure that the read
                // lock is dropped if we don't end up using the head beacon state.
                let state = &self.head().beacon_state;

                // If it turns out that the attestation was made using the head state, then there
                // is no need to load a state from the database to process the attestation.
                if state.current_epoch() == attestation_head_block.epoch()
                    && (state
                        .get_block_root(attestation_head_block.slot)
                        .map(|root| *root == attestation.data.beacon_block_root)
                        .unwrap_or_else(|_| false)
                        || attestation.data.beacon_block_root == self.head().beacon_block_root)
                {
                    // The head state is able to be used to validate this attestation. No need to load
                    // anything from the database.
                    Some(self.process_attestation_for_state_and_block(
                        attestation.clone(),
                        state,
                        &attestation_head_block,
                    ))
                } else {
                    None
                }
            };

            // TODO: we could try and see if the "speculative state" (e.g., self.state) can support
            // this, without needing to load it from the db.

            if let Some(outcome) = optional_outcome {
                outcome
            } else {
                // The state required to verify this attestation must be loaded from the database.
                let mut state: BeaconState<T::EthSpec> = self
                    .store
                    .get(&attestation_head_block.state_root)?
                    .ok_or_else(|| Error::MissingBeaconState(attestation_head_block.state_root))?;

                // Ensure the state loaded from the database matches the state of the attestation
                // head block.
                for _ in state.slot.as_u64()..attestation_head_block.slot.as_u64() {
                    per_slot_processing(&mut state, &self.spec)?;
                }

                self.process_attestation_for_state_and_block(
                    attestation,
                    &state,
                    &attestation_head_block,
                )
            }
        } else {
            // Reject any block where we have not processed `attestation.data.beacon_block_root`.
            //
            // This is likely overly restrictive, we could store the attestation for later
            // processing.
            warn!(
                self.log,
                "Dropping attestation for unknown block";
                "block" => format!("{}", attestation.data.beacon_block_root)
            );
            Ok(AttestationProcessingOutcome::UnknownHeadBlock {
                beacon_block_root: attestation.data.beacon_block_root,
            })
        }
    }

    fn process_attestation_for_state_and_block(
        &self,
        attestation: Attestation<T::EthSpec>,
        state: &BeaconState<T::EthSpec>,
        _head_block: &BeaconBlock<T::EthSpec>,
    ) -> Result<AttestationProcessingOutcome, Error> {
        self.metrics.attestation_processing_requests.inc();
        let timer = self.metrics.attestation_processing_times.start_timer();

        if self
            .fork_choice
            .should_process_attestation(state, &attestation)?
        {
            // TODO: check validation.
            let indexed_attestation = common::get_indexed_attestation(state, &attestation)?;
            per_block_processing::is_valid_indexed_attestation(
                state,
                &indexed_attestation,
                &self.spec,
            )?;
            self.fork_choice.process_attestation(&state, &attestation)?;
        }

        let result = self
            .op_pool
            .insert_attestation(attestation, state, &self.spec);

        timer.observe_duration();

        if result.is_ok() {
            self.metrics.attestation_processing_successes.inc();
        }

        result
            .map(|_| AttestationProcessingOutcome::Processed)
            .map_err(|e| Error::AttestationValidationError(e))
    }

    /// Accept some deposit and queue it for inclusion in an appropriate block.
    pub fn process_deposit(
        &self,
        index: u64,
        deposit: Deposit,
    ) -> Result<DepositInsertStatus, DepositValidationError> {
        self.op_pool.insert_deposit(index, deposit)
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
        attester_slashing: AttesterSlashing<T::EthSpec>,
    ) -> Result<(), AttesterSlashingValidationError> {
        self.op_pool
            .insert_attester_slashing(attester_slashing, &*self.state.read(), &self.spec)
    }

    /// Accept some block and attempt to add it to block DAG.
    ///
    /// Will accept blocks from prior slots, however it will reject any block from a future slot.
    pub fn process_block(
        &self,
        block: BeaconBlock<T::EthSpec>,
    ) -> Result<BlockProcessingOutcome, Error> {
        self.metrics.block_processing_requests.inc();
        let timer = self.metrics.block_processing_times.start_timer();

        let finalized_slot = self
            .state
            .read()
            .finalized_checkpoint
            .epoch
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

        if self.store.exists::<BeaconBlock<T::EthSpec>>(&block_root)? {
            return Ok(BlockProcessingOutcome::BlockIsAlreadyKnown);
        }

        // Load the blocks parent block from the database, returning invalid if that block is not
        // found.
        let parent_block: BeaconBlock<T::EthSpec> = match self.store.get(&block.parent_root)? {
            Some(block) => block,
            None => {
                return Ok(BlockProcessingOutcome::ParentUnknown {
                    parent: block.parent_root,
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
        if let Err(e) = self.fork_choice.process_block(&state, &block, block_root) {
            error!(
                self.log,
                "fork choice failed to process_block";
                "error" => format!("{:?}", e),
                "block_root" =>  format!("{}", block_root),
                "block_slot" => format!("{}", block.slot)
            )
        }

        // Execute the fork choice algorithm, enthroning a new head if discovered.
        //
        // Note: in the future we may choose to run fork-choice less often, potentially based upon
        // some heuristic around number of attestations seen for the block.
        if let Err(e) = self.fork_choice() {
            error!(
                self.log,
                "fork choice failed to find head";
                "error" => format!("{:?}", e)
            )
        };

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
    ) -> Result<(BeaconBlock<T::EthSpec>, BeaconState<T::EthSpec>), BlockProductionError> {
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
    ) -> Result<(BeaconBlock<T::EthSpec>, BeaconState<T::EthSpec>), BlockProductionError> {
        self.metrics.block_production_requests.inc();
        let timer = self.metrics.block_production_times.start_timer();

        // If required, transition the new state to the present slot.
        while state.slot < produce_at_slot {
            per_slot_processing(&mut state, &self.spec)?;
        }

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        let parent_root = if state.slot > 0 {
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
            parent_root,
            state_root: Hash256::zero(), // Updated after the state is calculated.
            signature: Signature::empty_signature(), // To be completed by a validator.
            body: BeaconBlockBody {
                randao_reveal,
                // TODO: replace with real data.
                eth1_data: Eth1Data {
                    deposit_count: state.eth1_data.deposit_count,
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                },
                graffiti,
                proposer_slashings: proposer_slashings.into(),
                attester_slashings: attester_slashings.into(),
                attestations: self.op_pool.get_attestations(&state, &self.spec).into(),
                deposits: self.op_pool.get_deposits(&state).into(),
                voluntary_exits: self.op_pool.get_voluntary_exits(&state, &self.spec).into(),
                transfers: self.op_pool.get_transfers(&state, &self.spec).into(),
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

            let beacon_block: BeaconBlock<T::EthSpec> = self
                .store
                .get(&beacon_block_root)?
                .ok_or_else(|| Error::MissingBeaconBlock(beacon_block_root))?;

            let beacon_state_root = beacon_block.state_root;
            let beacon_state: BeaconState<T::EthSpec> = self
                .store
                .get(&beacon_state_root)?
                .ok_or_else(|| Error::MissingBeaconState(beacon_state_root))?;

            let previous_slot = self.head().beacon_block.slot;
            let new_slot = beacon_block.slot;

            // If we switched to a new chain (instead of building atop the present chain).
            if self.head().beacon_block_root != beacon_block.parent_root {
                self.metrics.fork_choice_reorg_count.inc();
                warn!(
                    self.log,
                    "Beacon chain re-org";
                    "previous_slot" => previous_slot,
                    "new_slot" => new_slot
                );
            } else {
                info!(
                    self.log,
                    "new head block";
                    "justified_root" => format!("{}", beacon_state.current_justified_checkpoint.root),
                    "finalized_root" => format!("{}", beacon_state.finalized_checkpoint.root),
                    "root" => format!("{}", beacon_block_root),
                    "slot" => new_slot,
                );
            };

            let old_finalized_epoch = self.head().beacon_state.finalized_checkpoint.epoch;
            let new_finalized_epoch = beacon_state.finalized_checkpoint.epoch;
            let finalized_root = beacon_state.finalized_checkpoint.root;

            // Never revert back past a finalized epoch.
            if new_finalized_epoch < old_finalized_epoch {
                Err(Error::RevertedFinalizedEpoch {
                    previous_epoch: old_finalized_epoch,
                    new_epoch: new_finalized_epoch,
                })
            } else {
                self.update_canonical_head(CheckPoint {
                    beacon_block,
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
            .get::<BeaconBlock<T::EthSpec>>(&finalized_block_root)?
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
        Ok(!self
            .store
            .exists::<BeaconBlock<T::EthSpec>>(beacon_block_root)?)
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
            let beacon_block_root = last_slot.beacon_block.parent_root;

            if beacon_block_root == Hash256::zero() {
                break; // Genesis has been reached.
            }

            let beacon_block: BeaconBlock<T::EthSpec> =
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
