use crate::checkpoint::CheckPoint;
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use crate::fork_choice::{Error as ForkChoiceError, ForkChoice};
use crate::iter::{ReverseBlockRootIterator, ReverseStateRootIterator};
use crate::metrics;
use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};
use eth2_hashing::hash;
use lmd_ghost::LmdGhost;
use operation_pool::DepositInsertStatus;
use operation_pool::{OperationPool, PersistedOperationPool};
use parking_lot::{RwLock, RwLockReadGuard};
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use state_processing::per_block_processing::{
    errors::{
        AttestationValidationError, AttesterSlashingValidationError, DepositValidationError,
        ExitValidationError, ProposerSlashingValidationError, TransferValidationError,
    },
    verify_attestation_for_state, VerifySignatures,
};
use state_processing::{
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
};
use std::sync::Arc;
use std::time::Duration;
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
    UnknownHeadBlock {
        beacon_block_root: Hash256,
    },
    /// The attestation is attesting to a state that is later than itself. (Viz., attesting to the
    /// future).
    AttestsToFutureState {
        state: Slot,
        attestation: Slot,
    },
    /// The slot is finalized, no need to import.
    FinalizedSlot {
        attestation: Epoch,
        finalized: Epoch,
    },
    Invalid(AttestationValidationError),
}

/// Effectively a `Cow<BeaconState>`, however when it is `Borrowed` it holds a `RwLockReadGuard` (a
/// read-lock on some read/write-locked state).
///
/// Only has a small subset of the functionality of a `std::borrow::Cow`.
pub enum BeaconStateCow<'a, T: EthSpec> {
    Borrowed(RwLockReadGuard<'a, CheckPoint<T>>),
    Owned(BeaconState<T>),
}

impl<'a, T: EthSpec> BeaconStateCow<'a, T> {
    pub fn maybe_as_mut_ref(&mut self) -> Option<&mut BeaconState<T>> {
        match self {
            BeaconStateCow::Borrowed(_) => None,
            BeaconStateCow::Owned(ref mut state) => Some(state),
        }
    }
}

impl<'a, T: EthSpec> std::ops::Deref for BeaconStateCow<'a, T> {
    type Target = BeaconState<T>;

    fn deref(&self) -> &BeaconState<T> {
        match self {
            BeaconStateCow::Borrowed(checkpoint) => &checkpoint.beacon_state,
            BeaconStateCow::Owned(state) => &state,
        }
    }
}

pub trait BeaconChainTypes: Send + Sync + 'static {
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
    /// The root of the genesis block.
    pub genesis_block_root: Hash256,
    /// A state-machine that is updated with information from the network and chooses a canonical
    /// head block.
    pub fork_choice: ForkChoice<T>,
    /// Logging to CLI, etc.
    log: Logger,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Instantiate a new Beacon Chain, from genesis.
    pub fn from_genesis(
        store: Arc<T::Store>,
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

        // Slot clock
        let slot_clock = T::SlotClock::from_eth2_genesis(
            spec.genesis_slot,
            genesis_state.genesis_time,
            Duration::from_millis(spec.milliseconds_per_slot),
        )
        .ok_or_else(|| Error::SlotClockDidNotStart)?;

        info!(log, "Beacon chain initialized from genesis";
              "validator_count" => genesis_state.validators.len(),
              "state_root" => format!("{}", genesis_state_root),
              "block_root" => format!("{}", genesis_block_root),
        );

        Ok(Self {
            spec,
            slot_clock,
            op_pool: OperationPool::new(),
            canonical_head,
            genesis_block_root,
            fork_choice: ForkChoice::new(store.clone(), &genesis_block, genesis_block_root),
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

        let state = &p.canonical_head.beacon_state;

        let slot_clock = T::SlotClock::from_eth2_genesis(
            spec.genesis_slot,
            state.genesis_time,
            Duration::from_millis(spec.milliseconds_per_slot),
        )
        .ok_or_else(|| Error::SlotClockDidNotStart)?;

        let last_finalized_root = p.canonical_head.beacon_state.finalized_checkpoint.root;
        let last_finalized_block = &p.canonical_head.beacon_block;

        let op_pool = p.op_pool.into_operation_pool(state, &spec);

        info!(log, "Beacon chain initialized from store";
              "head_root" => format!("{}", p.canonical_head.beacon_block_root),
              "head_epoch" => format!("{}", p.canonical_head.beacon_block.slot.epoch(T::EthSpec::slots_per_epoch())),
              "finalized_root" => format!("{}", last_finalized_root),
              "finalized_epoch" => format!("{}", last_finalized_block.slot.epoch(T::EthSpec::slots_per_epoch())),
        );

        Ok(Some(BeaconChain {
            spec,
            slot_clock,
            fork_choice: ForkChoice::new(store.clone(), last_finalized_block, last_finalized_root),
            op_pool,
            canonical_head: RwLock::new(p.canonical_head),
            genesis_block_root: p.genesis_block_root,
            store,
            log,
        }))
    }

    /// Attempt to save this instance to `self.store`.
    pub fn persist(&self) -> Result<(), Error> {
        let timer = metrics::start_timer(&metrics::PERSIST_CHAIN);

        let p: PersistedBeaconChain<T> = PersistedBeaconChain {
            canonical_head: self.canonical_head.read().clone(),
            op_pool: PersistedOperationPool::from_operation_pool(&self.op_pool),
            genesis_block_root: self.genesis_block_root,
        };

        let key = Hash256::from_slice(&BEACON_CHAIN_DB_KEY.as_bytes());
        self.store.put(&key, &p)?;

        metrics::stop_timer(timer);

        Ok(())
    }

    /// Returns the slot _right now_ according to `self.slot_clock`. Returns `Err` if the slot is
    /// unavailable.
    ///
    /// The slot might be unavailable due to an error with the system clock, or if the present time
    /// is before genesis (i.e., a negative slot).
    pub fn slot(&self) -> Result<Slot, Error> {
        self.slot_clock.now().ok_or_else(|| Error::UnableToReadSlot)
    }

    /// Returns the epoch _right now_ according to `self.slot_clock`. Returns `Err` if the epoch is
    /// unavailable.
    ///
    /// The epoch might be unavailable due to an error with the system clock, or if the present time
    /// is before genesis (i.e., a negative epoch).
    pub fn epoch(&self) -> Result<Epoch, Error> {
        self.slot()
            .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
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

    /// Iterates across all `(block_root, slot)` pairs from the head of the chain (inclusive) to
    /// the earliest reachable ancestor (may or may not be genesis).
    ///
    /// ## Notes
    ///
    /// `slot` always decreases by `1`.
    /// - Skipped slots contain the root of the closest prior
    ///     non-skipped slot (identical to the way they are stored in `state.block_roots`) .
    /// - Iterator returns `(Hash256, Slot)`.
    /// - As this iterator starts at the `head` of the chain (viz., the best block), the first slot
    ///     returned may be earlier than the wall-clock slot.
    pub fn rev_iter_block_roots(&self) -> ReverseBlockRootIterator<T::EthSpec, T::Store> {
        let state = &self.head().beacon_state;
        let block_root = self.head().beacon_block_root;
        let block_slot = state.slot;

        let iter = BlockRootsIterator::owned(self.store.clone(), state.clone());

        ReverseBlockRootIterator::new((block_root, block_slot), iter)
    }

    /// Iterates across all `(state_root, slot)` pairs from the head of the chain (inclusive) to
    /// the earliest reachable ancestor (may or may not be genesis).
    ///
    /// ## Notes
    ///
    /// `slot` always decreases by `1`.
    /// - Iterator returns `(Hash256, Slot)`.
    /// - As this iterator starts at the `head` of the chain (viz., the best block), the first slot
    ///     returned may be earlier than the wall-clock slot.
    pub fn rev_iter_state_roots(&self) -> ReverseStateRootIterator<T::EthSpec, T::Store> {
        let state = &self.head().beacon_state;
        let state_root = self.head().beacon_state_root;
        let state_slot = state.slot;

        let iter = StateRootsIterator::owned(self.store.clone(), state.clone());

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

    /// Returns a read-lock guarded `CheckPoint` struct for reading the head (as chosen by the
    /// fork-choice rule).
    ///
    /// It is important to note that the `beacon_state` returned may not match the present slot. It
    /// is the state as it was when the head block was received, which could be some slots prior to
    /// now.
    pub fn head<'a>(&'a self) -> RwLockReadGuard<'a, CheckPoint<T::EthSpec>> {
        self.canonical_head.read()
    }

    /// Returns the `BeaconState` at the given slot.
    ///
    /// May return:
    ///
    ///  - A new state loaded from the database (for states prior to the head)
    ///  - A reference to the head state (note: this keeps a read lock on the head, try to use
    ///  sparingly).
    ///  - The head state, but with skipped slots (for states later than the head).
    ///
    ///  Returns `None` when the state is not found in the database or there is an error skipping
    ///  to a future state.
    pub fn state_at_slot(&self, slot: Slot) -> Result<BeaconStateCow<T::EthSpec>, Error> {
        let head_state = &self.head().beacon_state;

        if slot == head_state.slot {
            Ok(BeaconStateCow::Borrowed(self.head()))
        } else if slot > head_state.slot {
            let head_state_slot = head_state.slot;
            let mut state = head_state.clone();
            drop(head_state);
            while state.slot < slot {
                match per_slot_processing(&mut state, &self.spec) {
                    Ok(()) => (),
                    Err(e) => {
                        warn!(
                            self.log,
                            "Unable to load state at slot";
                            "error" => format!("{:?}", e),
                            "head_slot" => head_state_slot,
                            "requested_slot" => slot
                        );
                        return Err(Error::NoStateForSlot(slot));
                    }
                };
            }
            Ok(BeaconStateCow::Owned(state))
        } else {
            let state_root = self
                .rev_iter_state_roots()
                .find(|(_root, s)| *s == slot)
                .map(|(root, _slot)| root)
                .ok_or_else(|| Error::NoStateForSlot(slot))?;

            Ok(BeaconStateCow::Owned(
                self.store
                    .get(&state_root)?
                    .ok_or_else(|| Error::NoStateForSlot(slot))?,
            ))
        }
    }

    /// Returns the `BeaconState` the current slot (viz., `self.slot()`).
    ///
    ///  - A reference to the head state (note: this keeps a read lock on the head, try to use
    ///  sparingly).
    ///  - The head state, but with skipped slots (for states later than the head).
    ///
    ///  Returns `None` when there is an error skipping to a future state or the slot clock cannot
    ///  be read.
    pub fn state_now(&self) -> Result<BeaconStateCow<T::EthSpec>, Error> {
        self.state_at_slot(self.slot()?)
    }

    /// Returns the slot of the highest block in the canonical chain.
    pub fn best_slot(&self) -> Slot {
        self.canonical_head.read().beacon_block.slot
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

    /// Reads the slot clock (see `self.read_slot_clock()` and returns the number of slots since
    /// genesis.
    pub fn slots_since_genesis(&self) -> Option<SlotHeight> {
        let now = self.slot().ok()?;
        let genesis_slot = self.spec.genesis_slot;

        if now < genesis_slot {
            None
        } else {
            Some(SlotHeight::from(now.as_u64() - genesis_slot.as_u64()))
        }
    }

    /// Returns the block proposer for a given slot.
    ///
    /// Information is read from the present `beacon_state` shuffling, only information from the
    /// present epoch is available.
    pub fn block_proposer(&self, slot: Slot) -> Result<usize, Error> {
        let epoch = |slot: Slot| slot.epoch(T::EthSpec::slots_per_epoch());
        let head_state = &self.head().beacon_state;

        let mut state = if epoch(slot) == epoch(head_state.slot) {
            BeaconStateCow::Borrowed(self.head())
        } else {
            self.state_at_slot(slot)?
        };

        if let Some(state) = state.maybe_as_mut_ref() {
            state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;
        }

        if epoch(state.slot) != epoch(slot) {
            return Err(Error::InvariantViolated(format!(
                "Epochs in consistent in proposer lookup: state: {}, requested: {}",
                epoch(state.slot),
                epoch(slot)
            )));
        }

        state
            .get_beacon_proposer_index(slot, RelativeEpoch::Current, &self.spec)
            .map_err(Into::into)
    }

    /// Returns the attestation slot and shard for a given validator index.
    ///
    /// Information is read from the current state, so only information from the present and prior
    /// epoch is available.
    pub fn validator_attestation_slot_and_shard(
        &self,
        validator_index: usize,
        epoch: Epoch,
    ) -> Result<Option<(Slot, u64)>, Error> {
        let as_epoch = |slot: Slot| slot.epoch(T::EthSpec::slots_per_epoch());
        let head_state = &self.head().beacon_state;

        let mut state = if epoch == as_epoch(head_state.slot) {
            BeaconStateCow::Borrowed(self.head())
        } else {
            self.state_at_slot(epoch.start_slot(T::EthSpec::slots_per_epoch()))?
        };

        if let Some(state) = state.maybe_as_mut_ref() {
            state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;
        }

        if as_epoch(state.slot) != epoch {
            return Err(Error::InvariantViolated(format!(
                "Epochs in consistent in attestation duties lookup: state: {}, requested: {}",
                as_epoch(state.slot),
                epoch
            )));
        }

        if let Some(attestation_duty) =
            state.get_attestation_duties(validator_index, RelativeEpoch::Current)?
        {
            Ok(Some((attestation_duty.slot, attestation_duty.shard)))
        } else {
            Ok(None)
        }
    }

    /// Produce an `AttestationData` that is valid for the given `slot` `shard`.
    ///
    /// Always attests to the canonical chain.
    pub fn produce_attestation_data(
        &self,
        shard: u64,
        slot: Slot,
    ) -> Result<AttestationData, Error> {
        let state = self.state_at_slot(slot)?;

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
        metrics::inc_counter(&metrics::ATTESTATION_PRODUCTION_REQUESTS);
        let timer = metrics::start_timer(&metrics::ATTESTATION_PRODUCTION_TIMES);

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
        metrics::inc_counter(&metrics::ATTESTATION_PRODUCTION_SUCCESSES);
        metrics::stop_timer(timer);

        Ok(AttestationData {
            beacon_block_root: head_block_root,
            source: state.current_justified_checkpoint.clone(),
            target,
            crosslink,
        })
    }

    /// Accept a new, potentially invalid attestation from the network.
    ///
    /// If valid, the attestation is added to `self.op_pool` and `self.fork_choice`.
    ///
    /// Returns an `Ok(AttestationProcessingOutcome)` if the chain was able to make a determination
    /// about the `attestation` (whether it was invalid or not). Returns an `Err` if there was an
    /// error during this process and no determination was able to be made.
    ///
    /// ## Notes
    ///
    /// - Whilst the `attestation` is added to fork choice, the head is not updated. That must be
    /// done separately.
    pub fn process_attestation(
        &self,
        attestation: Attestation<T::EthSpec>,
    ) -> Result<AttestationProcessingOutcome, Error> {
        metrics::inc_counter(&metrics::ATTESTATION_PROCESSING_REQUESTS);
        let timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_TIMES);

        // From the store, load the attestation's "head block".
        //
        // An honest validator would have set this block to be the head of the chain (i.e., the
        // result of running fork choice).
        let result = if let Some(attestation_head_block) = self
            .store
            .get::<BeaconBlock<T::EthSpec>>(&attestation.data.beacon_block_root)?
        {
            // Attempt to process the attestation using the `self.head()` state.
            //
            // This is purely an effort to avoid loading a `BeaconState` unnecessarily from the DB.
            // Take a read lock on the head beacon state.
            let state = &self.head().beacon_state;

            // If it turns out that the attestation was made using the head state, then there
            // is no need to load a state from the database to process the attestation.
            //
            // Note: use the epoch of the target because it indicates which epoch the
            // attestation was created in. You cannot use the epoch of the head block, because
            // the block doesn't necessarily need to be in the same epoch as the attestation
            // (e.g., if there are skip slots between the epoch the block was created in and
            // the epoch for the attestation).
            //
            // This check also ensures that the slot for `data.beacon_block_root` is not higher
            // than `state.root` by ensuring that the block is in the history of `state`.
            if state.current_epoch() == attestation.data.target.epoch
                && (attestation.data.beacon_block_root == self.head().beacon_block_root
                    || state
                        .get_block_root(attestation_head_block.slot)
                        .map(|root| *root == attestation.data.beacon_block_root)
                        .unwrap_or_else(|_| false))
            {
                // The head state is able to be used to validate this attestation. No need to load
                // anything from the database.
                return self.process_attestation_for_state_and_block(
                    attestation.clone(),
                    state,
                    &attestation_head_block,
                );
            }

            // Ensure the read-lock from `self.head()` is dropped.
            //
            // This is likely unnecessary, however it remains as a reminder to ensure this lock
            // isn't hogged.
            std::mem::drop(state);

            // Use the `data.beacon_block_root` to load the state from the latest non-skipped
            // slot preceding the attestation's creation.
            //
            // This state is guaranteed to be in the same chain as the attestation, but it's
            // not guaranteed to be from the same slot or epoch as the attestation.
            let mut state: BeaconState<T::EthSpec> = self
                .store
                .get(&attestation_head_block.state_root)?
                .ok_or_else(|| Error::MissingBeaconState(attestation_head_block.state_root))?;

            // Ensure the state loaded from the database matches the state of the attestation
            // head block.
            //
            // The state needs to be advanced from the current slot through to the epoch in
            // which the attestation was created in. It would be an error to try and use
            // `state.get_attestation_data_slot(..)` because the state matching the
            // `data.beacon_block_root` isn't necessarily in a nearby epoch to the attestation
            // (e.g., if there were lots of skip slots since the head of the chain and the
            // epoch creation epoch).
            for _ in state.slot.as_u64()
                ..attestation
                    .data
                    .target
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch())
                    .as_u64()
            {
                per_slot_processing(&mut state, &self.spec)?;
            }

            state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

            let attestation_slot = state.get_attestation_data_slot(&attestation.data)?;

            // Reject any attestation where the `state` loaded from `data.beacon_block_root`
            // has a higher slot than the attestation.
            //
            // Permitting this would allow for attesters to vote on _future_ slots.
            if attestation_slot > state.slot {
                Ok(AttestationProcessingOutcome::AttestsToFutureState {
                    state: state.slot,
                    attestation: attestation_slot,
                })
            } else {
                self.process_attestation_for_state_and_block(
                    attestation,
                    &state,
                    &attestation_head_block,
                )
            }
        } else {
            // Drop any attestation where we have not processed `attestation.data.beacon_block_root`.
            //
            // This is likely overly restrictive, we could store the attestation for later
            // processing.
            warn!(
                self.log,
                "Dropped attestation for unknown block";
                "block" => format!("{}", attestation.data.beacon_block_root)
            );
            Ok(AttestationProcessingOutcome::UnknownHeadBlock {
                beacon_block_root: attestation.data.beacon_block_root,
            })
        };

        metrics::stop_timer(timer);

        if let Ok(AttestationProcessingOutcome::Processed) = &result {
            metrics::inc_counter(&metrics::ATTESTATION_PROCESSING_SUCCESSES);
        }

        result
    }

    /// Verifies the `attestation` against the `state` to which it is attesting.
    ///
    /// Updates fork choice with any new latest messages, but _does not_ find or update the head.
    ///
    /// ## Notes
    ///
    /// The given `state` must fulfil one of the following conditions:
    ///
    /// - `state` corresponds to the `block.state_root` identified by
    /// `attestation.data.beacon_block_root`. (Viz., `attestation` was created using `state`).
    /// - `state.slot` is in the same epoch as `data.target.epoch` and
    /// `attestation.data.beacon_block_root` is in the history of `state`.
    ///
    /// Additionally, `attestation.data.beacon_block_root` **must** be available to read in
    /// `self.store` _and_ be the root of the given `block`.
    ///
    /// If the given conditions are not fulfilled, the function may error or provide a false
    /// negative (indicating that a given `attestation` is invalid when it is was validly formed).
    fn process_attestation_for_state_and_block(
        &self,
        attestation: Attestation<T::EthSpec>,
        state: &BeaconState<T::EthSpec>,
        block: &BeaconBlock<T::EthSpec>,
    ) -> Result<AttestationProcessingOutcome, Error> {
        // Find the highest between:
        //
        // - The highest valid finalized epoch we've ever seen (i.e., the head).
        // - The finalized epoch that this attestation was created against.
        let finalized_epoch = std::cmp::max(
            self.head().beacon_state.finalized_checkpoint.epoch,
            state.finalized_checkpoint.epoch,
        );

        // A helper function to allow attestation processing to be metered.
        let verify_attestation_for_state = |state, attestation, spec, verify_signatures| {
            let timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_CORE);

            let result = verify_attestation_for_state(state, attestation, spec, verify_signatures);

            metrics::stop_timer(timer);
            result
        };

        if block.slot <= finalized_epoch.start_slot(T::EthSpec::slots_per_epoch()) {
            // Ignore any attestation where the slot of `data.beacon_block_root` is equal to or
            // prior to the finalized epoch.
            //
            // For any valid attestation if the `beacon_block_root` is prior to finalization, then
            // all other parameters (source, target, etc) must all be prior to finalization and
            // therefore no longer interesting.
            Ok(AttestationProcessingOutcome::FinalizedSlot {
                attestation: block.slot.epoch(T::EthSpec::slots_per_epoch()),
                finalized: finalized_epoch,
            })
        } else if let Err(e) =
            verify_attestation_for_state(state, &attestation, VerifySignatures::True, &self.spec)
        {
            warn!(
                self.log,
                "Invalid attestation";
                "state_epoch" => state.current_epoch(),
                "error" => format!("{:?}", e),
            );

            Ok(AttestationProcessingOutcome::Invalid(e))
        } else {
            // Provide the attestation to fork choice, updating the validator latest messages but
            // _without_ finding and updating the head.
            if let Err(e) = self
                .fork_choice
                .process_attestation(&state, &attestation, block)
            {
                error!(
                    self.log,
                    "Add attestation to fork choice failed";
                    "fork_choice_integrity" => format!("{:?}", self.fork_choice.verify_integrity()),
                    "beacon_block_root" =>  format!("{}", attestation.data.beacon_block_root),
                    "error" => format!("{:?}", e)
                );
                return Err(e.into());
            }

            // Provide the valid attestation to op pool, which may choose to retain the
            // attestation for inclusion in a future block.
            self.op_pool
                .insert_attestation(attestation, state, &self.spec)?;

            // Update the metrics.
            metrics::inc_counter(&metrics::ATTESTATION_PROCESSING_SUCCESSES);

            Ok(AttestationProcessingOutcome::Processed)
        }
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
        match self.state_now() {
            Ok(state) => self
                .op_pool
                .insert_voluntary_exit(exit, &*state, &self.spec),
            Err(e) => {
                error!(
                    &self.log,
                    "Unable to process voluntary exit";
                    "error" => format!("{:?}", e),
                    "reason" => "no state"
                );
                Ok(())
            }
        }
    }

    /// Accept some transfer and queue it for inclusion in an appropriate block.
    pub fn process_transfer(&self, transfer: Transfer) -> Result<(), TransferValidationError> {
        match self.state_now() {
            Ok(state) => self.op_pool.insert_transfer(transfer, &*state, &self.spec),
            Err(e) => {
                error!(
                    &self.log,
                    "Unable to process transfer";
                    "error" => format!("{:?}", e),
                    "reason" => "no state"
                );
                Ok(())
            }
        }
    }

    /// Accept some proposer slashing and queue it for inclusion in an appropriate block.
    pub fn process_proposer_slashing(
        &self,
        proposer_slashing: ProposerSlashing,
    ) -> Result<(), ProposerSlashingValidationError> {
        match self.state_now() {
            Ok(state) => {
                self.op_pool
                    .insert_proposer_slashing(proposer_slashing, &*state, &self.spec)
            }
            Err(e) => {
                error!(
                    &self.log,
                    "Unable to process proposer slashing";
                    "error" => format!("{:?}", e),
                    "reason" => "no state"
                );
                Ok(())
            }
        }
    }

    /// Accept some attester slashing and queue it for inclusion in an appropriate block.
    pub fn process_attester_slashing(
        &self,
        attester_slashing: AttesterSlashing<T::EthSpec>,
    ) -> Result<(), AttesterSlashingValidationError> {
        match self.state_now() {
            Ok(state) => {
                self.op_pool
                    .insert_attester_slashing(attester_slashing, &*state, &self.spec)
            }
            Err(e) => {
                error!(
                    &self.log,
                    "Unable to process attester slashing";
                    "error" => format!("{:?}", e),
                    "reason" => "no state"
                );
                Ok(())
            }
        }
    }

    /// Accept some block and attempt to add it to block DAG.
    ///
    /// Will accept blocks from prior slots, however it will reject any block from a future slot.
    pub fn process_block(
        &self,
        block: BeaconBlock<T::EthSpec>,
    ) -> Result<BlockProcessingOutcome, Error> {
        metrics::inc_counter(&metrics::BLOCK_PROCESSING_REQUESTS);
        let full_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_TIMES);

        let finalized_slot = self
            .head()
            .beacon_state
            .finalized_checkpoint
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        if block.slot <= finalized_slot {
            return Ok(BlockProcessingOutcome::FinalizedSlot);
        }

        if block.slot == 0 {
            return Ok(BlockProcessingOutcome::GenesisBlock);
        }

        let block_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_BLOCK_ROOT);

        let block_root = block.canonical_root();

        metrics::stop_timer(block_root_timer);

        if block_root == self.genesis_block_root {
            return Ok(BlockProcessingOutcome::GenesisBlock);
        }

        let present_slot = self.slot()?;

        if block.slot > present_slot {
            return Ok(BlockProcessingOutcome::FutureSlot {
                present_slot,
                block_slot: block.slot,
            });
        }

        if self.store.exists::<BeaconBlock<T::EthSpec>>(&block_root)? {
            return Ok(BlockProcessingOutcome::BlockIsAlreadyKnown);
        }

        // Records the time taken to load the block and state from the database during block
        // processing.
        let db_read_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_READ);

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

        metrics::stop_timer(db_read_timer);

        let catchup_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CATCHUP_STATE);

        // Keep a list of any states that were "skipped" (block-less) in between the parent state
        // slot and the block slot. These will need to be stored in the database.
        let mut intermediate_states = vec![];

        // Transition the parent state to the block slot.
        let mut state: BeaconState<T::EthSpec> = parent_state;
        for i in state.slot.as_u64()..block.slot.as_u64() {
            if i > 0 {
                intermediate_states.push(state.clone());
            }
            per_slot_processing(&mut state, &self.spec)?;
        }

        metrics::stop_timer(catchup_timer);

        let committee_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_COMMITTEE);

        state.build_committee_cache(RelativeEpoch::Previous, &self.spec)?;
        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        metrics::stop_timer(committee_timer);

        let core_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CORE);

        // Apply the received block to its parent state (which has been transitioned into this
        // slot).
        match per_block_processing(
            &mut state,
            &block,
            Some(block_root),
            BlockSignatureStrategy::VerifyIndividual,
            &self.spec,
        ) {
            Err(BlockProcessingError::BeaconStateError(e)) => {
                return Err(Error::BeaconStateError(e))
            }
            Err(e) => return Ok(BlockProcessingOutcome::PerBlockProcessingError(e)),
            _ => {}
        }

        metrics::stop_timer(core_timer);

        let state_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_STATE_ROOT);

        let state_root = state.canonical_root();

        if block.state_root != state_root {
            return Ok(BlockProcessingOutcome::StateRootMismatch);
        }

        metrics::stop_timer(state_root_timer);

        let db_write_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_WRITE);

        // Store all the states between the parent block state and this blocks slot before storing
        // the final state.
        for (i, intermediate_state) in intermediate_states.iter().enumerate() {
            // To avoid doing an unnecessary tree hash, use the following (slot + 1) state's
            // state_roots field to find the root.
            let following_state = match intermediate_states.get(i + 1) {
                Some(following_state) => following_state,
                None => &state,
            };
            let intermediate_state_root =
                following_state.get_state_root(intermediate_state.slot)?;

            self.store
                .put(&intermediate_state_root, intermediate_state)?;
        }

        // Store the block and state.
        self.store.put(&block_root, &block)?;
        self.store.put(&state_root, &state)?;

        metrics::stop_timer(db_write_timer);

        let fork_choice_register_timer =
            metrics::start_timer(&metrics::BLOCK_PROCESSING_FORK_CHOICE_REGISTER);

        // Register the new block with the fork choice service.
        if let Err(e) = self.fork_choice.process_block(&state, &block, block_root) {
            error!(
                self.log,
                "Add block to fork choice failed";
                "fork_choice_integrity" => format!("{:?}", self.fork_choice.verify_integrity()),
                "block_root" =>  format!("{}", block_root),
                "error" => format!("{:?}", e),
            )
        }

        metrics::stop_timer(fork_choice_register_timer);

        let find_head_timer =
            metrics::start_timer(&metrics::BLOCK_PROCESSING_FORK_CHOICE_FIND_HEAD);

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

        metrics::stop_timer(find_head_timer);

        metrics::inc_counter(&metrics::BLOCK_PROCESSING_SUCCESSES);
        metrics::observe(
            &metrics::OPERATIONS_PER_BLOCK_ATTESTATION,
            block.body.attestations.len() as f64,
        );
        metrics::stop_timer(full_timer);

        Ok(BlockProcessingOutcome::Processed { block_root })
    }

    /// Produce a new block at the given `slot`.
    ///
    /// The produced block will not be inherently valid, it must be signed by a block producer.
    /// Block signing is out of the scope of this function and should be done by a separate program.
    pub fn produce_block(
        &self,
        randao_reveal: Signature,
        slot: Slot,
    ) -> Result<(BeaconBlock<T::EthSpec>, BeaconState<T::EthSpec>), BlockProductionError> {
        let state = self
            .state_at_slot(slot - 1)
            .map_err(|_| BlockProductionError::UnableToProduceAtSlot(slot))?;

        self.produce_block_on_state(state.clone(), slot, randao_reveal)
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
        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_REQUESTS);
        let timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_TIMES);

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
                eth1_data: Self::eth1_data_stub(&state),
                graffiti,
                proposer_slashings: proposer_slashings.into(),
                attester_slashings: attester_slashings.into(),
                attestations: self.op_pool.get_attestations(&state, &self.spec).into(),
                deposits: self.op_pool.get_deposits(&state).into(),
                voluntary_exits: self.op_pool.get_voluntary_exits(&state, &self.spec).into(),
                transfers: self.op_pool.get_transfers(&state, &self.spec).into(),
            },
        };

        per_block_processing(
            &mut state,
            &block,
            None,
            BlockSignatureStrategy::NoVerification,
            &self.spec,
        )?;

        let state_root = state.canonical_root();

        block.state_root = state_root;

        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_SUCCESSES);
        metrics::stop_timer(timer);

        Ok((block, state))
    }

    fn eth1_data_stub(state: &BeaconState<T::EthSpec>) -> Eth1Data {
        let current_epoch = state.current_epoch();
        let slots_per_voting_period = T::EthSpec::slots_per_eth1_voting_period() as u64;
        let current_voting_period: u64 = current_epoch.as_u64() / slots_per_voting_period;

        // TODO: confirm that `int_to_bytes32` is correct.
        let deposit_root = hash(&int_to_bytes32(current_voting_period));
        let block_hash = hash(&deposit_root);

        Eth1Data {
            deposit_root: Hash256::from_slice(&deposit_root),
            deposit_count: state.eth1_deposit_index,
            block_hash: Hash256::from_slice(&block_hash),
        }
    }

    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
    pub fn fork_choice(&self) -> Result<(), Error> {
        metrics::inc_counter(&metrics::FORK_CHOICE_REQUESTS);

        // Start fork choice metrics timer.
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_TIMES);

        // Determine the root of the block that is the head of the chain.
        let beacon_block_root = self.fork_choice.find_head(&self)?;

        // If a new head was chosen.
        let result = if beacon_block_root != self.head().beacon_block_root {
            metrics::inc_counter(&metrics::FORK_CHOICE_CHANGED_HEAD);

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
                metrics::inc_counter(&metrics::FORK_CHOICE_REORG_COUNT);
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
        };

        // End fork choice metrics timer.
        metrics::stop_timer(timer);

        if let Err(_) = result {
            metrics::inc_counter(&metrics::FORK_CHOICE_ERRORS);
        }

        result
    }

    /// Update the canonical head to `new_head`.
    fn update_canonical_head(&self, mut new_head: CheckPoint<T::EthSpec>) -> Result<(), Error> {
        let timer = metrics::start_timer(&metrics::UPDATE_HEAD_TIMES);

        new_head.beacon_state.build_all_caches(&self.spec)?;

        // Update the checkpoint that stores the head of the chain at the time it received the
        // block.
        *self.canonical_head.write() = new_head;

        // Save `self` to `self.store`.
        self.persist()?;

        metrics::stop_timer(timer);

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

            let finalized_state = self
                .store
                .get::<BeaconState<T::EthSpec>>(&finalized_block.state_root)?
                .ok_or_else(|| Error::MissingBeaconState(finalized_block.state_root))?;

            self.op_pool.prune_all(&finalized_state, &self.spec);

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

/// Returns `int` as little-endian bytes with a length of 32.
fn int_to_bytes32(int: u64) -> Vec<u8> {
    let mut vec = int.to_le_bytes().to_vec();
    vec.resize(32, 0);
    vec
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
