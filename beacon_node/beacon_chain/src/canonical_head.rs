//! This module provides all functionality for finding the canonical head, updating all necessary
//! components see (e.g. caches) and also maintaining a cached head block and state.
//!
//! ## Usage
//!
//! This module primarily provides the following:
//!
//! ### The `CanonicalHead` struct.
//!
//! Use this to access values from fork choice or from the `cached_head`, which is a cached block
//! and state from the last time fork choice was run.
//!
//! ### The `BeaconChain::recompute_head` method.
//!
//! This method was formally known as `BeaconChain::fork_choice`. It runs the fork choice
//! algorithm and then enshrines the result as the "canonical head". This involves updating the
//! `cached_head` so we always have the head block and state on hand. It also involves pruning
//! caches, sending SSE events, pruning the database and other things.
//!
//! ## The Three Rules
//!
//! There are three locks managed by this function:
//!
//! 1. `RwLock<BeaconForkChoice>`: Contains `proto_array` fork choice.
//! 2. `RwLock<CachedHead>`: Contains a cached block/state from the last run of `proto_array`.
//! 3. `Mutex<()>`: Is used to prevent concurrent execution of `BeaconChain::recompute_head`.
//!
//! The code in this module is designed specifically to prevent dead-locks through improper use of
//! these locks. There are three primary "rules" which, if followed, will prevent *other modules* from
//! causing dead-locks. The rules are:
//!
//! Rule #1: Never expose a *read or write* lock for `RwLock<BeaconForkChoice>` outside this module.
//! Rule #2: Functions external to this module may hold a *read lock* for `RwLock<CachedHead>`
//!          (never a write-lock).
//! Rule #3: Never expose a read or write lock for `Mutex<()>` outside this module.
//!
//! Since users can only access a `RwLock<CachedHead>` outside this function, they cannot interleave
//! the other two locks and cause a deadlock. Whilst we maintain the three rules, external functions
//! are dead-lock safe. Unfortunately, this module has no such guarantees, proceed with extreme
//! caution when managing locks in this module.
//!
//! The downside of Rule #1 is that we must re-expose every function on `BeaconForkChoice` on the
//! `CanonicalHead`. This prevents users from being able to hold and interleave the fork choice lock
//! with the canonical head lock. It's annoying when working on this file, but hopefully the
//! long-term safety benefits will pay off.
//!
//! Like all good rules, we have some exceptions. The first violates rule #1 via exposing the
//! `BlockProcessingForkChoiceWriteLock`. This exposes a write-lock on the `BeaconForkChoice` for
//! use during block processing. We *need* an exclusive lock here so we block access to fork choice
//! until we've written to the database; this helps prevent corruption. This struct is *clearly*
//! labelled for use only with block processing and it has a limited set of functionality to give
//! this module control over what happens with it.
//!
//! ## Design Considerations
//!
//! We separate the `BeaconForkChoice` and `CachedHead` into two `RwLocks` because we want to ensure
//! fast access to the `CachedHead`. If we were to put them both under the same lock, we would need
//! to take an exclusive write-lock on it in order to run `ForkChoice::get_head`. This can take tens
//! of milliseconds and would block all downstream functions that want to know the head block root.
//! This is unacceptable for fast-responding functions like the networking stack. Believe me, I have
//! tried to put them under the same lock and it did not work well :(

use crate::persisted_fork_choice::PersistedForkChoice;
use crate::{
    beacon_chain::{
        BeaconForkChoice, BeaconStore, BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT, FORK_CHOICE_DB_KEY,
    },
    block_times_cache::BlockTimesCache,
    events::ServerSentEventHandler,
    metrics,
    validator_monitor::{get_slot_delay_ms, timestamp_now},
    BeaconChain, BeaconChainError as Error, BeaconChainTypes, BeaconSnapshot, ForkChoiceError,
};
use eth2::types::{EventKind, SseChainReorg, SseFinalizedCheckpoint, SseHead, SseLateHead};
use fork_choice::{
    AttestationFromBlock, ExecutionStatus, ForkChoiceView, ForkchoiceUpdateParameters,
    InvalidationOperation, PayloadVerificationStatus, ProtoBlock,
};
use itertools::process_results;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use slog::{crit, debug, error, warn, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use store::{iter::StateRootsIterator, KeyValueStoreOp, StoreItem};
use task_executor::{JoinHandle, ShutdownReason};
use types::*;

/// Simple wrapper around `RwLock` that uses private visibility to prevent any other modules from
/// accessing the contained lock.
///
/// Whilst we prevent external functions from accessing this lock, we can guarantee them dead-lock
/// safety.
pub struct CanonicalHeadRwLock<T>(RwLock<T>);

impl<T> From<RwLock<T>> for CanonicalHeadRwLock<T> {
    fn from(rw_lock: RwLock<T>) -> Self {
        Self(rw_lock)
    }
}

impl<T> CanonicalHeadRwLock<T> {
    fn new(item: T) -> Self {
        Self::from(RwLock::new(item))
    }

    fn read(&self) -> RwLockReadGuard<T> {
        self.0.read()
    }

    fn write(&self) -> RwLockWriteGuard<T> {
        self.0.write()
    }
}

/// Provides a series of cached values from the last time `BeaconChain::recompute_head` was run.
///
/// This struct is designed to be cheap-to-clone, any large fields should be wrapped in an `Arc` (or
/// similar).
#[derive(Clone)]
pub struct CachedHead<E: EthSpec> {
    /// Provides the head block and state from the last time the head was updated.
    pub snapshot: Arc<BeaconSnapshot<E>>,
    /// The justified checkpoint as per `self.fork_choice`.
    ///
    /// This value may be distinct to the `self.head_snapshot.beacon_state.justified_checkpoint`.
    /// This value should be used over the beacon state value in practically all circumstances.
    justified_checkpoint: Checkpoint,
    /// The finalized checkpoint as per `self.fork_choice`.
    ///
    /// This value may be distinct to the `self.head_snapshot.beacon_state.finalized_checkpoint`.
    /// This value should be used over the beacon state value in practically all circumstances.
    finalized_checkpoint: Checkpoint,
    /// The `execution_payload.block_hash` of the block at the head of the chain. Set to `None`
    /// before Bellatrix.
    head_hash: Option<ExecutionBlockHash>,
    /// The `execution_payload.block_hash` of the finalized block. Set to `None` before Bellatrix.
    finalized_hash: Option<ExecutionBlockHash>,
}

impl<E: EthSpec> CachedHead<E> {
    /// Returns root of the block at the head of the beacon chain.
    pub fn head_block_root(&self) -> Hash256 {
        self.snapshot.beacon_block_root
    }

    /// Returns root of the `BeaconState` at the head of the beacon chain.
    ///
    /// ## Note
    ///
    /// This `BeaconState` has *not* been advanced to the current slot, it has the same slot as the
    /// head block.
    pub fn head_state_root(&self) -> Hash256 {
        self.snapshot.beacon_state_root()
    }

    /// Returns slot of the block at the head of the beacon chain.
    ///
    /// ## Notes
    ///
    /// This is *not* the current slot as per the system clock.
    pub fn head_slot(&self) -> Slot {
        self.snapshot.beacon_block.slot()
    }

    /// Returns the `Fork` from the `BeaconState` at the head of the chain.
    pub fn head_fork(&self) -> Fork {
        self.snapshot.beacon_state.fork()
    }

    /// Returns the randao mix for the block at the head of the chain.
    pub fn head_random(&self) -> Result<Hash256, BeaconStateError> {
        let state = &self.snapshot.beacon_state;
        let root = *state.get_randao_mix(state.current_epoch())?;
        Ok(root)
    }

    /// Returns the active validator count for the current epoch of the head state.
    ///
    /// Should only return `None` if the caches have not been build on the head state (this should
    /// never happen).
    pub fn active_validator_count(&self) -> Option<usize> {
        self.snapshot
            .beacon_state
            .get_cached_active_validator_indices(RelativeEpoch::Current)
            .map(|indices| indices.len())
            .ok()
    }

    /// Returns the finalized checkpoint, as determined by fork choice.
    ///
    /// ## Note
    ///
    /// This is *not* the finalized checkpoint of the `head_snapshot.beacon_state`, rather it is the
    /// best finalized checkpoint that has been observed by `self.fork_choice`. It is possible that
    /// the `head_snapshot.beacon_state` finalized value is earlier than the one returned here.
    pub fn finalized_checkpoint(&self) -> Checkpoint {
        self.finalized_checkpoint
    }

    /// Returns the justified checkpoint, as determined by fork choice.
    ///
    /// ## Note
    ///
    /// This is *not* the "current justified checkpoint" of the `head_snapshot.beacon_state`, rather
    /// it is the justified checkpoint in the view of `self.fork_choice`. It is possible that the
    /// `head_snapshot.beacon_state` justified value is different to, but not conflicting with, the
    /// one returned here.
    pub fn justified_checkpoint(&self) -> Checkpoint {
        self.justified_checkpoint
    }

    /// Returns the cached values of `ForkChoice::forkchoice_update_parameters`.
    ///
    /// Useful for supplying to the execution layer.
    pub fn forkchoice_update_parameters(&self) -> ForkchoiceUpdateParameters {
        ForkchoiceUpdateParameters {
            head_root: self.snapshot.beacon_block_root,
            head_hash: self.head_hash,
            finalized_hash: self.finalized_hash,
        }
    }
}

/// This struct provides a write-lock on the `BeaconForkChoice` is is **only for use during block
/// processing**.
///
/// It provides a limited set of functionality that is required for processing blocks and
/// maintaining consistency between the database and fork choice.
pub struct BlockProcessingForkChoiceWriteLock<'a, T: BeaconChainTypes> {
    fork_choice: RwLockWriteGuard<'a, BeaconForkChoice<T>>,
}

impl<'a, T: BeaconChainTypes> BlockProcessingForkChoiceWriteLock<'a, T> {
    /// Get a `ProtoBlock` from proto array. Contains a limited, but useful set of information about
    /// the block.
    pub fn get_block(&self, block_root: &Hash256) -> Option<ProtoBlock> {
        self.fork_choice.get_block(block_root)
    }

    /// Apply a block to fork choice.
    #[allow(clippy::too_many_arguments)]
    pub fn on_block<Payload: ExecPayload<T::EthSpec>>(
        &mut self,
        current_slot: Slot,
        block: BeaconBlockRef<T::EthSpec, Payload>,
        block_root: Hash256,
        block_delay: Duration,
        state: &BeaconState<T::EthSpec>,
        payload_verification_status: PayloadVerificationStatus,
        spec: &ChainSpec,
    ) -> Result<(), ForkChoiceError> {
        self.fork_choice.on_block(
            current_slot,
            block,
            block_root,
            block_delay,
            state,
            payload_verification_status,
            spec,
        )
    }

    /// Apply some attestations to fork choice.
    pub fn on_attestations(
        &mut self,
        current_slot: Slot,
        attestations: &[IndexedAttestation<T::EthSpec>],
        is_from_block: AttestationFromBlock,
    ) -> Result<(), ForkChoiceError> {
        for indexed_attestation in attestations {
            self.fork_choice
                .on_attestation(current_slot, indexed_attestation, is_from_block)?
        }
        Ok(())
    }

    /// Recompute the head of the beacon chain.
    ///
    /// ## Note
    ///
    /// Exposing this function means that the `canonical_head.fork_choice` can get ahead of
    /// `canonical_head.cached_head`! We deem this to be OK, it's required for use to achieve the
    /// `early_attester_cache` and we ensure that we make minimal assumptions about fork choice
    /// being at the same place as the `cached_head`.
    pub fn get_head(
        &mut self,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Hash256, ForkChoiceError> {
        self.fork_choice.get_head(current_slot, spec)
    }
}

/// Represents the "canonical head" of the beacon chain.
///
/// The `cached_head` is elected by the `fork_choice` algorithm contained in this struct.
///
/// There is no guarantee that the state of the `fork_choice` struct will always represent the
/// `cached_head` (i.e. we may call `fork_choice` *without* updating the cached values), however
/// there is a guarantee that the `cached_head` represents some past state of `fork_choice` (i.e.
/// `fork_choice` never lags *behind* the `cached_head`).
pub struct CanonicalHead<T: BeaconChainTypes> {
    /// Provides an in-memory representation of the non-finalized block tree and is used to run the
    /// fork choice algorithm and determine the canonical head.
    pub fork_choice: CanonicalHeadRwLock<BeaconForkChoice<T>>,
    /// Provides values cached from a previous execution of `self.fork_choice.get_head`.
    ///
    /// Although `self.fork_choice` might be slightly more advanced that this value, it is safe to
    /// consider that these values represent the "canonical head" of the beacon chain.
    pub cached_head: CanonicalHeadRwLock<CachedHead<T::EthSpec>>,
    /// A lock used to prevent concurrent runs of `BeaconChain::recompute_head`.
    ///
    /// This lock **should not be made public**, it should only be used inside this module.
    recompute_head_lock: Mutex<()>,
}

impl<T: BeaconChainTypes> CanonicalHead<T> {
    /// Instantiate `Self`.
    pub fn new(
        fork_choice: BeaconForkChoice<T>,
        snapshot: Arc<BeaconSnapshot<T::EthSpec>>,
    ) -> Result<Self, Error> {
        let fork_choice_view = fork_choice.cached_fork_choice_view();
        let forkchoice_update_params = fork_choice.get_forkchoice_update_parameters();
        let cached_head = CachedHead {
            snapshot,
            justified_checkpoint: fork_choice_view.justified_checkpoint,
            finalized_checkpoint: fork_choice_view.finalized_checkpoint,
            head_hash: forkchoice_update_params.head_hash,
            finalized_hash: forkchoice_update_params.finalized_hash,
        };

        Ok(Self {
            fork_choice: CanonicalHeadRwLock::new(fork_choice),
            cached_head: CanonicalHeadRwLock::new(cached_head),
            recompute_head_lock: Mutex::new(()),
        })
    }

    /// Load a persisted version of `BeaconForkChoice` from the `store` and restore `self` to that
    /// state.
    ///
    /// This is useful if some database corruption is expected and we wish to go back to our last
    /// save-point.
    pub(crate) fn restore_from_store(
        &self,
        // We don't actually *need* the block processing guard, but we pass it because the only
        // place that calls this function is block processing and we'll get a deadlock if it isn't
        // dropped before this function runs.
        block_processing_guard: BlockProcessingForkChoiceWriteLock<T>,
        store: &BeaconStore<T>,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        // Failing to drop this will result in a dead-lock.
        drop(block_processing_guard);

        let fork_choice = <BeaconChain<T>>::load_fork_choice(store.clone(), spec)?
            .ok_or(Error::MissingPersistedForkChoice)?;
        let fork_choice_view = fork_choice.cached_fork_choice_view();
        let beacon_block_root = fork_choice_view.head_block_root;
        let beacon_block = store
            .get_full_block(&beacon_block_root)?
            .ok_or(Error::MissingBeaconBlock(beacon_block_root))?;
        let beacon_state_root = beacon_block.state_root();
        let beacon_state = store
            .get_state(&beacon_state_root, Some(beacon_block.slot()))?
            .ok_or(Error::MissingBeaconState(beacon_state_root))?;

        let snapshot = BeaconSnapshot {
            beacon_block_root,
            beacon_block: Arc::new(beacon_block),
            beacon_state,
        };

        let fork_choice_view = fork_choice.cached_fork_choice_view();
        let forkchoice_update_params = fork_choice.get_forkchoice_update_parameters();
        let cached_head = CachedHead {
            snapshot: Arc::new(snapshot),
            justified_checkpoint: fork_choice_view.justified_checkpoint,
            finalized_checkpoint: fork_choice_view.finalized_checkpoint,
            head_hash: forkchoice_update_params.head_hash,
            finalized_hash: forkchoice_update_params.finalized_hash,
        };

        *self.fork_choice.write() = fork_choice;
        *self.cached_head.write() = cached_head;

        Ok(())
    }

    /// Only for use in block processing. Do not use this function unless you are *certain* you know
    /// what you are doing.
    ///
    /// See `BlockProcessingForkChoiceWriteLock` for more detail.
    pub(crate) fn block_processing_fork_choice_write_lock(
        &self,
    ) -> BlockProcessingForkChoiceWriteLock<T> {
        BlockProcessingForkChoiceWriteLock {
            fork_choice: self.fork_choice_write_lock(),
        }
    }

    /// Returns the execution status of the block at the head of the beacon chain.
    ///
    /// This will only return `Err` in the scenario where `self.fork_choice` has advanced
    /// significantly past the cached `head_snapshot`. In such a scenario is it likely prudent to
    /// run `BeaconChain::recompute_head` to update the cached values.
    pub fn head_execution_status(&self) -> Result<ExecutionStatus, Error> {
        let head_block_root = self.cached_head.read().head_block_root();
        self.fork_choice
            .read()
            .get_block_execution_status(&head_block_root)
            .ok_or(Error::HeadMissingFromForkChoice(head_block_root))
    }

    /// Returns a cloned `Arc` to `self.cached_head`.
    ///
    /// Takes a read-lock on `self.cached_head` for a short time (just long enough to clone an
    /// `Arc`).
    ///
    /// This function is safe to be public. (See "Rule #2")
    pub fn cached_head(&self) -> CachedHead<T::EthSpec> {
        self.cached_head.read().clone()
    }

    /// Access a write-lock for the cached head.
    ///
    /// This function **must not be made public**. (See "Rule #2")
    fn cached_head_write_lock(&self) -> RwLockWriteGuard<CachedHead<T::EthSpec>> {
        self.cached_head.write()
    }

    /// Access a read-lock for fork choice.
    ///
    /// This function **must not be made public**. (See "Rule #1")
    fn fork_choice_read_lock(&self) -> RwLockReadGuard<BeaconForkChoice<T>> {
        self.fork_choice.read()
    }

    /// Access a read-lock for fork choice.
    ///
    /// This function **must only be used in testing**. (See "Rule #1")
    pub fn fork_choice_read_lock_testing_only(&self) -> RwLockReadGuard<BeaconForkChoice<T>> {
        self.fork_choice_read_lock()
    }

    /// Access a write-lock for fork choice.
    ///
    /// This function **must not be made public**. (See "Rule #1")
    fn fork_choice_write_lock(&self) -> RwLockWriteGuard<BeaconForkChoice<T>> {
        self.fork_choice.write()
    }

    /// Access a write-lock for fork choice.
    ///
    /// This function **must only be used in testing**. (See "Rule #1")
    pub fn fork_choice_write_lock_testing_only(&self) -> RwLockWriteGuard<BeaconForkChoice<T>> {
        self.fork_choice_write_lock()
    }

    /// Update fork choice to inform it about a valid execution payload.
    ///
    /// Mutates fork choice.
    pub fn on_valid_execution_payload(&self, block_root: Hash256) -> Result<(), ForkChoiceError> {
        self.fork_choice_write_lock()
            .on_valid_execution_payload(block_root)
    }

    /// Update fork choice to inform it about an invalid execution payload.
    ///
    /// Mutates fork choice.
    pub fn on_invalid_execution_payload(
        &self,
        op: &InvalidationOperation,
    ) -> Result<(), ForkChoiceError> {
        self.fork_choice_write_lock()
            .on_invalid_execution_payload(op)
    }

    /// Returns `true` if fork choice is aware of a block with `block_root`.
    ///
    /// Does not mutate fork choice.
    pub fn contains_block(&self, block_root: &Hash256) -> bool {
        self.fork_choice_read_lock().contains_block(block_root)
    }

    /// Returns the `ProtoBlock` identified by `block_root`, if known to fork choice.
    ///
    /// Does not mutate fork choice.
    pub fn get_block(&self, block_root: &Hash256) -> Option<ProtoBlock> {
        self.fork_choice_read_lock().get_block(block_root)
    }

    /// Returns the `ExecutionStatus` for the `block_root`, if known to fork choice.
    ///
    /// Does not mutate fork choice.
    pub fn get_block_execution_status(&self, block_root: &Hash256) -> Option<ExecutionStatus> {
        self.fork_choice_read_lock()
            .get_block_execution_status(block_root)
    }

    /// Returns the `ProtoBlock` of the justified block.
    ///
    /// This *may not* be the same block as `self.cached_head.justified_checkpoint`, since it uses
    /// fork choice and it might be ahead of the cached head.
    ///
    /// Does not mutate fork choice.
    pub fn get_justified_block(&self) -> Result<ProtoBlock, ForkChoiceError> {
        self.fork_choice_read_lock().get_justified_block()
    }

    /// Returns `true` if some block with the given parameters is safe to be imported
    /// optimistically.
    ///
    /// Does not mutate fork choice.
    pub fn is_optimistic_candidate_block(
        &self,
        current_slot: Slot,
        block_slot: Slot,
        block_parent_root: &Hash256,
        spec: &ChainSpec,
    ) -> Result<bool, ForkChoiceError> {
        self.fork_choice_read_lock().is_optimistic_candidate_block(
            current_slot,
            block_slot,
            block_parent_root,
            spec,
        )
    }

    /// See `ForkChoice::is_optimistic_block` for documentation.
    ///
    /// Does not mutate fork choice.
    pub fn is_optimistic_block(&self, block_root: &Hash256) -> Result<bool, ForkChoiceError> {
        self.fork_choice_read_lock().is_optimistic_block(block_root)
    }

    /// See `ForkChoice::is_optimistic_block_no_fallback` for documentation.
    ///
    /// Does not mutate fork choice.
    pub fn is_optimistic_block_no_fallback(
        &self,
        block_root: &Hash256,
    ) -> Result<bool, ForkChoiceError> {
        self.fork_choice_read_lock()
            .is_optimistic_block_no_fallback(block_root)
    }

    /// Returns `true` if the `block_root` is a known descendant of the finalized block.
    ///
    /// The finalized block used is per fork choice and might be later than (but not conflicting
    /// with) `self.cached_head.finalized_checkpoint`.
    ///
    /// Does not mutate fork choice.
    pub fn is_descendant_of_finalized(&self, block_root: Hash256) -> bool {
        self.fork_choice_read_lock()
            .is_descendant_of_finalized(block_root)
    }

    /// Applies an attestation to fork choice.
    ///
    /// Mutates fork choice.
    pub fn on_attestation(
        &self,
        current_slot: Slot,
        attestation: &IndexedAttestation<T::EthSpec>,
        is_from_block: AttestationFromBlock,
    ) -> Result<(), ForkChoiceError> {
        self.fork_choice_write_lock()
            .on_attestation(current_slot, attestation, is_from_block)
    }

    /// Gets the ancestor of `block_root` at a slot equal to or less than `target_slot`, if any.
    ///
    /// Does not mutate fork choice.
    pub fn get_ancestor_at_or_below_slot(
        &self,
        block_root: &Hash256,
        target_slot: Slot,
    ) -> Option<Hash256> {
        self.fork_choice_read_lock()
            .proto_array()
            .core_proto_array()
            .iter_block_roots(block_root)
            .find(|(_, slot)| *slot <= target_slot)
            .map(|(block_root, _)| block_root)
    }

    /// Returns the core `ProtoArray` struct as JSON. Useful for the HTTP API.
    ///
    /// Does not mutate fork choice.
    pub fn proto_array_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(
            &self
                .fork_choice_read_lock()
                .proto_array()
                .core_proto_array(),
        )
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
    ///
    /// This method replaces the old `BeaconChain::fork_choice` method.
    pub async fn recompute_head_at_current_slot(self: &Arc<Self>) -> Result<(), Error> {
        let current_slot = self.slot()?;
        self.recompute_head_at_slot(current_slot).await
    }

    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
    ///
    /// The `current_slot` is specified rather than relying on the wall-clock slot. Using a
    /// different slot to the wall-clock can be useful for pushing fork choice into the next slot
    /// *just* before the start of the slot. This ensures that block production can use the correct
    /// head value without being delayed.
    pub async fn recompute_head_at_slot(self: &Arc<Self>, current_slot: Slot) -> Result<(), Error> {
        metrics::inc_counter(&metrics::FORK_CHOICE_REQUESTS);
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_TIMES);

        let chain = self.clone();
        match self
            .task_executor
            .spawn_blocking_handle(
                move || chain.recompute_head_at_slot_internal(current_slot),
                "recompute_head_internal",
            )
            .ok_or(Error::RuntimeShutdown)?
            .await
            .map_err(Error::TokioJoin)?
        {
            // Fork choice returned successfully and did not need to update the EL.
            Ok(None) => Ok(()),
            // Fork choice returned successfully and needed to update the EL. It has returned a
            // join-handle from when it spawned some async tasks. We should await those tasks.
            Ok(Some(join_handle)) => match join_handle.await {
                // The async task completed successfully.
                Ok(Some(())) => Ok(()),
                // The async task did not complete successfully since the runtime is shutting down.
                Ok(None) => {
                    debug!(
                        self.log,
                        "Did not update EL fork choice";
                        "info" => "shutting down"
                    );
                    Err(Error::RuntimeShutdown)
                }
                // The async task did not complete successfully, tokio returned an error.
                Err(e) => {
                    error!(
                        self.log,
                        "Did not update EL fork choice";
                        "error" => ?e
                    );
                    Err(Error::TokioJoin(e))
                }
            },
            // There was an error recomputing the head.
            Err(e) => {
                metrics::inc_counter(&metrics::FORK_CHOICE_ERRORS);
                Err(e)
            }
        }
    }

    /// A non-async (blocking) function which recomputes the canonical head and spawns async tasks.
    ///
    /// This function performs long-running, heavy-lifting tasks which should not be performed on
    /// the core `tokio` executor.
    fn recompute_head_at_slot_internal(
        self: &Arc<Self>,
        current_slot: Slot,
    ) -> Result<Option<JoinHandle<Option<()>>>, Error> {
        let recompute_head_lock = self.canonical_head.recompute_head_lock.lock();

        // Take a clone of the current ("old") head.
        let old_cached_head = self.canonical_head.cached_head();

        // Determine the current ("old") fork choice parameters.
        //
        // It is important to read the `fork_choice_view` from the cached head rather than from fork
        // choice, since the fork choice value might have changed between calls to this function. We
        // are interested in the changes since we last cached the head values, not since fork choice
        // was last run.
        let old_view = ForkChoiceView {
            head_block_root: old_cached_head.head_block_root(),
            justified_checkpoint: old_cached_head.justified_checkpoint(),
            finalized_checkpoint: old_cached_head.finalized_checkpoint(),
        };

        let mut fork_choice_write_lock = self.canonical_head.fork_choice_write_lock();

        // Recompute the current head via the fork choice algorithm.
        fork_choice_write_lock.get_head(current_slot, &self.spec)?;

        // Read the current head value from the fork choice algorithm.
        let new_view = fork_choice_write_lock.cached_fork_choice_view();

        // Downgrade the fork choice write-lock to a read lock, without allowing access to any
        // other writers.
        let fork_choice_read_lock = RwLockWriteGuard::downgrade(fork_choice_write_lock);

        // Check to ensure that the finalized block hasn't been marked as invalid. If it has,
        // shut down Lighthouse.
        let finalized_proto_block = fork_choice_read_lock.get_finalized_block()?;
        check_finalized_payload_validity(self, &finalized_proto_block)?;

        // Sanity check the finalized checkpoint.
        //
        // The new finalized checkpoint must be either equal to or better than the previous
        // finalized checkpoint.
        check_against_finality_reversion(&old_view, &new_view)?;

        let new_head_proto_block = fork_choice_read_lock
            .get_block(&new_view.head_block_root)
            .ok_or(Error::HeadBlockMissingFromForkChoice(
                new_view.head_block_root,
            ))?;

        // Do not allow an invalid block to become the head.
        //
        // This check avoids the following infinite loop:
        //
        // 1. A new block is set as the head.
        // 2. The EL is updated with the new head, and returns INVALID.
        // 3. We call `process_invalid_execution_payload` and it calls this function.
        // 4. This function elects an invalid block as the head.
        // 5. GOTO 2
        //
        // In theory, this function should never select an invalid head (i.e., step #3 is
        // impossible). However, this check is cheap.
        if new_head_proto_block.execution_status.is_invalid() {
            return Err(Error::HeadHasInvalidPayload {
                block_root: new_head_proto_block.root,
                execution_status: new_head_proto_block.execution_status,
            });
        }

        // Exit early if the head or justified/finalized checkpoints have not changed, there's
        // nothing to do.
        if new_view == old_view {
            debug!(
                self.log,
                "No change in canonical head";
                "head" => ?new_view.head_block_root
            );
            return Ok(None);
        }

        // Get the parameters to update the execution layer since either the head or some finality
        // parameters have changed.
        let new_forkchoice_update_parameters =
            fork_choice_read_lock.get_forkchoice_update_parameters();

        perform_debug_logging::<T>(&old_view, &new_view, &fork_choice_read_lock, &self.log);

        // Drop the read lock, it's no longer required and holding it any longer than necessary
        // will just cause lock contention.
        drop(fork_choice_read_lock);

        // If the head has changed, update `self.canonical_head`.
        let new_cached_head = if new_view.head_block_root != old_view.head_block_root {
            metrics::inc_counter(&metrics::FORK_CHOICE_CHANGED_HEAD);

            // Try and obtain the snapshot for `beacon_block_root` from the snapshot cache, falling
            // back to a database read if that fails.
            let new_snapshot = self
                .snapshot_cache
                .try_read_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
                .and_then(|snapshot_cache| {
                    snapshot_cache.get_cloned(
                        new_view.head_block_root,
                        CloneConfig::committee_caches_only(),
                    )
                })
                .map::<Result<_, Error>, _>(Ok)
                .unwrap_or_else(|| {
                    let beacon_block = self
                        .store
                        .get_full_block(&new_view.head_block_root)?
                        .ok_or(Error::MissingBeaconBlock(new_view.head_block_root))?;

                    let beacon_state_root = beacon_block.state_root();
                    let beacon_state: BeaconState<T::EthSpec> = self
                        .get_state(&beacon_state_root, Some(beacon_block.slot()))?
                        .ok_or(Error::MissingBeaconState(beacon_state_root))?;

                    Ok(BeaconSnapshot {
                        beacon_block: Arc::new(beacon_block),
                        beacon_block_root: new_view.head_block_root,
                        beacon_state,
                    })
                })
                .and_then(|mut snapshot| {
                    // Regardless of where we got the state from, attempt to build the committee
                    // caches.
                    snapshot
                        .beacon_state
                        .build_all_committee_caches(&self.spec)
                        .map_err(Into::into)
                        .map(|()| snapshot)
                })?;

            let new_cached_head = CachedHead {
                snapshot: Arc::new(new_snapshot),
                justified_checkpoint: new_view.justified_checkpoint,
                finalized_checkpoint: new_view.finalized_checkpoint,
                head_hash: new_forkchoice_update_parameters.head_hash,
                finalized_hash: new_forkchoice_update_parameters.finalized_hash,
            };

            let new_head = {
                // Now the new snapshot has been obtained, take a write-lock on the cached head so
                // we can update it quickly.
                let mut cached_head_write_lock = self.canonical_head.cached_head_write_lock();
                // Enshrine the new head as the canonical cached head.
                *cached_head_write_lock = new_cached_head;
                // Take a clone of the cached head for later use. It is cloned whilst
                // holding the write-lock to ensure we get exactly the head we just enshrined.
                cached_head_write_lock.clone()
            };

            // Clear the early attester cache in case it conflicts with `self.canonical_head`.
            self.early_attester_cache.clear();

            new_head
        } else {
            let mut cached_head_write_lock = self.canonical_head.cached_head_write_lock();

            let new_cached_head = CachedHead {
                // The head hasn't changed, take a relatively cheap `Arc`-clone of the existing
                // head.
                snapshot: old_cached_head.snapshot.clone(),
                justified_checkpoint: new_view.justified_checkpoint,
                finalized_checkpoint: new_view.finalized_checkpoint,
                head_hash: new_forkchoice_update_parameters.head_hash,
                finalized_hash: new_forkchoice_update_parameters.finalized_hash,
            };

            // Enshrine the new head as the canonical cached head. Whilst the head block hasn't
            // changed, the FFG checkpoints must have changed.
            *cached_head_write_lock = new_cached_head;

            // Take a clone of the cached head for later use. It is cloned whilst
            // holding the write-lock to ensure we get exactly the head we just enshrined.
            cached_head_write_lock.clone()
        };

        // Alias for readability.
        let new_snapshot = &new_cached_head.snapshot;
        let old_snapshot = &old_cached_head.snapshot;

        // If the head changed, perform some updates.
        if new_snapshot.beacon_block_root != old_snapshot.beacon_block_root {
            if let Err(e) =
                self.after_new_head(&old_cached_head, &new_cached_head, new_head_proto_block)
            {
                crit!(
                    self.log,
                    "Error updating canonical head";
                    "error" => ?e
                );
            }
        }

        // If the finalized checkpoint changed, perform some updates.
        if new_view.finalized_checkpoint != old_view.finalized_checkpoint {
            if let Err(e) =
                self.after_finalization(&new_cached_head, new_view, finalized_proto_block)
            {
                crit!(
                    self.log,
                    "Error updating finalization";
                    "error" => ?e
                );
            }
        }

        // The execution layer updates might attempt to take a write-lock on fork choice, so it's
        // important to ensure the fork-choice lock isn't being held.
        let el_update_handle =
            spawn_execution_layer_updates(self.clone(), new_forkchoice_update_parameters)?;

        // We have completed recomputing the head and it's now valid for another process to do the
        // same.
        drop(recompute_head_lock);

        Ok(Some(el_update_handle))
    }

    /// Perform updates to caches and other components after the canonical head has been changed.
    ///
    /// # Deadlock Warning
    ///
    /// Taking a write lock on the `self.canonical_head` in this function will result in a deadlock!
    /// This is because `Self::recompute_head_internal` will already be holding a read-lock.
    fn after_new_head(
        self: &Arc<Self>,
        old_cached_head: &CachedHead<T::EthSpec>,
        new_cached_head: &CachedHead<T::EthSpec>,
        new_head_proto_block: ProtoBlock,
    ) -> Result<(), Error> {
        let old_snapshot = &old_cached_head.snapshot;
        let new_snapshot = &new_cached_head.snapshot;

        // Detect and potentially report any re-orgs.
        let reorg_distance = detect_reorg(
            &old_snapshot.beacon_state,
            old_snapshot.beacon_block_root,
            &new_snapshot.beacon_state,
            new_snapshot.beacon_block_root,
            &self.spec,
            &self.log,
        );

        // Determine if the new head is in a later epoch to the previous head.
        let is_epoch_transition = old_snapshot
            .beacon_block
            .slot()
            .epoch(T::EthSpec::slots_per_epoch())
            < new_snapshot
                .beacon_state
                .slot()
                .epoch(T::EthSpec::slots_per_epoch());

        // These fields are used for server-sent events.
        let state_root = new_snapshot.beacon_state_root();
        let head_slot = new_snapshot.beacon_state.slot();
        let dependent_root = new_snapshot
            .beacon_state
            .proposer_shuffling_decision_root(self.genesis_block_root);
        let prev_dependent_root = new_snapshot
            .beacon_state
            .attester_shuffling_decision_root(self.genesis_block_root, RelativeEpoch::Current);

        // Update the snapshot cache with the latest head value.
        //
        // This *could* be done inside `recompute_head`, however updating the head on the snapshot
        // cache is not critical so we avoid placing it on a critical path. Note that this function
        // will not return an error if the update fails, it will just log an error.
        self.snapshot_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .map(|mut snapshot_cache| {
                snapshot_cache.update_head(new_snapshot.beacon_block_root);
            })
            .unwrap_or_else(|| {
                error!(
                    self.log,
                    "Failed to obtain cache write lock";
                    "lock" => "snapshot_cache",
                    "task" => "update head"
                );
            });

        observe_head_block_delays(
            &mut self.block_times_cache.write(),
            &new_head_proto_block,
            new_snapshot.beacon_block.message().proposer_index(),
            new_snapshot
                .beacon_block
                .message()
                .body()
                .graffiti()
                .as_utf8_lossy(),
            &self.slot_clock,
            self.event_handler.as_ref(),
            &self.log,
        );

        if is_epoch_transition || reorg_distance.is_some() {
            self.persist_head_and_fork_choice()?;
            self.op_pool.prune_attestations(self.epoch()?);
        }

        // Register server-sent-events for a new head.
        if let Some(event_handler) = self
            .event_handler
            .as_ref()
            .filter(|handler| handler.has_head_subscribers())
        {
            match (dependent_root, prev_dependent_root) {
                (Ok(current_duty_dependent_root), Ok(previous_duty_dependent_root)) => {
                    event_handler.register(EventKind::Head(SseHead {
                        slot: head_slot,
                        block: new_snapshot.beacon_block_root,
                        state: state_root,
                        current_duty_dependent_root,
                        previous_duty_dependent_root,
                        epoch_transition: is_epoch_transition,
                    }));
                }
                (Err(e), _) | (_, Err(e)) => {
                    warn!(
                        self.log,
                        "Unable to find dependent roots, cannot register head event";
                        "error" => ?e
                    );
                }
            }
        }

        // Register a server-sent-event for a reorg (if necessary).
        if let Some(depth) = reorg_distance {
            if let Some(event_handler) = self
                .event_handler
                .as_ref()
                .filter(|handler| handler.has_reorg_subscribers())
            {
                event_handler.register(EventKind::ChainReorg(SseChainReorg {
                    slot: head_slot,
                    depth: depth.as_u64(),
                    old_head_block: old_snapshot.beacon_block_root,
                    old_head_state: old_snapshot.beacon_state_root(),
                    new_head_block: new_snapshot.beacon_block_root,
                    new_head_state: new_snapshot.beacon_state_root(),
                    epoch: head_slot.epoch(T::EthSpec::slots_per_epoch()),
                }));
            }
        }

        Ok(())
    }

    /// Perform updates to caches and other components after the finalized checkpoint has been
    /// changed.
    ///
    /// # Deadlock Warning
    ///
    /// Taking a write lock on the `self.canonical_head` in this function will result in a deadlock!
    /// This is because `Self::recompute_head_internal` will already be holding a read-lock.
    fn after_finalization(
        self: &Arc<Self>,
        new_cached_head: &CachedHead<T::EthSpec>,
        new_view: ForkChoiceView,
        finalized_proto_block: ProtoBlock,
    ) -> Result<(), Error> {
        let new_snapshot = &new_cached_head.snapshot;

        self.op_pool
            .prune_all(&new_snapshot.beacon_state, self.epoch()?);

        self.observed_block_producers.write().prune(
            new_view
                .finalized_checkpoint
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch()),
        );

        self.snapshot_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .map(|mut snapshot_cache| {
                snapshot_cache.prune(new_view.finalized_checkpoint.epoch);
                debug!(
                    self.log,
                    "Snapshot cache pruned";
                    "new_len" => snapshot_cache.len(),
                    "remaining_roots" => ?snapshot_cache.beacon_block_roots(),
                );
            })
            .unwrap_or_else(|| {
                error!(
                    self.log,
                    "Failed to obtain cache write lock";
                    "lock" => "snapshot_cache",
                    "task" => "prune"
                );
            });

        // The store migration task requires the *state at the slot of the finalized epoch*,
        // rather than the state of the latest finalized block. These two values will only
        // differ when the first slot of the finalized epoch is a skip slot.
        //
        // Use the `StateRootsIterator` directly rather than `BeaconChain::state_root_at_slot`
        // to ensure we use the same state that we just set as the head.
        let new_finalized_slot = new_view
            .finalized_checkpoint
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let new_finalized_state_root = process_results(
            StateRootsIterator::new(&self.store, &new_snapshot.beacon_state),
            |mut iter| {
                iter.find_map(|(state_root, slot)| {
                    if slot == new_finalized_slot {
                        Some(state_root)
                    } else {
                        None
                    }
                })
            },
        )?
        .ok_or(Error::MissingFinalizedStateRoot(new_finalized_slot))?;

        self.store_migrator.process_finalization(
            new_finalized_state_root.into(),
            new_view.finalized_checkpoint,
            self.head_tracker.clone(),
        )?;

        self.attester_cache
            .prune_below(new_view.finalized_checkpoint.epoch);

        if let Some(event_handler) = self.event_handler.as_ref() {
            if event_handler.has_finalized_subscribers() {
                event_handler.register(EventKind::FinalizedCheckpoint(SseFinalizedCheckpoint {
                    epoch: new_view.finalized_checkpoint.epoch,
                    block: new_view.finalized_checkpoint.root,
                    // Provide the state root of the latest finalized block, rather than the
                    // specific state root at the first slot of the finalized epoch (which
                    // might be a skip slot).
                    state: finalized_proto_block.state_root,
                }));
            }
        }

        Ok(())
    }

    /// Return a database operation for writing fork choice to disk.
    pub fn persist_fork_choice_in_batch(&self) -> KeyValueStoreOp {
        Self::persist_fork_choice_in_batch_standalone(&self.canonical_head.fork_choice_read_lock())
    }

    /// Return a database operation for writing fork choice to disk.
    pub fn persist_fork_choice_in_batch_standalone(
        fork_choice: &BeaconForkChoice<T>,
    ) -> KeyValueStoreOp {
        let persisted_fork_choice = PersistedForkChoice {
            fork_choice: fork_choice.to_persisted(),
            fork_choice_store: fork_choice.fc_store().to_persisted(),
        };
        persisted_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY)
    }
}

/// Check to see if the `finalized_proto_block` has an invalid execution payload. If so, shut down
/// Lighthouse.
///
/// ## Notes
///
/// This function is called whilst holding a write-lock on the `canonical_head`. To ensure dead-lock
/// safety, **do not take any other locks inside this function**.
fn check_finalized_payload_validity<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    finalized_proto_block: &ProtoBlock,
) -> Result<(), Error> {
    if let ExecutionStatus::Invalid(block_hash) = finalized_proto_block.execution_status {
        crit!(
            chain.log,
            "Finalized block has an invalid payload";
            "msg" => "You must use the `--purge-db` flag to clear the database and restart sync. \
            You may be on a hostile network.",
            "block_hash" => ?block_hash
        );
        let mut shutdown_sender = chain.shutdown_sender();
        shutdown_sender
            .try_send(ShutdownReason::Failure(
                "Finalized block has an invalid execution payload.",
            ))
            .map_err(Error::InvalidFinalizedPayloadShutdownError)?;

        // Exit now, the node is in an invalid state.
        return Err(Error::InvalidFinalizedPayload {
            finalized_root: finalized_proto_block.root,
            execution_block_hash: block_hash,
        });
    }

    Ok(())
}

/// Check to ensure that the transition from `old_view` to `new_view` will not revert finality.
///
/// ## Notes
///
/// This function is called whilst holding a write-lock on the `canonical_head`. To ensure dead-lock
/// safety, **do not take any other locks inside this function**.
fn check_against_finality_reversion(
    old_view: &ForkChoiceView,
    new_view: &ForkChoiceView,
) -> Result<(), Error> {
    let finalization_equal = new_view.finalized_checkpoint == old_view.finalized_checkpoint;
    let finalization_advanced =
        new_view.finalized_checkpoint.epoch > old_view.finalized_checkpoint.epoch;

    if finalization_equal || finalization_advanced {
        Ok(())
    } else {
        Err(Error::RevertedFinalizedEpoch {
            old: old_view.finalized_checkpoint,
            new: new_view.finalized_checkpoint,
        })
    }
}

fn perform_debug_logging<T: BeaconChainTypes>(
    old_view: &ForkChoiceView,
    new_view: &ForkChoiceView,
    fork_choice: &BeaconForkChoice<T>,
    log: &Logger,
) {
    if new_view.head_block_root != old_view.head_block_root {
        debug!(
            log,
            "Fork choice updated head";
            "new_head_weight" => ?fork_choice
                .get_block_weight(&new_view.head_block_root),
            "new_head" => ?new_view.head_block_root,
            "old_head_weight" => ?fork_choice
                .get_block_weight(&old_view.head_block_root),
            "old_head" => ?old_view.head_block_root,
        )
    }
    if new_view.justified_checkpoint != old_view.justified_checkpoint {
        debug!(
            log,
            "Fork choice justified";
            "new_root" => ?new_view.justified_checkpoint.root,
            "new_epoch" => new_view.justified_checkpoint.epoch,
            "old_root" => ?old_view.justified_checkpoint.root,
            "old_epoch" => old_view.justified_checkpoint.epoch,
        )
    }
    if new_view.finalized_checkpoint != old_view.finalized_checkpoint {
        debug!(
            log,
            "Fork choice finalized";
            "new_root" => ?new_view.finalized_checkpoint.root,
            "new_epoch" => new_view.finalized_checkpoint.epoch,
            "old_root" => ?old_view.finalized_checkpoint.root,
            "old_epoch" => old_view.finalized_checkpoint.epoch,
        )
    }
}

fn spawn_execution_layer_updates<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    forkchoice_update_params: ForkchoiceUpdateParameters,
) -> Result<JoinHandle<Option<()>>, Error> {
    let current_slot = chain
        .slot_clock
        .now_or_genesis()
        .ok_or(Error::UnableToReadSlot)?;

    chain
        .task_executor
        .clone()
        .spawn_handle(
            async move {
                // Avoids raising an error before Bellatrix.
                //
                // See `Self::prepare_beacon_proposer` for more detail.
                if chain.slot_is_prior_to_bellatrix(current_slot + 1) {
                    return;
                }

                if let Err(e) = chain
                    .update_execution_engine_forkchoice(current_slot, forkchoice_update_params)
                    .await
                {
                    crit!(
                        chain.log,
                        "Failed to update execution head";
                        "error" => ?e
                    );
                }

                // Update the mechanism for preparing for block production on the execution layer.
                //
                // Performing this call immediately after `update_execution_engine_forkchoice_blocking`
                // might result in two calls to fork choice updated, one *without* payload attributes and
                // then a second *with* payload attributes.
                //
                // This seems OK. It's not a significant waste of EL<>CL bandwidth or resources, as far as I
                // know.
                if let Err(e) = chain.prepare_beacon_proposer(current_slot).await {
                    crit!(
                        chain.log,
                        "Failed to prepare proposers after fork choice";
                        "error" => ?e
                    );
                }
            },
            "update_el_forkchoice",
        )
        .ok_or(Error::RuntimeShutdown)
}

/// Attempt to detect if the new head is not on the same chain as the previous block
/// (i.e., a re-org).
///
/// Note: this will declare a re-org if we skip `SLOTS_PER_HISTORICAL_ROOT` blocks
/// between calls to fork choice without swapping between chains. This seems like an
/// extreme-enough scenario that a warning is fine.
fn detect_reorg<E: EthSpec>(
    old_state: &BeaconState<E>,
    old_block_root: Hash256,
    new_state: &BeaconState<E>,
    new_block_root: Hash256,
    spec: &ChainSpec,
    log: &Logger,
) -> Option<Slot> {
    let is_reorg = new_state
        .get_block_root(old_state.slot())
        .map_or(true, |root| *root != old_block_root);

    if is_reorg {
        let reorg_distance =
            match find_reorg_slot(old_state, old_block_root, new_state, new_block_root, spec) {
                Ok(slot) => old_state.slot().saturating_sub(slot),
                Err(e) => {
                    warn!(
                        log,
                        "Could not find re-org depth";
                        "error" => format!("{:?}", e),
                    );
                    return None;
                }
            };

        metrics::inc_counter(&metrics::FORK_CHOICE_REORG_COUNT);
        metrics::inc_counter(&metrics::FORK_CHOICE_REORG_COUNT_INTEROP);
        warn!(
            log,
            "Beacon chain re-org";
            "previous_head" => ?old_block_root,
            "previous_slot" => old_state.slot(),
            "new_head" => ?new_block_root,
            "new_slot" => new_state.slot(),
            "reorg_distance" => reorg_distance,
        );

        Some(reorg_distance)
    } else {
        None
    }
}

/// Iterate through the current chain to find the slot intersecting with the given beacon state.
/// The maximum depth this will search is `SLOTS_PER_HISTORICAL_ROOT`, and if that depth is reached
/// and no intersection is found, the finalized slot will be returned.
pub fn find_reorg_slot<E: EthSpec>(
    old_state: &BeaconState<E>,
    old_block_root: Hash256,
    new_state: &BeaconState<E>,
    new_block_root: Hash256,
    spec: &ChainSpec,
) -> Result<Slot, Error> {
    // The earliest slot for which the two chains may have a common history.
    let lowest_slot = std::cmp::min(new_state.slot(), old_state.slot());

    // Create an iterator across `$state`, assuming that the block at `$state.slot` has the
    // block root of `$block_root`.
    //
    // The iterator will be skipped until the next value returns `lowest_slot`.
    //
    // This is a macro instead of a function or closure due to the complex types invloved
    // in all the iterator wrapping.
    macro_rules! aligned_roots_iter {
        ($state: ident, $block_root: ident) => {
            std::iter::once(Ok(($state.slot(), $block_root)))
                .chain($state.rev_iter_block_roots(spec))
                .skip_while(|result| {
                    result
                        .as_ref()
                        .map_or(false, |(slot, _)| *slot > lowest_slot)
                })
        };
    }

    // Create iterators across old/new roots where iterators both start at the same slot.
    let mut new_roots = aligned_roots_iter!(new_state, new_block_root);
    let mut old_roots = aligned_roots_iter!(old_state, old_block_root);

    // Whilst *both* of the iterators are still returning values, try and find a common
    // ancestor between them.
    while let (Some(old), Some(new)) = (old_roots.next(), new_roots.next()) {
        let (old_slot, old_root) = old?;
        let (new_slot, new_root) = new?;

        // Sanity check to detect programming errors.
        if old_slot != new_slot {
            return Err(Error::InvalidReorgSlotIter { new_slot, old_slot });
        }

        if old_root == new_root {
            // A common ancestor has been found.
            return Ok(old_slot);
        }
    }

    // If no common ancestor is found, declare that the re-org happened at the previous
    // finalized slot.
    //
    // Sometimes this will result in the return slot being *lower* than the actual reorg
    // slot. However, assuming we don't re-org through a finalized slot, it will never be
    // *higher*.
    //
    // We provide this potentially-inaccurate-but-safe information to avoid onerous
    // database reads during times of deep reorgs.
    Ok(old_state
        .finalized_checkpoint()
        .epoch
        .start_slot(E::slots_per_epoch()))
}

fn observe_head_block_delays<E: EthSpec, S: SlotClock>(
    block_times_cache: &mut BlockTimesCache,
    head_block: &ProtoBlock,
    head_block_proposer_index: u64,
    head_block_graffiti: String,
    slot_clock: &S,
    event_handler: Option<&ServerSentEventHandler<E>>,
    log: &Logger,
) {
    let block_time_set_as_head = timestamp_now();
    let head_block_root = head_block.root;
    let head_block_slot = head_block.slot;

    // Calculate the total delay between the start of the slot and when it was set as head.
    let block_delay_total = get_slot_delay_ms(block_time_set_as_head, head_block_slot, slot_clock);

    // Do not write to the cache for blocks older than 2 epochs, this helps reduce writes to
    // the cache during sync.
    if block_delay_total < slot_clock.slot_duration() * 64 {
        block_times_cache.set_time_set_as_head(
            head_block_root,
            head_block_slot,
            block_time_set_as_head,
        );
    }

    // If a block comes in from over 4 slots ago, it is most likely a block from sync.
    let block_from_sync = block_delay_total > slot_clock.slot_duration() * 4;

    // Determine whether the block has been set as head too late for proper attestation
    // production.
    let late_head = block_delay_total >= slot_clock.unagg_attestation_production_delay();

    // Do not store metrics if the block was > 4 slots old, this helps prevent noise during
    // sync.
    if !block_from_sync {
        // Observe the total block delay. This is the delay between the time the slot started
        // and when the block was set as head.
        metrics::observe_duration(
            &metrics::BEACON_BLOCK_HEAD_SLOT_START_DELAY_TIME,
            block_delay_total,
        );

        // Observe the delay between when we imported the block and when we set the block as
        // head.
        let block_delays = block_times_cache.get_block_delays(
            head_block_root,
            slot_clock
                .start_of(head_block_slot)
                .unwrap_or_else(|| Duration::from_secs(0)),
        );

        metrics::observe_duration(
            &metrics::BEACON_BLOCK_OBSERVED_SLOT_START_DELAY_TIME,
            block_delays
                .observed
                .unwrap_or_else(|| Duration::from_secs(0)),
        );

        metrics::observe_duration(
            &metrics::BEACON_BLOCK_HEAD_IMPORTED_DELAY_TIME,
            block_delays
                .set_as_head
                .unwrap_or_else(|| Duration::from_secs(0)),
        );

        // If the block was enshrined as head too late for attestations to be created for it,
        // log a debug warning and increment a metric.
        if late_head {
            metrics::inc_counter(&metrics::BEACON_BLOCK_HEAD_SLOT_START_DELAY_EXCEEDED_TOTAL);
            debug!(
                log,
                "Delayed head block";
                "block_root" => ?head_block_root,
                "proposer_index" => head_block_proposer_index,
                "slot" => head_block_slot,
                "block_delay" => ?block_delay_total,
                "observed_delay" => ?block_delays.observed,
                "imported_delay" => ?block_delays.imported,
                "set_as_head_delay" => ?block_delays.set_as_head,
            );
        }
    }

    if let Some(event_handler) = event_handler {
        if !block_from_sync && late_head && event_handler.has_late_head_subscribers() {
            let peer_info = block_times_cache.get_peer_info(head_block_root);
            let block_delays = block_times_cache.get_block_delays(
                head_block_root,
                slot_clock
                    .start_of(head_block_slot)
                    .unwrap_or_else(|| Duration::from_secs(0)),
            );
            event_handler.register(EventKind::LateHead(SseLateHead {
                slot: head_block_slot,
                block: head_block_root,
                peer_id: peer_info.id,
                peer_client: peer_info.client,
                proposer_index: head_block_proposer_index,
                proposer_graffiti: head_block_graffiti,
                block_delay: block_delay_total,
                observed_delay: block_delays.observed,
                imported_delay: block_delays.imported,
                set_as_head_delay: block_delays.set_as_head,
            }));
        }
    }
}
