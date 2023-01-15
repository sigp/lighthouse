//! This module provides all functionality for finding the canonical head, updating all necessary
//! components (e.g. caches) and maintaining a cached head block and state.
//!
//! For practically all applications, the "canonical head" can be read using
//! `beacon_chain.canonical_head.cached_head()`.
//!
//! The canonical head can be updated using `beacon_chain.recompute_head()`.
//!
//! ## Deadlock safety
//!
//! This module contains three locks:
//!
//! 1. `RwLock<BeaconForkChoice>`: Contains `proto_array` fork choice.
//! 2. `RwLock<CachedHead>`: Contains a cached block/state from the last run of `proto_array`.
//! 3. `Mutex<()>`: Is used to prevent concurrent execution of `BeaconChain::recompute_head`.
//!
//! This module has to take great efforts to avoid causing a deadlock with these three methods. Any
//! developers working in this module should tread carefully and seek a detailed review.
//!
//! To encourage safe use of this module, it should **only ever return a read or write lock for the
//! fork choice lock (lock 1)**. Whilst public functions might indirectly utilise locks (2) and (3),
//! the fundamental `RwLockWriteGuard` or `RwLockReadGuard` should never be exposed. This prevents
//! external functions from acquiring these locks in conflicting orders and causing a deadlock.
//!
//! ## Design Considerations
//!
//! We separate the `BeaconForkChoice` and `CachedHead` into two `RwLocks` because we want to ensure
//! fast access to the `CachedHead`. If we were to put them both under the same lock, we would need
//! to take an exclusive write-lock on it in order to run `ForkChoice::get_head`. This can take tens
//! of milliseconds and would block all downstream functions that want to know simple things like
//! the head block root. This is unacceptable for fast-responding functions like the networking
//! stack.

use crate::persisted_fork_choice::PersistedForkChoice;
use crate::{
    beacon_chain::{
        BeaconForkChoice, BeaconStore, OverrideForkchoiceUpdate,
        BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT, FORK_CHOICE_DB_KEY,
    },
    block_times_cache::BlockTimesCache,
    events::ServerSentEventHandler,
    metrics,
    validator_monitor::{get_slot_delay_ms, timestamp_now},
    BeaconChain, BeaconChainError as Error, BeaconChainTypes, BeaconSnapshot,
};
use eth2::types::{EventKind, SseChainReorg, SseFinalizedCheckpoint, SseHead, SseLateHead};
use fork_choice::{
    CountUnrealizedFull, ExecutionStatus, ForkChoiceView, ForkchoiceUpdateParameters, ProtoBlock,
    ResetPayloadStatuses,
};
use itertools::process_results;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use slog::{crit, debug, error, warn, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use store::{iter::StateRootsIterator, KeyValueStoreOp, Split, StoreItem};
use task_executor::{JoinHandle, ShutdownReason};
use types::consts::eip4844::MIN_EPOCHS_FOR_BLOBS_SIDECARS_REQUESTS;
use types::*;

/// Simple wrapper around `RwLock` that uses private visibility to prevent any other modules from
/// accessing the contained lock without it being explicitly noted in this module.
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
    /// This value may be distinct to the `self.snapshot.beacon_state.justified_checkpoint`.
    /// This value should be used over the beacon state value in practically all circumstances.
    justified_checkpoint: Checkpoint,
    /// The finalized checkpoint as per `self.fork_choice`.
    ///
    /// This value may be distinct to the `self.snapshot.beacon_state.finalized_checkpoint`.
    /// This value should be used over the beacon state value in practically all circumstances.
    finalized_checkpoint: Checkpoint,
    /// The `execution_payload.block_hash` of the block at the head of the chain. Set to `None`
    /// before Bellatrix.
    head_hash: Option<ExecutionBlockHash>,
    /// The `execution_payload.block_hash` of the justified block. Set to `None` before Bellatrix.
    justified_hash: Option<ExecutionBlockHash>,
    /// The `execution_payload.block_hash` of the finalized block. Set to `None` before Bellatrix.
    finalized_hash: Option<ExecutionBlockHash>,
}

impl<E: EthSpec> CachedHead<E> {
    /// Returns root of the block at the head of the beacon chain.
    pub fn head_block_root(&self) -> Hash256 {
        self.snapshot.beacon_block_root
    }

    /// Returns the root of the parent of the head block.
    pub fn parent_block_root(&self) -> Hash256 {
        self.snapshot.beacon_block.parent_root()
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
    /// This is *not* the current slot as per the system clock. Use `BeaconChain::slot` for the
    /// system clock (aka "wall clock") slot.
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

    /// Returns the randao mix for the parent of the block at the head of the chain.
    ///
    /// This is useful for re-orging the current head. The parent's RANDAO value is read from
    /// the head's execution payload because it is unavailable in the beacon state's RANDAO mixes
    /// array after being overwritten by the head block's RANDAO mix.
    ///
    /// This will error if the head block is not execution-enabled (post Bellatrix).
    pub fn parent_random(&self) -> Result<Hash256, BeaconStateError> {
        self.snapshot
            .beacon_block
            .message()
            .execution_payload()
            .map(|payload| payload.prev_randao())
    }

    /// Returns the active validator count for the current epoch of the head state.
    ///
    /// Should only return `None` if the caches have not been built on the head state (this should
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
            justified_hash: self.justified_hash,
            finalized_hash: self.finalized_hash,
        }
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
    ) -> Self {
        let fork_choice_view = fork_choice.cached_fork_choice_view();
        let forkchoice_update_params = fork_choice.get_forkchoice_update_parameters();
        let cached_head = CachedHead {
            snapshot,
            justified_checkpoint: fork_choice_view.justified_checkpoint,
            finalized_checkpoint: fork_choice_view.finalized_checkpoint,
            head_hash: forkchoice_update_params.head_hash,
            justified_hash: forkchoice_update_params.justified_hash,
            finalized_hash: forkchoice_update_params.finalized_hash,
        };

        Self {
            fork_choice: CanonicalHeadRwLock::new(fork_choice),
            cached_head: CanonicalHeadRwLock::new(cached_head),
            recompute_head_lock: Mutex::new(()),
        }
    }

    /// Load a persisted version of `BeaconForkChoice` from the `store` and restore `self` to that
    /// state.
    ///
    /// This is useful if some database corruption is expected and we wish to go back to our last
    /// save-point.
    pub(crate) fn restore_from_store(
        &self,
        // We don't actually need this value, however it's always present when we call this function
        // and it needs to be dropped to prevent a dead-lock. Requiring it to be passed here is
        // defensive programming.
        mut fork_choice_write_lock: RwLockWriteGuard<BeaconForkChoice<T>>,
        reset_payload_statuses: ResetPayloadStatuses,
        count_unrealized_full: CountUnrealizedFull,
        store: &BeaconStore<T>,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Result<(), Error> {
        let fork_choice = <BeaconChain<T>>::load_fork_choice(
            store.clone(),
            reset_payload_statuses,
            count_unrealized_full,
            spec,
            log,
        )?
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

        let forkchoice_update_params = fork_choice.get_forkchoice_update_parameters();
        let cached_head = CachedHead {
            snapshot: Arc::new(snapshot),
            justified_checkpoint: fork_choice_view.justified_checkpoint,
            finalized_checkpoint: fork_choice_view.finalized_checkpoint,
            head_hash: forkchoice_update_params.head_hash,
            justified_hash: forkchoice_update_params.justified_hash,
            finalized_hash: forkchoice_update_params.finalized_hash,
        };

        *fork_choice_write_lock = fork_choice;
        // Avoid interleaving the fork choice and cached head locks.
        drop(fork_choice_write_lock);
        *self.cached_head.write() = cached_head;

        Ok(())
    }

    /// Returns the execution status of the block at the head of the beacon chain.
    ///
    /// This will only return `Err` in the scenario where `self.fork_choice` has advanced
    /// significantly past the cached `head_snapshot`. In such a scenario it is likely prudent to
    /// run `BeaconChain::recompute_head` to update the cached values.
    pub fn head_execution_status(&self) -> Result<ExecutionStatus, Error> {
        let head_block_root = self.cached_head().head_block_root();
        self.fork_choice_read_lock()
            .get_block_execution_status(&head_block_root)
            .ok_or(Error::HeadMissingFromForkChoice(head_block_root))
    }

    /// Returns a clone of the `CachedHead` and the execution status of the contained head block.
    ///
    /// This will only return `Err` in the scenario where `self.fork_choice` has advanced
    /// significantly past the cached `head_snapshot`. In such a scenario it is likely prudent to
    /// run `BeaconChain::recompute_head` to update the cached values.
    pub fn head_and_execution_status(
        &self,
    ) -> Result<(CachedHead<T::EthSpec>, ExecutionStatus), Error> {
        let head = self.cached_head();
        let head_block_root = head.head_block_root();
        let execution_status = self
            .fork_choice_read_lock()
            .get_block_execution_status(&head_block_root)
            .ok_or(Error::HeadMissingFromForkChoice(head_block_root))?;
        Ok((head, execution_status))
    }

    /// Returns a clone of `self.cached_head`.
    ///
    /// Takes a read-lock on `self.cached_head` for a short time (just long enough to clone it).
    /// The `CachedHead` is designed to be fast-to-clone so this is preferred to passing back a
    /// `RwLockReadGuard`, which may cause deadlock issues (see module-level documentation).
    ///
    /// This function is safe to be public since it does not expose any locks.
    pub fn cached_head(&self) -> CachedHead<T::EthSpec> {
        self.cached_head_read_lock().clone()
    }

    /// Access a read-lock for the cached head.
    ///
    /// This function is **not safe** to be public. See the module-level documentation for more
    /// information about protecting from deadlocks.
    fn cached_head_read_lock(&self) -> RwLockReadGuard<CachedHead<T::EthSpec>> {
        self.cached_head.read()
    }

    /// Access a write-lock for the cached head.
    ///
    /// This function is **not safe** to be public. See the module-level documentation for more
    /// information about protecting from deadlocks.
    fn cached_head_write_lock(&self) -> RwLockWriteGuard<CachedHead<T::EthSpec>> {
        self.cached_head.write()
    }

    /// Access a read-lock for fork choice.
    pub fn fork_choice_read_lock(&self) -> RwLockReadGuard<BeaconForkChoice<T>> {
        self.fork_choice.read()
    }

    /// Access a write-lock for fork choice.
    pub fn fork_choice_write_lock(&self) -> RwLockWriteGuard<BeaconForkChoice<T>> {
        self.fork_choice.write()
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Contains the "best block"; the head of the canonical `BeaconChain`.
    ///
    /// It is important to note that the `snapshot.beacon_state` returned may not match the present slot. It
    /// is the state as it was when the head block was received, which could be some slots prior to
    /// now.
    pub fn head(&self) -> CachedHead<T::EthSpec> {
        self.canonical_head.cached_head()
    }

    /// Apply a function to an `Arc`-clone of the canonical head snapshot.
    ///
    /// This method is a relic from an old implementation where the canonical head was not behind
    /// an `Arc` and the canonical head lock had to be held whenever it was read. This method is
    /// fine to be left here, it just seems a bit weird.
    pub fn with_head<U, E>(
        &self,
        f: impl FnOnce(&BeaconSnapshot<T::EthSpec>) -> Result<U, E>,
    ) -> Result<U, E>
    where
        E: From<Error>,
    {
        let head_snapshot = self.head_snapshot();
        f(&head_snapshot)
    }

    /// Returns the beacon block root at the head of the canonical chain.
    ///
    /// See `Self::head` for more information.
    pub fn head_beacon_block_root(&self) -> Hash256 {
        self.canonical_head
            .cached_head_read_lock()
            .snapshot
            .beacon_block_root
    }

    /// Returns the slot of the highest block in the canonical chain.
    pub fn best_slot(&self) -> Slot {
        self.canonical_head
            .cached_head_read_lock()
            .snapshot
            .beacon_block
            .slot()
    }

    /// Returns a `Arc` of the `BeaconSnapshot` at the head of the canonical chain.
    ///
    /// See `Self::head` for more information.
    pub fn head_snapshot(&self) -> Arc<BeaconSnapshot<T::EthSpec>> {
        self.canonical_head.cached_head_read_lock().snapshot.clone()
    }

    /// Returns the beacon block at the head of the canonical chain.
    ///
    /// See `Self::head` for more information.
    pub fn head_beacon_block(&self) -> Arc<SignedBeaconBlock<T::EthSpec>> {
        self.canonical_head
            .cached_head_read_lock()
            .snapshot
            .beacon_block
            .clone()
    }

    /// Returns a clone of the beacon state at the head of the canonical chain.
    ///
    /// Cloning the head state is expensive and should generally be avoided outside of tests.
    ///
    /// See `Self::head` for more information.
    pub fn head_beacon_state_cloned(&self) -> BeaconState<T::EthSpec> {
        // Don't clone whilst holding the read-lock, take an Arc-clone to reduce lock contention.
        let snapshot: Arc<_> = self.head_snapshot();
        snapshot
            .beacon_state
            .clone_with(CloneConfig::committee_caches_only())
    }

    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
    ///
    /// This method replaces the old `BeaconChain::fork_choice` method.
    pub async fn recompute_head_at_current_slot(self: &Arc<Self>) {
        match self.slot() {
            Ok(current_slot) => self.recompute_head_at_slot(current_slot).await,
            Err(e) => error!(
                self.log,
                "No slot when recomputing head";
                "error" => ?e
            ),
        }
    }

    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
    ///
    /// The `current_slot` is specified rather than relying on the wall-clock slot. Using a
    /// different slot to the wall-clock can be useful for pushing fork choice into the next slot
    /// *just* before the start of the slot. This ensures that block production can use the correct
    /// head value without being delayed.
    ///
    /// This function purposefully does *not* return a `Result`. It's possible for fork choice to
    /// fail to update if there is only one viable head and it has an invalid execution payload. In
    /// such a case it's critical that the `BeaconChain` keeps importing blocks so that the
    /// situation can be rectified. We avoid returning an error here so that calling functions
    /// can't abort block import because an error is returned here.
    pub async fn recompute_head_at_slot(self: &Arc<Self>, current_slot: Slot) {
        metrics::inc_counter(&metrics::FORK_CHOICE_REQUESTS);
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_TIMES);

        let chain = self.clone();
        match self
            .spawn_blocking_handle(
                move || chain.recompute_head_at_slot_internal(current_slot),
                "recompute_head_internal",
            )
            .await
        {
            // Fork choice returned successfully and did not need to update the EL.
            Ok(Ok(None)) => (),
            // Fork choice returned successfully and needed to update the EL. It has returned a
            // join-handle from when it spawned some async tasks. We should await those tasks.
            Ok(Ok(Some(join_handle))) => match join_handle.await {
                // The async task completed successfully.
                Ok(Some(())) => (),
                // The async task did not complete successfully since the runtime is shutting down.
                Ok(None) => {
                    debug!(
                        self.log,
                        "Did not update EL fork choice";
                        "info" => "shutting down"
                    );
                }
                // The async task did not complete successfully, tokio returned an error.
                Err(e) => {
                    error!(
                        self.log,
                        "Did not update EL fork choice";
                        "error" => ?e
                    );
                }
            },
            // There was an error recomputing the head.
            Ok(Err(e)) => {
                metrics::inc_counter(&metrics::FORK_CHOICE_ERRORS);
                error!(
                    self.log,
                    "Error whist recomputing head";
                    "error" => ?e
                );
            }
            // There was an error spawning the task.
            Err(e) => {
                error!(
                    self.log,
                    "Failed to spawn recompute head task";
                    "error" => ?e
                );
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

        // Downgrade the fork choice write-lock to a read lock, without allowing access to any
        // other writers.
        let fork_choice_read_lock = RwLockWriteGuard::downgrade(fork_choice_write_lock);

        // Read the current head value from the fork choice algorithm.
        let new_view = fork_choice_read_lock.cached_fork_choice_view();

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
        // In theory, fork choice should never select an invalid head (i.e., step #3 is impossible).
        // However, this check is cheap.
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
                justified_hash: new_forkchoice_update_parameters.justified_hash,
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
            let new_cached_head = CachedHead {
                // The head hasn't changed, take a relatively cheap `Arc`-clone of the existing
                // head.
                snapshot: old_cached_head.snapshot.clone(),
                justified_checkpoint: new_view.justified_checkpoint,
                finalized_checkpoint: new_view.finalized_checkpoint,
                head_hash: new_forkchoice_update_parameters.head_hash,
                justified_hash: new_forkchoice_update_parameters.justified_hash,
                finalized_hash: new_forkchoice_update_parameters.finalized_hash,
            };

            let mut cached_head_write_lock = self.canonical_head.cached_head_write_lock();

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

        // Drop the old cache head nice and early to try and free the memory as soon as possible.
        drop(old_cached_head);

        // If the finalized checkpoint changed, perform some updates.
        //
        // The `after_finalization` function will take a write-lock on `fork_choice`, therefore it
        // is a dead-lock risk to hold any other lock on fork choice at this point.
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
    fn after_new_head(
        self: &Arc<Self>,
        old_cached_head: &CachedHead<T::EthSpec>,
        new_cached_head: &CachedHead<T::EthSpec>,
        new_head_proto_block: ProtoBlock,
    ) -> Result<(), Error> {
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_AFTER_NEW_HEAD_TIMES);
        let old_snapshot = &old_cached_head.snapshot;
        let new_snapshot = &new_cached_head.snapshot;
        let new_head_is_optimistic = new_head_proto_block
            .execution_status
            .is_optimistic_or_invalid();

        if self.store.get_config().prune_blobs {
            let current_slot = self.slot()?;
            let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());
            if Some(current_epoch)
                > self.spec.eip4844_fork_epoch.map(|eip4844_fork_epoch| {
                    eip4844_fork_epoch + *MIN_EPOCHS_FOR_BLOBS_SIDECARS_REQUESTS
                })
            {
                let current_epoch_start_slot =
                    current_epoch.start_slot(T::EthSpec::slots_per_epoch());

                // Update db's metadata for blobs pruning.
                if current_slot == current_epoch_start_slot {
                    if let Some(mut blob_info) = self.store.get_blob_info() {
                        if let Some(data_availability_boundary) = self.data_availability_boundary()
                        {
                            let dab_slot =
                                data_availability_boundary.end_slot(T::EthSpec::slots_per_epoch());
                            if let Some(dab_state_root) = self.state_root_at_slot(dab_slot)? {
                                blob_info.data_availability_boundary =
                                    Split::new(dab_slot, dab_state_root);

                                self.store.compare_and_set_blob_info_with_write(
                                    self.store.get_blob_info(),
                                    Some(blob_info),
                                )?;
                            }
                        }
                    }
                }
            }

            let store = self.store.clone();
            let log = self.log.clone();

            self.task_executor.spawn_blocking(
                move || {
                    if let Err(e) = store.try_prune_blobs(false) {
                        error!(log, "Error pruning blobs in background"; "error" => ?e);
                    }
                },
                "prune_blobs_background",
            );
        }

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
                        execution_optimistic: new_head_is_optimistic,
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
                    execution_optimistic: new_head_is_optimistic,
                }));
            }
        }

        Ok(())
    }

    /// Perform updates to caches and other components after the finalized checkpoint has been
    /// changed.
    ///
    /// This function will take a write-lock on `canonical_head.fork_choice`, therefore it would be
    /// unwise to hold any lock on fork choice while calling this function.
    fn after_finalization(
        self: &Arc<Self>,
        new_cached_head: &CachedHead<T::EthSpec>,
        new_view: ForkChoiceView,
        finalized_proto_block: ProtoBlock,
    ) -> Result<(), Error> {
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_AFTER_FINALIZATION_TIMES);
        let new_snapshot = &new_cached_head.snapshot;
        let finalized_block_is_optimistic = finalized_proto_block
            .execution_status
            .is_optimistic_or_invalid();

        self.op_pool.prune_all(
            &new_snapshot.beacon_block,
            &new_snapshot.beacon_state,
            self.epoch()?,
            &self.spec,
        );

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
                    execution_optimistic: finalized_block_is_optimistic,
                }));
            }
        }

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

        // Take a write-lock on the canonical head and signal for it to prune.
        self.canonical_head.fork_choice_write_lock().prune()?;

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
                    .update_execution_engine_forkchoice(
                        current_slot,
                        forkchoice_update_params,
                        OverrideForkchoiceUpdate::Yes,
                    )
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
        metrics::set_gauge(
            &metrics::FORK_CHOICE_REORG_DISTANCE,
            reorg_distance.as_u64() as i64,
        );
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
    let head_block_is_optimistic = head_block.execution_status.is_optimistic_or_invalid();

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
                execution_optimistic: head_block_is_optimistic,
            }));
        }
    }
}
