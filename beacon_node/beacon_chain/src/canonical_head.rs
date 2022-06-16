use crate::{
    beacon_chain::{BeaconForkChoice, BeaconStore, BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT},
    block_times_cache::BlockTimesCache,
    events::ServerSentEventHandler,
    metrics,
    validator_monitor::{get_slot_delay_ms, timestamp_now},
    BeaconChain, BeaconChainError as Error, BeaconChainTypes, BeaconSnapshot,
};
use eth2::types::{EventKind, SseChainReorg, SseFinalizedCheckpoint, SseHead, SseLateHead};
use fork_choice::{ExecutionStatus, ForkChoiceView, ForkchoiceUpdateParameters, ProtoBlock};
use itertools::process_results;
use parking_lot::{RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard};
use slog::{crit, debug, error, warn, Logger};
use slot_clock::SlotClock;
use std::mem;
use std::sync::Arc;
use std::time::Duration;
use store::iter::StateRootsIterator;
use task_executor::{JoinHandle, ShutdownReason};
use types::*;

/// A simple wrapper around an `RwLock` which allows us to use the `disallowed-from-async` lint to
/// prevent this lock being used from async threads. Using this lock from an async thread can block
/// the core `tokio` executor.
pub struct CanonicalHeadRwLock<T>(RwLock<T>);

impl<T> From<RwLock<T>> for CanonicalHeadRwLock<T> {
    fn from(rw_lock: RwLock<T>) -> Self {
        Self(rw_lock)
    }
}

impl<T> CanonicalHeadRwLock<T> {
    pub fn read(&self) -> RwLockReadGuard<T> {
        self.0.read()
    }

    pub fn write(&self) -> RwLockWriteGuard<T> {
        self.0.write()
    }
}

/// A simple wrapper around an `RwLock` to prevent access to the lock from anywhere else other than
/// this file.
pub struct FastCanonicalHeadRwLock<T>(RwLock<T>);

impl<T> From<RwLock<T>> for FastCanonicalHeadRwLock<T> {
    fn from(rw_lock: RwLock<T>) -> Self {
        Self(rw_lock)
    }
}

impl<T> FastCanonicalHeadRwLock<T> {
    /// Do not make this function public without considering the risk of deadlocks when interacting
    /// with the `canonical_head` lock.
    fn read(&self) -> RwLockReadGuard<T> {
        self.0.read()
    }

    /// Do not make this function public without considering the risk of deadlocks when interacting
    /// with the `canonical_head` lock.
    fn write(&self) -> RwLockWriteGuard<T> {
        self.0.write()
    }
}

/// A smaller version of `CanonicalHead` designed to have very little lock contention but with the
/// downside of sometimes being slightly behind the `CanonicalHead`.
#[derive(Clone, Debug, PartialEq)]
pub struct FastCanonicalHead {
    pub head_block_root: Hash256,
    pub head_block_slot: Slot,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub active_validator_count: usize,
}

impl FastCanonicalHead {
    pub fn new<T: BeaconChainTypes>(
        fork_choice: &BeaconForkChoice<T>,
        head_snapshot: &BeaconSnapshot<T::EthSpec>,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let state = &head_snapshot.beacon_state;
        let fork_choice_view = fork_choice.cached_fork_choice_view();

        let active_validator_count = state
            .get_active_validator_indices(state.current_epoch(), spec)?
            .len();

        Ok(Self {
            head_block_root: head_snapshot.beacon_block_root,
            head_block_slot: head_snapshot.beacon_block.slot(),
            justified_checkpoint: fork_choice_view.justified_checkpoint,
            finalized_checkpoint: fork_choice_view.finalized_checkpoint,
            active_validator_count,
        })
    }
}

/// Represents the "canonical head" of the beacon chain.
///
/// The canonical head and justified/finalized checkpoints are elected by the `fork_choice`
/// algorithm contained in this struct. Once elected, they are cached in the `fork_choice_view` and
/// `head_snapshot`.
///
/// There is no guarantee that the state of the `fork_choice` struct will always represent the
/// cached values (we may call `fork_choice` *without* updating the cached values), however there is
/// a guarantee that the cached values represent some past state of `fork_choice` (i.e.
/// `fork_choice` never lags behind the cached values).
pub struct CanonicalHead<T: BeaconChainTypes> {
    /// Provides an in-memory representation of the non-finalized block tree and is used to run the
    /// fork choice algorithm and determine the canonical head.
    pub fork_choice: BeaconForkChoice<T>,
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
    /// Provides the head block and state from the last time the head was updated.
    pub head_snapshot: BeaconSnapshot<T::EthSpec>,
}

impl<T: BeaconChainTypes> CanonicalHead<T> {
    /// Instantiate `Self`.
    ///
    /// An error will be returned if the cached head of `fork_choice` is not equal to the given
    /// `head_snapshot`.
    pub fn new(
        fork_choice: BeaconForkChoice<T>,
        head_snapshot: BeaconSnapshot<T::EthSpec>,
    ) -> Result<Self, Error> {
        let fork_choice_view = fork_choice.cached_fork_choice_view();

        Ok(Self {
            fork_choice,
            justified_checkpoint: fork_choice_view.justified_checkpoint,
            finalized_checkpoint: fork_choice_view.finalized_checkpoint,
            head_snapshot,
        })
    }

    /// Instantiate `Self`, loading the latest persisted `fork_choice` from the `store`.
    pub fn load_from_store(store: &BeaconStore<T>, spec: &ChainSpec) -> Result<Self, Error> {
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

        let head_snapshot = BeaconSnapshot {
            beacon_block_root,
            beacon_block: Arc::new(beacon_block),
            beacon_state,
        };

        Self::new(fork_choice, head_snapshot)
    }

    /// Returns root of the block at the head of the beacon chain.
    pub fn head_block_root(&self) -> Hash256 {
        self.head_snapshot.beacon_block_root
    }

    /// Returns root of the `BeaconState` at the head of the beacon chain.
    ///
    /// ## Note
    ///
    /// This `BeaconState` has *not* been advanced to the current slot, it has the same slot as the
    /// head block.
    pub fn head_state_root(&self) -> Hash256 {
        self.head_snapshot.beacon_state_root()
    }

    /// Returns slot of the block at the head of the beacon chain.
    ///
    /// ## Notes
    ///
    /// This is *not* the current slot as per the system clock.
    pub fn head_slot(&self) -> Slot {
        self.head_snapshot.beacon_block.slot()
    }

    /// Returns the `Fork` from the `BeaconState` at the head of the chain.
    pub fn head_fork(&self) -> Fork {
        self.head_snapshot.beacon_state.fork()
    }

    /// Returns the execution status of the block at the head of the beacon chain.
    ///
    /// This will only return `Err` in the scenario where `self.fork_choice` has advanced
    /// significantly past the cached `head_snapshot`. In such a scenario is it likely prudent to
    /// run `BeaconChain::recompute_head` to update the cached values.
    pub fn head_execution_status(&self) -> Result<ExecutionStatus, Error> {
        let head_block_root = self.head_block_root();
        self.fork_choice
            .get_block_execution_status(&head_block_root)
            .ok_or(Error::HeadMissingFromForkChoice(head_block_root))
    }

    /// Returns the randao mix for the block at the head of the chain.
    pub fn head_random(&self) -> Result<Hash256, BeaconStateError> {
        let state = &self.head_snapshot.beacon_state;
        let root = *state.get_randao_mix(state.current_epoch())?;
        Ok(root)
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
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns a summary of the `CanonicalHead`. It is "fast" since it lives behind it's own
    /// `RwLock` which should have very little contention. The downsides are that it only has
    /// limited information about the head and it might lag behind the `CanonicalHead` very slightly
    /// (generally on the order of milliseconds).
    ///
    /// This method should be used by tasks which are very sensitive to delays caused by lock
    /// contention, like the networking stack.
    pub fn fast_canonical_head(&self) -> FastCanonicalHead {
        self.fast_canonical_head.read().clone()
    }
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
        let mut canonical_head_write_lock = self.canonical_head.write();

        // Take note of the last-known head and finalization values.
        //
        // It is important to read the `fork_choice_view` from the canonical head rather than from
        // fork choice, since the fork choice value might have changed between calls to this
        // function. We are interested in the changes since we last cached the head values, not
        // since fork choice was last run.
        let old_view = ForkChoiceView {
            head_block_root: canonical_head_write_lock.head_block_root(),
            finalized_checkpoint: canonical_head_write_lock.finalized_checkpoint(),
            justified_checkpoint: canonical_head_write_lock.justified_checkpoint(),
        };

        // Recompute the current head via the fork choice algorithm.
        canonical_head_write_lock
            .fork_choice
            .get_head(current_slot, &self.spec)?;

        // Read the current head value from the fork choice algorithm.
        let new_view = canonical_head_write_lock
            .fork_choice
            .cached_fork_choice_view();

        // Check to ensure that the finalized block hasn't been marked as invalid. If it has,
        // shut down Lighthouse.
        let finalized_proto_block = canonical_head_write_lock
            .fork_choice
            .get_finalized_block()?;
        check_finalized_payload_validity(self, &finalized_proto_block)?;

        // Sanity check the finalized checkpoint.
        //
        // The new finalized checkpoint must be either equal to or better than the previous
        // finalized checkpoint.
        check_against_finality_reversion(&old_view, &new_view)?;

        let new_head_proto_block = canonical_head_write_lock
            .fork_choice
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

        perform_debug_logging::<T>(
            &old_view,
            &new_view,
            &canonical_head_write_lock.fork_choice,
            &self.log,
        );

        // Update the checkpoints on the `canonical_head`.
        canonical_head_write_lock.justified_checkpoint = new_view.justified_checkpoint;
        canonical_head_write_lock.finalized_checkpoint = new_view.finalized_checkpoint;

        // If the head has changed, update `self.canonical_head`.
        //
        //  Regarding the returned read-lock, the `parking_lot` docs have this to say about
        //  downgraded write locks:
        //
        // > Note that if there are any writers currently waiting to take the lock then other >
        // readers may not be able to acquire the lock even if it was downgraded.
        //
        // This means that it's dangerous to take another read-lock on the `canonical_head` in this
        // thread.
        let (canonical_head_read_lock, head_update_params) = if new_view.head_block_root
            != old_view.head_block_root
        {
            metrics::inc_counter(&metrics::FORK_CHOICE_CHANGED_HEAD);

            // Downgrade the write-lock to a read lock to avoid preventing all access to the head
            // whilst the head snapshot is loaded. The docs note:
            //
            // > Note that if there are any writers currently waiting to take the lock then other
            // > readers may not be able to acquire the lock even if it was downgraded.
            //
            // This means that other readers are not *guaranteed* access during this period, but
            // there's a decent chance that there are no other writers and they'll be able to read.
            let canonical_head_read_lock =
                RwLockWriteGuard::downgrade_to_upgradable(canonical_head_write_lock);

            // Try and obtain the snapshot for `beacon_block_root` from the snapshot cache, falling
            // back to a database read if that fails.
            //
            // ## Note
            //
            // the snapshot cache read-lock is being held whilst we have a lock on the
            // `canonical_head`. This is a deadlock risk.
            //
            // TODO(paul): check all other uses of the snapshot cache.
            let new_head = self
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

            // Upgrade the read lock to a write lock, without allowing any other writers access in
            // the meantime.
            let mut canonical_head_write_lock =
                RwLockUpgradableReadGuard::upgrade(canonical_head_read_lock);

            // Enshrine the new value as the head.
            let old_head = mem::replace(&mut canonical_head_write_lock.head_snapshot, new_head);

            // Downgrade the write-lock to a read-lock, without allowing any other writers access during
            // the process.
            let canonical_head_read_lock = RwLockWriteGuard::downgrade(canonical_head_write_lock);

            // Clear the early attester cache in case it conflicts with `self.canonical_head`.
            self.early_attester_cache.clear();

            (
                canonical_head_read_lock,
                Some((old_head, new_head_proto_block)),
            )
        } else {
            let canonical_head_read_lock = RwLockWriteGuard::downgrade(canonical_head_write_lock);
            (canonical_head_read_lock, None)
        };

        // Alias for readability.
        let new_head = &canonical_head_read_lock.head_snapshot;

        // Update the fast canonical head, whilst holding the lock on the canonical head.
        //
        // Doing it whilst holding the read-lock ensures that the `canonical_head` and
        // `fast_canonical_head` stay consistent.
        *self.fast_canonical_head.write() = FastCanonicalHead {
            head_block_root: new_view.head_block_root,
            head_block_slot: new_head.beacon_block.slot(),
            justified_checkpoint: new_view.justified_checkpoint,
            finalized_checkpoint: new_view.finalized_checkpoint,
            active_validator_count: new_head
                .beacon_state
                .get_cached_active_validator_indices(RelativeEpoch::Current)?
                .len(),
        };

        // If the head changed, perform some updates.
        if let Some((old_head, new_head_proto_block)) = head_update_params {
            if let Err(e) = self.after_new_head(&old_head, new_head, new_head_proto_block) {
                crit!(
                    self.log,
                    "Error updating canonical head";
                    "error" => ?e
                );
            }
        }

        // If the finalized checkpoint changed, perform some updates.
        if new_view.finalized_checkpoint != old_view.finalized_checkpoint {
            // The store migration task requires the *state at the slot of the finalized epoch*,
            // rather than the state of the latest finalized block. These two values will only
            // differ when the first slot of the finalized epoch is a skip slot.
            //
            // Use the `StateRootsIterator` directly rather than `BeaconChain::state_root_at_slot`
            // since the latter will try to take a read-lock on the state.
            let new_finalized_slot = new_view
                .finalized_checkpoint
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch());
            let new_finalized_state_root = process_results(
                StateRootsIterator::new(&self.store, &new_head.beacon_state),
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

            if let Err(e) = self.after_finalization(
                new_head,
                new_view,
                finalized_proto_block,
                new_finalized_state_root,
            ) {
                crit!(
                    self.log,
                    "Error updating finalization";
                    "error" => ?e
                );
            }
        }

        // Get the parameters toupdate the execution layer since either the head or some finality
        // parameters have changed.
        let forkchoice_update_parameters = canonical_head_read_lock
            .fork_choice
            .get_forkchoice_update_parameters()
            .ok_or(Error::ForkchoiceUpdateParamsMissing)?;

        // The read-lock on the canonical head *MUST* be dropped before spawning the execution
        // layer update tasks since they might try to take a write-lock on the canonical head.
        drop(canonical_head_read_lock);

        // The read-lock on the canonical head *MUST* be dropped before this call since it might try to take a write-lock on the canonical head.
        let el_update_handle =
            spawn_execution_layer_updates(self.clone(), forkchoice_update_parameters)?;

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
        old_head: &BeaconSnapshot<T::EthSpec>,
        new_head: &BeaconSnapshot<T::EthSpec>,
        new_head_proto_block: ProtoBlock,
    ) -> Result<(), Error> {
        // Detect and potentially report any re-orgs.
        let reorg_distance = detect_reorg(
            &old_head.beacon_state,
            old_head.beacon_block_root,
            &new_head.beacon_state,
            new_head.beacon_block_root,
            &self.spec,
            &self.log,
        );

        // Determine if the new head is in a later epoch to the previous head.
        let is_epoch_transition = old_head
            .beacon_block
            .slot()
            .epoch(T::EthSpec::slots_per_epoch())
            < new_head
                .beacon_state
                .slot()
                .epoch(T::EthSpec::slots_per_epoch());

        // These fields are used for server-sent events.
        let state_root = new_head.beacon_state_root();
        let head_slot = new_head.beacon_state.slot();
        let dependent_root = new_head
            .beacon_state
            .proposer_shuffling_decision_root(self.genesis_block_root);
        let prev_dependent_root = new_head
            .beacon_state
            .attester_shuffling_decision_root(self.genesis_block_root, RelativeEpoch::Current);

        // The rest of this function is spawned in another task, since we don't need to wait for it
        // to complete and it doesn't require a reference to the beacon state.
        let chain = self.clone();
        let old_head_block: Arc<_> = old_head.beacon_block.clone();
        let old_head_block_root = old_head.beacon_block_root;
        let new_head_block_root = new_head.beacon_block_root;
        let new_head_block: Arc<_> = new_head.beacon_block.clone();
        let concurrent_task = move || {
            // Update the snapshot cache with the latest head value.
            //
            // This *could* be done inside `recompute_head`, however updating the head on the snapshot
            // cache is not critical so we avoid placing it on a critical path. Note that this function
            // will not return an error if the update fails, it will just log an error.
            chain
                .snapshot_cache
                .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
                .map(|mut snapshot_cache| {
                    snapshot_cache.update_head(new_head_block_root);
                })
                .unwrap_or_else(|| {
                    error!(
                        chain.log,
                        "Failed to obtain cache write lock";
                        "lock" => "snapshot_cache",
                        "task" => "update head"
                    );
                });

            observe_head_block_delays(
                &mut chain.block_times_cache.write(),
                &new_head_proto_block,
                new_head_block.message().proposer_index(),
                new_head_block.message().body().graffiti().as_utf8_lossy(),
                &chain.slot_clock,
                chain.event_handler.as_ref(),
                &chain.log,
            );

            if is_epoch_transition || reorg_distance.is_some() {
                chain.persist_head_and_fork_choice()?;
                chain.op_pool.prune_attestations(chain.epoch()?);
            }

            // Register server-sent-events for a new head.
            if let Some(event_handler) = chain
                .event_handler
                .as_ref()
                .filter(|handler| handler.has_head_subscribers())
            {
                match (dependent_root, prev_dependent_root) {
                    (Ok(current_duty_dependent_root), Ok(previous_duty_dependent_root)) => {
                        event_handler.register(EventKind::Head(SseHead {
                            slot: head_slot,
                            block: new_head_block_root,
                            state: state_root,
                            current_duty_dependent_root,
                            previous_duty_dependent_root,
                            epoch_transition: is_epoch_transition,
                        }));
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        warn!(
                            chain.log,
                            "Unable to find dependent roots, cannot register head event";
                            "error" => ?e
                        );
                    }
                }
            }

            // Register a server-sent-event for a reorg (if necessary).
            if let Some(depth) = reorg_distance {
                if let Some(event_handler) = chain
                    .event_handler
                    .as_ref()
                    .filter(|handler| handler.has_reorg_subscribers())
                {
                    event_handler.register(EventKind::ChainReorg(SseChainReorg {
                        slot: head_slot,
                        depth: depth.as_u64(),
                        old_head_block: old_head_block_root,
                        old_head_state: old_head_block.state_root(),
                        new_head_block: new_head_block_root,
                        new_head_state: new_head_block.state_root(),
                        epoch: head_slot.epoch(T::EthSpec::slots_per_epoch()),
                    }));
                }
            }

            Ok::<_, Error>(())
        };
        let log = self.log.clone();
        self.task_executor.spawn_blocking(
            move || {
                if let Err(e) = concurrent_task() {
                    error!(
                        log,
                        "Error after updating head";
                        "error" => ?e
                    );
                }
            },
            "after_head",
        );

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
        new_head: &BeaconSnapshot<T::EthSpec>,
        new_view: ForkChoiceView,
        finalized_proto_block: ProtoBlock,
        new_finalized_state_root: Hash256,
    ) -> Result<(), Error> {
        self.op_pool
            .prune_all(&new_head.beacon_state, self.epoch()?);

        let chain = self.clone();
        let concurrent_task = move || {
            chain.observed_block_producers.write().prune(
                new_view
                    .finalized_checkpoint
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch()),
            );

            chain
                .snapshot_cache
                .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
                .map(|mut snapshot_cache| {
                    snapshot_cache.prune(new_view.finalized_checkpoint.epoch);
                    debug!(
                        chain.log,
                        "Snapshot cache pruned";
                        "new_len" => snapshot_cache.len(),
                        "remaining_roots" => ?snapshot_cache.beacon_block_roots(),
                    );
                })
                .unwrap_or_else(|| {
                    error!(
                        chain.log,
                        "Failed to obtain cache write lock";
                        "lock" => "snapshot_cache",
                        "task" => "prune"
                    );
                });

            chain.store_migrator.process_finalization(
                new_finalized_state_root.into(),
                new_view.finalized_checkpoint,
                chain.head_tracker.clone(),
            )?;

            chain
                .attester_cache
                .prune_below(new_view.finalized_checkpoint.epoch);

            if let Some(event_handler) = chain.event_handler.as_ref() {
                if event_handler.has_finalized_subscribers() {
                    event_handler.register(EventKind::FinalizedCheckpoint(
                        SseFinalizedCheckpoint {
                            epoch: new_view.finalized_checkpoint.epoch,
                            block: new_view.finalized_checkpoint.root,
                            // Provide the state root of the latest finalized block, rather than the
                            // specific state root at the first slot of the finalized epoch (which
                            // might be a skip slot).
                            state: finalized_proto_block.state_root,
                        },
                    ));
                }
            }

            Ok::<_, Error>(())
        };
        let log = self.log.clone();
        self.task_executor.spawn_blocking(
            move || {
                if let Err(e) = concurrent_task() {
                    error!(
                        log,
                        "Error after updating finalization";
                        "error" => ?e
                    );
                }
            },
            "after_finalization",
        );

        Ok(())
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
