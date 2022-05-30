use crate::{
    beacon_chain::BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT,
    block_times_cache::BlockTimesCache,
    events::ServerSentEventHandler,
    metrics,
    validator_monitor::{get_slot_delay_ms, timestamp_now},
    BeaconChain, BeaconChainError as Error, BeaconChainTypes, BeaconSnapshot,
};
use eth2::types::{EventKind, SseChainReorg, SseFinalizedCheckpoint, SseHead, SseLateHead};
use fork_choice::{ExecutionStatus, ForkChoiceView, ForkchoiceUpdateParameters, ProtoBlock};
use parking_lot::RwLockWriteGuard;
use slog::{crit, debug, error, trace, warn, Logger};
use slot_clock::SlotClock;
use std::mem;
use std::sync::Arc;
use std::time::Duration;
use task_executor::{JoinHandle, ShutdownReason};
use types::*;

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn spawn_recompute_head_at_current_slot(self: Arc<Self>, call_location: &'static str) {
        self.task_executor.clone().spawn(
            async move {
                if let Err(e) = self.recompute_head_at_current_slot().await {
                    error!(
                        self.log,
                        "Fork choice failed";
                        "error" => ?e,
                        "location" => call_location
                    )
                } else {
                    trace!(
                        self.log,
                        "Fork choice success";
                        "location" => call_location
                    )
                }
            },
            "spawn_recompute_head",
        )
    }

    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
    pub async fn recompute_head_at_current_slot(self: &Arc<Self>) -> Result<(), Error> {
        let current_slot = self.slot()?;
        self.recompute_head_at_slot(current_slot).await
    }

    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
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

    pub fn recompute_head_at_slot_internal(
        self: &Arc<Self>,
        current_slot: Slot,
    ) -> Result<Option<JoinHandle<Option<()>>>, Error> {
        let mut canonical_head_write_lock = self.canonical_head.write();

        // Take note of the last-known head and finalization values.
        //
        // It is important to read the `fork_choice_view` from the canonical head rather than from
        // fork choice, since the fork choice value might have changed between calls to this
        // function.
        let old_view = canonical_head_write_lock.fork_choice_view;

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
        if let ExecutionStatus::Invalid(block_hash) = finalized_proto_block.execution_status {
            crit!(
                self.log,
                "Finalized block has an invalid payload";
                "msg" => "You must use the `--purge-db` flag to clear the database and restart sync. \
                You may be on a hostile network.",
                "block_hash" => ?block_hash
            );
            let mut shutdown_sender = self.shutdown_sender();
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

        // Sanity check the finalized checkpoint.
        //
        // The new finalized checkpoint must be either equal to or better than the previous
        // finalized checkpoint.
        let valid_finalization_transition = new_view.finalized_checkpoint.epoch
            > old_view.finalized_checkpoint.epoch
            || new_view.finalized_checkpoint == old_view.finalized_checkpoint;
        if !valid_finalization_transition {
            // Exit now with an error
            return Err(Error::RevertedFinalizedEpoch {
                old: old_view.finalized_checkpoint,
                new: new_view.finalized_checkpoint,
            });
        }

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
            return Ok(None);
        }

        // Update the fork choice view on the `canonical_head`.
        canonical_head_write_lock.fork_choice_view = new_view;

        // If the head has changed, update `self.canonical_head`.
        let head_update_params = if new_view.head_block_root != old_view.head_block_root {
            metrics::inc_counter(&metrics::FORK_CHOICE_CHANGED_HEAD);

            // Try and obtain the snapshot for `beacon_block_root` from the snapshot cache, falling
            // back to a database read if that fails.
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
                        beacon_block,
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

            // Enshrine the new value as the head.
            canonical_head_write_lock.head_proposer_shuffling_decision_root = new_head
                .beacon_state
                .proposer_shuffling_decision_root(new_head.beacon_block_root)?;
            let old_head = mem::replace(&mut canonical_head_write_lock.head_snapshot, new_head);

            // Clear the early attester cache in case it conflicts with `self.canonical_head`.
            self.early_attester_cache.clear();

            Some((old_head, new_head_proto_block))
        } else {
            None
        };

        // Downgrade the write-lock to a read-lock, without allowing any other writers access.
        //
        // Holding the write-lock any longer than is required creates the risk of contention and
        // deadlocks. This is especially relevant since later parts of this function will interact
        // with other locks and potentially perform long-running operations.
        let canonical_head_read_lock = RwLockWriteGuard::downgrade(canonical_head_write_lock);

        // Alias for readability.
        let new_head = &canonical_head_read_lock.head_snapshot;

        // Update the execution layer since either the head or some finality parameters have
        // changed.
        //
        // Since we're spawning these tasks here *without* awaiting them, they'll happen
        // concurrently with the other calls in this function (e.g., cleaning caches and migrating
        // things from the hot database into the cold database).
        //
        // Notably, we're spawning these tasks whilst holding a read-lock on `self.canonical_head`.
        // There is a scenario where these spawned tasks will try to take a write-lock on
        // `self.canonical_head` (e.g., when the execution status of a block changes). Whilst some
        // lock contention might arise, this won't deadlock as long as we drop the read-lock on
        // `self.canonical_head` before waiting for these tasks to complete.
        let forkchoice_update_parameters = canonical_head_read_lock
            .fork_choice
            .get_forkchoice_update_parameters()
            .ok_or(Error::ForkchoiceUpdateParamsMissing)?;
        let el_update_handle =
            spawn_execution_layer_updates(self.clone(), forkchoice_update_parameters)?;

        // If the head changed, perform some updates.
        if let Some((old_head, new_head_proto_block)) = &head_update_params {
            if let Err(e) = self.after_new_head(old_head, new_head, new_head_proto_block) {
                crit!(
                    self.log,
                    "Error updating canonical head";
                    "error" => ?e
                );
            }
        }

        // If the finalized checkpoint changed, perform some updates.
        if new_view.finalized_checkpoint != old_view.finalized_checkpoint {
            if let Err(e) = self.after_finalization(new_head, new_view, &finalized_proto_block) {
                crit!(
                    self.log,
                    "Error updating finalization";
                    "error" => ?e
                );
            }
        }

        // The read-lock on the canonical head *MUST* be dropped before awaiting the completion of
        // the execution layer updates. Those updates might try to take a write-lock on the head, so
        // holding the read-lock until they complete may result in a **deadlock**.
        drop(canonical_head_read_lock);

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
        new_head_proto_block: &ProtoBlock,
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

        // Update the snapshot cache with the latest head value.
        //
        // TODO(paul): do this when we're mutating the snapshot cache to get the head?
        self.snapshot_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .map(|mut snapshot_cache| {
                snapshot_cache.update_head(new_head.beacon_block_root);
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
            new_head_proto_block,
            new_head.beacon_block.message().proposer_index(),
            new_head
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
                        block: new_head.beacon_block_root,
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
                    old_head_block: old_head.beacon_block_root,
                    old_head_state: old_head.beacon_state_root(),
                    new_head_block: new_head.beacon_block_root,
                    new_head_state: new_head.beacon_state_root(),
                    epoch: head_slot.epoch(T::EthSpec::slots_per_epoch()),
                }));
            }
        }

        Ok(())
    }

    fn after_finalization(
        &self,
        new_head: &BeaconSnapshot<T::EthSpec>,
        new_view: ForkChoiceView,
        finalized_proto_block: &ProtoBlock,
    ) -> Result<(), Error> {
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

        self.op_pool
            .prune_all(&new_head.beacon_state, self.epoch()?);

        self.store_migrator.process_finalization(
            finalized_proto_block.state_root.into(),
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
                    state: finalized_proto_block.state_root,
                }));
            }
        }

        Ok(())
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
                // See `Self::prepare_beacon_proposer_async` for more detail.
                if chain.slot_is_prior_to_bellatrix(current_slot + 1) {
                    return;
                }

                if let Err(e) = chain
                    .update_execution_engine_forkchoice_async(
                        current_slot,
                        forkchoice_update_params,
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
                if let Err(e) = chain.prepare_beacon_proposer_async(current_slot).await {
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
fn find_reorg_slot<E: EthSpec>(
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
