use std::sync::Arc;
use std::time::Duration;

use fork_choice::PayloadVerificationStatus;
use logging::crit;
use slot_clock::SlotClock;
use store::StoreOp;
use tracing::{debug, error, info, info_span, instrument, warn};
use types::{BeaconState, BlockImportSource, Hash256, SignedBeaconBlock, Slot};

use super::{
    AvailableEnvelope, AvailableExecutedEnvelope, EnvelopeError, EnvelopeImportData,
    ExecutedEnvelope, IntoExecutionPendingEnvelope, MaybeAvailableEnvelope,
};
use crate::{
    AvailabilityProcessingStatus, BeaconChain, BeaconChainError, BeaconChainTypes,
    NotifyExecutionLayer,
    block_verification_types::{AsBlock, AvailableBlockData},
    metrics,
    payload_envelope_verification::ExecutionPendingEnvelope,
    validator_monitor::{get_slot_delay_ms, timestamp_now},
};
use eth2::types::{EventKind, SseExecutionPayloadAvailable};

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `Ok(block_root)` if the given `unverified_envelope` was successfully verified and
    /// imported into the chain.
    ///
    /// Items that implement `IntoExecutionPendingEnvelope` include:
    ///
    /// - `GossipVerifiedEnvelope`
    /// - TODO(gloas) implement for envelopes recieved over RPC
    ///
    /// ## Errors
    ///
    /// Returns an `Err` if the given block was invalid, or an error was encountered during
    /// verification.
    #[instrument(skip_all, fields(block_root = ?block_root, block_source = %block_source))]
    pub async fn process_execution_payload_envelope<P: IntoExecutionPendingEnvelope<T>>(
        self: &Arc<Self>,
        block_root: Hash256,
        unverified_envelope: P,
        notify_execution_layer: NotifyExecutionLayer,
        block_source: BlockImportSource,
        publish_fn: impl FnOnce() -> Result<(), EnvelopeError>,
    ) -> Result<AvailabilityProcessingStatus, EnvelopeError> {
        let block_slot = unverified_envelope.envelope().slot();

        // Set observed time if not already set. Usually this should be set by gossip or RPC,
        // but just in case we set it again here (useful for tests).
        if let Some(seen_timestamp) = self.slot_clock.now_duration() {
            self.envelope_times_cache.write().set_time_observed(
                block_root,
                block_slot,
                seen_timestamp,
                None,
            );
        }

        // TODO(gloas) insert the pre-executed envelope into some type of cache.

        let _full_timer = metrics::start_timer(&metrics::ENVELOPE_PROCESSING_TIMES);

        metrics::inc_counter(&metrics::ENVELOPE_PROCESSING_REQUESTS);

        // A small closure to group the verification and import errors.
        let chain = self.clone();
        let import_envelope = async move {
            let execution_pending = unverified_envelope
                .into_execution_pending_envelope(&chain, notify_execution_layer)?;
            publish_fn()?;

            // Record the time it took to complete consensus verification.
            if let Some(timestamp) = chain.slot_clock.now_duration() {
                chain
                    .envelope_times_cache
                    .write()
                    .set_time_consensus_verified(block_root, block_slot, timestamp);
            }

            let envelope_times_cache = chain.envelope_times_cache.clone();
            let slot_clock = chain.slot_clock.clone();

            let executed_envelope = chain
                .into_executed_payload_envelope(execution_pending)
                .await
                .inspect_err(|_| {
                    // TODO(gloas) If the envelope fails execution for whatever reason (e.g. engine offline),
                    // and we keep it in the cache, then the node will NOT perform lookup and
                    // reprocess this block until the block is evicted from DA checker, causing the
                    // chain to get stuck temporarily if the block is canonical. Therefore we remove
                    // it from the cache if execution fails.
                })?;

            // Record the time it took to wait for execution layer verification.
            if let Some(timestamp) = slot_clock.now_duration() {
                envelope_times_cache
                    .write()
                    .set_time_executed(block_root, block_slot, timestamp);
            }

            match executed_envelope {
                ExecutedEnvelope::Available(envelope) => {
                    self.import_available_execution_payload_envelope(Box::new(envelope))
                        .await
                }
                ExecutedEnvelope::AvailabilityPending() => Err(EnvelopeError::InternalError(
                    "Pending payload envelope not yet implemented".to_owned(),
                )),
            }
        };

        // Verify and import the block.
        match import_envelope.await {
            // The block was successfully verified and imported. Yay.
            Ok(status @ AvailabilityProcessingStatus::Imported(block_root)) => {
                info!(
                    ?block_root,
                    %block_slot,
                    source = %block_source,
                    "Execution payload envelope imported"
                );

                metrics::inc_counter(&metrics::ENVELOPE_PROCESSING_SUCCESSES);

                Ok(status)
            }
            Ok(status @ AvailabilityProcessingStatus::MissingComponents(slot, block_root)) => {
                debug!(?block_root, %slot, "Beacon block awaiting blobs");

                Ok(status)
            }
            Err(EnvelopeError::BeaconChainError(e)) => {
                match e.as_ref() {
                    BeaconChainError::TokioJoin(e) => {
                        debug!(
                            error = ?e,
                            "Envelope processing cancelled"
                        );
                    }
                    _ => {
                        // There was an error whilst attempting to verify and import the block. The block might
                        // be partially verified or partially imported.
                        crit!(
                            error = ?e,
                            "Envelope processing error"
                        );
                    }
                };
                Err(EnvelopeError::BeaconChainError(e))
            }
            // The block failed verification.
            Err(other) => {
                warn!(
                    reason = other.to_string(),
                    "Execution payload envelope rejected"
                );
                Err(other)
            }
        }
    }

    /// Accepts a fully-verified payload envelope and awaits on its payload verification handle to
    /// get a fully `ExecutedEnvelope`.
    ///
    /// An error is returned if the verification handle couldn't be awaited.
    #[instrument(skip_all, level = "debug")]
    pub async fn into_executed_payload_envelope(
        self: Arc<Self>,
        pending_envelope: ExecutionPendingEnvelope<T::EthSpec>,
    ) -> Result<ExecutedEnvelope<T::EthSpec>, EnvelopeError> {
        let ExecutionPendingEnvelope {
            signed_envelope,
            import_data,
            payload_verification_handle,
        } = pending_envelope;

        let payload_verification_outcome = payload_verification_handle
            .await
            .map_err(BeaconChainError::TokioJoin)?
            .ok_or(BeaconChainError::RuntimeShutdown)??;

        // TODO(gloas): implement data column availability checking.
        // For now, treat all envelopes as available after EL verification with empty columns.
        let signed_envelope = match signed_envelope {
            available @ MaybeAvailableEnvelope::Available(_) => available,
            MaybeAvailableEnvelope::AvailabilityPending {
                block_hash,
                envelope,
            } => MaybeAvailableEnvelope::Available(AvailableEnvelope::new(
                block_hash,
                envelope,
                vec![],
                None,
                self.spec.clone(),
            )),
        };

        Ok(ExecutedEnvelope::new(
            signed_envelope,
            import_data,
            payload_verification_outcome,
        ))
    }

    #[instrument(skip_all)]
    pub async fn import_available_execution_payload_envelope(
        self: &Arc<Self>,
        envelope: Box<AvailableExecutedEnvelope<T::EthSpec>>,
    ) -> Result<AvailabilityProcessingStatus, EnvelopeError> {
        let AvailableExecutedEnvelope {
            envelope,
            import_data,
            payload_verification_outcome,
        } = *envelope;

        let EnvelopeImportData {
            block_root,
            block,
            post_state,
        } = import_data;

        let block_root = {
            // Capture the current span before moving into the blocking task
            let current_span = tracing::Span::current();
            let chain = self.clone();
            self.spawn_blocking_handle(
                move || {
                    // Enter the captured span in the blocking thread
                    let _guard = current_span.enter();
                    chain.import_execution_payload_envelope(
                        envelope,
                        block_root,
                        *post_state,
                        payload_verification_outcome.payload_verification_status,
                        block,
                    )
                },
                "payload_verification_handle",
            )
            .await??
        };

        Ok(AvailabilityProcessingStatus::Imported(block_root))
    }

    /// Accepts a fully-verified and available envelope and imports it into the chain without performing any
    /// additional verification.
    ///
    /// An error is returned if the envelope was unable to be imported. It may be partially imported
    /// (i.e., this function is not atomic).
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip_all)]
    fn import_execution_payload_envelope(
        &self,
        signed_envelope: AvailableEnvelope<T::EthSpec>,
        block_root: Hash256,
        state: BeaconState<T::EthSpec>,
        _payload_verification_status: PayloadVerificationStatus,
        parent_block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<Hash256, EnvelopeError> {
        // Everything in this initial section is on the hot path for processing the envelope.

        let post_exec_timer =
            metrics::start_timer(&metrics::ENVELOPE_PROCESSING_POST_EXEC_PROCESSING);

        // Check the payloads parent block against weak subjectivity checkpoint.
        self.check_block_against_weak_subjectivity_checkpoint(
            parent_block.message(),
            block_root,
            &state,
        )?;

        // Take an upgradable read lock on fork choice so we can check if this block has already
        // been imported. We don't want to repeat work importing a block that is already imported.
        let fork_choice_reader = self.canonical_head.fork_choice_upgradable_read_lock();
        if !fork_choice_reader.contains_block(&block_root) {
            return Err(EnvelopeError::BlockRootUnknown { block_root });
        }

        // Take an exclusive write-lock on fork choice. It's very important to prevent deadlocks by
        // avoiding taking other locks whilst holding this lock.
        let mut fork_choice = parking_lot::RwLockUpgradableReadGuard::upgrade(fork_choice_reader);

        // Update the node's payload_status from PENDING to FULL in fork choice.
        fork_choice
            .on_execution_payload(block_root)
            .map_err(|e| EnvelopeError::InternalError(format!("{e:?}")))?;

        // TODO(gloas) Do we need this check? Do not import a block that doesn't descend from the finalized root.
        // let signed_block = check_block_is_finalized_checkpoint_or_descendant(self, &fork_choice, signed_block)?;

        // TODO(gloas) Do we want to use an early attester cache like mechanism for payload enevelopes?
        // TODO(gloas) emit SSE event if the payload became the new head payload
        drop(post_exec_timer);

        // It is important NOT to return errors here before the database commit, because the envelope
        // has already been added to fork choice and the database would be left in an inconsistent
        // state if we returned early without committing. In other words, an error here would
        // corrupt the node's database permanently.

        // Store the envelope and its state, and execute the confirmation batch for the intermediate
        // states, which will delete their temporary flags.
        // If the write fails, revert fork choice to the version from disk, else we can
        // end up with envelopes in fork choice that are missing from disk.
        // See https://github.com/sigp/lighthouse/issues/2028
        let (signed_envelope, columns) = signed_envelope.deconstruct();

        let mut ops = vec![];

        match self.get_blobs_or_columns_store_op(
            block_root,
            signed_envelope.slot(),
            AvailableBlockData::DataColumns(columns),
        ) {
            Ok(Some(blobs_or_columns_store_op)) => {
                ops.push(blobs_or_columns_store_op);
            }
            Ok(None) => {}
            Err(e) => {
                error!(
                    msg = "Restoring fork choice from disk",
                    error = &e,
                    ?block_root,
                    "Failed to store data columns into the database"
                );
                // TODO(gloas) implement failed write handling to fork choice
                // let _ = self.handle_import_block_db_write_error(fork_choice);
                return Err(EnvelopeError::InternalError(e));
            }
        }

        let db_write_timer = metrics::start_timer(&metrics::ENVELOPE_PROCESSING_DB_WRITE);

        ops.push(StoreOp::PutPayloadEnvelope(
            block_root,
            signed_envelope.clone(),
        ));
        ops.push(StoreOp::PutState(
            signed_envelope.message.state_root,
            &state,
        ));

        let db_span = info_span!("persist_payloads_and_blobs").entered();

        if let Err(e) = self.store.do_atomically_with_block_and_blobs_cache(ops) {
            error!(
                msg = "Restoring fork choice from disk",
                error = ?e,
                "Database write failed!"
            );
            // TODO(gloas) handle db write failure
            // return Err(self
            //    .handle_import_block_db_write_error(fork_choice)
            //    .err()
            //    .unwrap_or(e.into()));
        }

        drop(db_span);

        // The fork choice write-lock is dropped *after* the on-disk database has been updated.
        // This prevents inconsistency between the two at the expense of concurrency.
        drop(fork_choice);

        // We're declaring the envelope "imported" at this point, since fork choice and the DB know
        // about it.
        let envelope_time_imported = timestamp_now();

        // TODO(gloas) depending on what happens with light clients
        // we might need to do some light client related computations here

        metrics::stop_timer(db_write_timer);
        metrics::inc_counter(&metrics::ENVELOPE_PROCESSING_SUCCESSES);

        self.import_envelope_update_metrics_and_events(
            block_root,
            signed_envelope.slot(),
            envelope_time_imported,
        );

        Ok(block_root)
    }

    fn import_envelope_update_metrics_and_events(
        &self,
        block_root: Hash256,
        envelope_slot: Slot,
        envelope_time_imported: Duration,
    ) {
        let envelope_delay_total =
            get_slot_delay_ms(envelope_time_imported, envelope_slot, &self.slot_clock);

        // Do not write to the cache for envelopes older than 2 epochs, this helps reduce writes
        // to the cache during sync.
        if envelope_delay_total < self.slot_clock.slot_duration().saturating_mul(64) {
            self.envelope_times_cache.write().set_time_imported(
                block_root,
                envelope_slot,
                envelope_time_imported,
            );
        }

        // Beacon API execution_payload_available events
        if let Some(event_handler) = self.event_handler.as_ref()
            && event_handler.has_execution_payload_available_subscribers()
        {
            event_handler.register(EventKind::ExecutionPayloadAvailable(
                SseExecutionPayloadAvailable {
                    slot: envelope_slot,
                    block_root,
                },
            ));
        }
    }
}
