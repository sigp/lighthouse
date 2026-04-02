use std::sync::Arc;
use std::time::Duration;

use eth2::types::{EventKind, SseExecutionPayload};
use fork_choice::PayloadVerificationStatus;
use slot_clock::SlotClock;
use store::StoreOp;
use tracing::{debug, error, info, info_span, instrument, warn};
use types::{BeaconState, BlockImportSource, Hash256, SignedExecutionPayloadEnvelope};

use super::{
    AvailableEnvelope, AvailableExecutedEnvelope, EnvelopeError, EnvelopeImportData,
    ExecutedEnvelope, gossip_verified_envelope::GossipVerifiedEnvelope,
};
use crate::{
    AvailabilityProcessingStatus, BeaconChain, BeaconChainError, BeaconChainTypes,
    NotifyExecutionLayer, block_verification_types::AvailableBlockData, metrics,
    payload_envelope_verification::ExecutionPendingEnvelope, validator_monitor::get_slot_delay_ms,
};

const ENVELOPE_METRICS_CACHE_SLOT_LIMIT: u32 = 64;

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `Ok(status)` if the given `unverified_envelope` was successfully verified and
    /// imported into the chain.
    ///
    /// ## Errors
    ///
    /// Returns an `Err` if the given payload envelope was invalid, or an error was encountered during
    /// verification.
    #[instrument(skip_all, fields(block_root = ?block_root, block_source = %block_source))]
    pub async fn process_execution_payload_envelope(
        self: &Arc<Self>,
        block_root: Hash256,
        unverified_envelope: GossipVerifiedEnvelope<T>,
        notify_execution_layer: NotifyExecutionLayer,
        block_source: BlockImportSource,
        publish_fn: impl FnOnce() -> Result<(), EnvelopeError>,
    ) -> Result<AvailabilityProcessingStatus, EnvelopeError> {
        let block_slot = unverified_envelope.signed_envelope.slot();

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

            // TODO(gloas): rename/refactor these `into_` names to be less similar and more clear
            // about what the function actually does.
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

        // Verify and import the payload envelope.
        match import_envelope.await {
            // The payload envelope was successfully verified and imported.
            Ok(status @ AvailabilityProcessingStatus::Imported(block_root)) => {
                info!(
                    ?block_root,
                    %block_slot,
                    source = %block_source,
                    "Execution payload envelope imported"
                );

                // TODO(gloas) do we need to send a `PayloadImported` event to the reprocess queue?
                // TODO(gloas) do we need to recompute head?
                // should canonical_head return the block and the payload now?
                self.recompute_head_at_current_slot().await;

                metrics::inc_counter(&metrics::ENVELOPE_PROCESSING_SUCCESSES);

                Ok(status)
            }
            Ok(status @ AvailabilityProcessingStatus::MissingComponents(slot, block_root)) => {
                debug!(?block_root, %slot, "Payload envelope awaiting blobs");

                Ok(status)
            }
            Err(EnvelopeError::BeaconChainError(e)) => {
                if matches!(e.as_ref(), BeaconChainError::TokioJoin(_)) {
                    debug!(error = ?e, "Envelope processing cancelled");
                } else {
                    warn!(error = ?e, "Execution payload envelope rejected");
                }
                Err(EnvelopeError::BeaconChainError(e))
            }
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
    async fn into_executed_payload_envelope(
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
            post_state,
        } = import_data;

        let block_root = {
            let chain = self.clone();
            self.spawn_blocking_handle(
                move || {
                    chain.import_execution_payload_envelope(
                        envelope,
                        block_root,
                        *post_state,
                        payload_verification_outcome.payload_verification_status,
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
        payload_verification_status: PayloadVerificationStatus,
    ) -> Result<Hash256, EnvelopeError> {
        // Everything in this initial section is on the hot path for processing the envelope.
        // Take an upgradable read lock on fork choice so we can check if this block has already
        // been imported. We don't want to repeat work importing a block that is already imported.
        let fork_choice_reader = self.canonical_head.fork_choice_upgradable_read_lock();
        if !fork_choice_reader.contains_block(&block_root) {
            return Err(EnvelopeError::BlockRootUnknown { block_root });
        }

        // TODO(gloas) add defensive check to see if payload envelope is already in fork choice
        // Note that a duplicate cache/payload status table should prevent this from happening
        // but it doesnt hurt to be defensive.

        // TODO(gloas) when the code below is implemented we can delete this drop
        drop(fork_choice_reader);

        // TODO(gloas) no fork choice logic yet
        // Take an exclusive write-lock on fork choice. It's very important to prevent deadlocks by
        // avoiding taking other locks whilst holding this lock.
        // let fork_choice = parking_lot::RwLockUpgradableReadGuard::upgrade(fork_choice_reader);

        // TODO(gloas) Do we need this check? Do not import a block that doesn't descend from the finalized root.
        // let signed_block = check_block_is_finalized_checkpoint_or_descendant(self, &fork_choice, signed_block)?;

        // TODO(gloas) emit SSE event if the payload became the new head payload

        // It is important NOT to return errors here before the database commit, because the envelope
        // has already been added to fork choice and the database would be left in an inconsistent
        // state if we returned early without committing. In other words, an error here would
        // corrupt the node's database permanently.

        // Store the envelope, its post-state, and any data columns.
        // If the write fails, revert fork choice to the version from disk, else we can
        // end up with envelopes in fork choice that are missing from disk.
        // See https://github.com/sigp/lighthouse/issues/2028
        let (signed_envelope, columns) = signed_envelope.deconstruct();

        let mut ops = vec![];

        if let Some(blobs_or_columns_store_op) = self.get_blobs_or_columns_store_op(
            block_root,
            signed_envelope.slot(),
            AvailableBlockData::DataColumns(columns),
        ) {
            ops.push(blobs_or_columns_store_op);
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
            return Err(e.into());
            // TODO(gloas) handle db write failure
            // return Err(self
            //    .handle_import_block_db_write_error(fork_choice)
            //    .err()
            //    .unwrap_or(e.into()));
        }

        drop(db_span);

        // TODO(gloas) drop fork choice lock
        // The fork choice write-lock is dropped *after* the on-disk database has been updated.
        // This prevents inconsistency between the two at the expense of concurrency.
        // drop(fork_choice);

        // We're declaring the envelope "imported" at this point, since fork choice and the DB know
        // about it.
        let envelope_time_imported = self.slot_clock.now_duration().unwrap_or(Duration::MAX);

        // TODO(gloas) depending on what happens with light clients
        // we might need to do some light client related computations here

        metrics::stop_timer(db_write_timer);

        self.import_envelope_update_metrics_and_events(
            signed_envelope,
            block_root,
            payload_verification_status,
            envelope_time_imported,
        );

        Ok(block_root)
    }

    fn import_envelope_update_metrics_and_events(
        &self,
        signed_envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        block_root: Hash256,
        payload_verification_status: PayloadVerificationStatus,
        envelope_time_imported: Duration,
    ) {
        let envelope_slot = signed_envelope.slot();
        let envelope_delay_total =
            get_slot_delay_ms(envelope_time_imported, envelope_slot, &self.slot_clock);

        // Do not write to the cache for envelopes older than 2 epochs, this helps reduce writes
        // to the cache during sync.
        if envelope_delay_total
            < self
                .slot_clock
                .slot_duration()
                .saturating_mul(ENVELOPE_METRICS_CACHE_SLOT_LIMIT)
        {
            self.envelope_times_cache.write().set_time_imported(
                block_root,
                envelope_slot,
                envelope_time_imported,
            );
        }

        if let Some(event_handler) = self.event_handler.as_ref()
            && event_handler.has_execution_payload_subscribers()
        {
            event_handler.register(EventKind::ExecutionPayload(SseExecutionPayload {
                slot: envelope_slot,
                builder_index: signed_envelope.message.builder_index,
                block_hash: signed_envelope.block_hash(),
                block_root,
                state_root: signed_envelope.message.state_root,
                execution_optimistic: payload_verification_status.is_optimistic(),
            }));
        }
    }
}
