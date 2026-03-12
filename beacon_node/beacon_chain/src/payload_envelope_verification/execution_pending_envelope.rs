use std::sync::Arc;

use slot_clock::SlotClock;
use state_processing::{
    VerifySignatures,
    envelope_processing::{VerifyStateRoot, process_execution_payload_envelope},
};
use types::EthSpec;

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, NotifyExecutionLayer,
    PayloadVerificationOutcome,
    block_verification::PayloadVerificationHandle,
    payload_envelope_verification::{
        EnvelopeError, EnvelopeImportData, MaybeAvailableEnvelope,
        gossip_verified_envelope::GossipVerifiedEnvelope, load_snapshot_from_state_root,
        payload_notifier::PayloadNotifier,
    },
};

pub struct ExecutionPendingEnvelope<E: EthSpec> {
    pub signed_envelope: MaybeAvailableEnvelope<E>,
    pub import_data: EnvelopeImportData<E>,
    pub payload_verification_handle: PayloadVerificationHandle,
}

impl<T: BeaconChainTypes> GossipVerifiedEnvelope<T> {
    pub fn into_execution_pending_envelope(
        self,
        chain: &Arc<BeaconChain<T>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<ExecutionPendingEnvelope<T::EthSpec>, EnvelopeError> {
        let signed_envelope = self.signed_envelope;
        let envelope = &signed_envelope.message;
        let payload = &envelope.payload;

        // Define a future that will verify the execution payload with an execution engine.
        //
        // We do this as early as possible so that later parts of this function can run in parallel
        // with the payload verification.
        let payload_notifier = PayloadNotifier::new(
            chain.clone(),
            signed_envelope.clone(),
            self.block.clone(),
            notify_execution_layer,
        )?;
        let block_root = envelope.beacon_block_root;
        let slot = self.block.slot();

        let payload_verification_future = async move {
            let chain = payload_notifier.chain.clone();
            if let Some(started_execution) = chain.slot_clock.now_duration() {
                chain
                    .envelope_times_cache
                    .write()
                    .set_time_started_execution(block_root, slot, started_execution);
            }

            let payload_verification_status = payload_notifier.notify_new_payload().await?;
            Ok(PayloadVerificationOutcome {
                payload_verification_status,
            })
        };
        // Spawn the payload verification future as a new task, but don't wait for it to complete.
        // The `payload_verification_future` will be awaited later to ensure verification completed
        // successfully.
        let payload_verification_handle = chain
            .task_executor
            .spawn_handle(
                payload_verification_future,
                "execution_payload_verification",
            )
            .ok_or(BeaconChainError::RuntimeShutdown)?;

        let snapshot = if let Some(snapshot) = self.snapshot {
            *snapshot
        } else {
            load_snapshot_from_state_root::<T>(block_root, self.block.state_root(), &chain.store)?
        };
        let mut state = snapshot.pre_state;

        // All the state modifications are done in envelope_processing
        process_execution_payload_envelope(
            &mut state,
            Some(snapshot.state_root),
            &signed_envelope,
            // verify signature already done for GossipVerifiedEnvelope
            VerifySignatures::False,
            VerifyStateRoot::True,
            &chain.spec,
        )?;

        Ok(ExecutionPendingEnvelope {
            signed_envelope: MaybeAvailableEnvelope::AvailabilityPending {
                block_hash: payload.block_hash,
                envelope: signed_envelope,
            },
            import_data: EnvelopeImportData {
                block_root,
                post_state: Box::new(state),
            },
            payload_verification_handle,
        })
    }
}
