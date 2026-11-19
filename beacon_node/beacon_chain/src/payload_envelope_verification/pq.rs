use super::{AvailabilityPendingExecutedEnvelope, EnvelopeError, load_snapshot_from_state_root};
use crate::{
    AvailabilityProcessingStatus, BeaconChain, BeaconChainError, BeaconChainTypes, BlockError,
    PayloadVerificationOutcome, metrics,
};
use execution_layer::{NewPayloadRequest, NewPayloadRequestGloas};
use slot_clock::SlotClock;
use ssz::Encode;
use state_processing::{
    envelope_processing::verify_pq_execution_payload_envelope,
    per_block_processing::deneb::kzg_commitment_to_versioned_hash,
};
use std::sync::Arc;
use store::DatabaseBlock;
use types::{
    EthSpec, ExecutionPayloadEnvelopeGloas, ExecutionRequestsRef, ForkName, SignedBeaconBlock,
    SignedExecutionPayloadBid, SignedExecutionPayloadEnvelopeGloas,
    SignedExecutionPayloadEnvelopePq,
};

pub struct VerifiedPqEnvelope<T: BeaconChainTypes> {
    envelope: Arc<SignedExecutionPayloadEnvelopePq<T::EthSpec>>,
    bid: Arc<SignedExecutionPayloadBid<T::EthSpec>>,
    pub block: Arc<SignedBeaconBlock<T::EthSpec>>,
}

impl<T: BeaconChainTypes> VerifiedPqEnvelope<T> {
    pub fn blob_commitment_count(&self) -> usize {
        self.bid.message().blob_kzg_commitments().len()
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub async fn verify_pq_envelope_for_gossip(
        self: &Arc<Self>,
        envelope: Arc<SignedExecutionPayloadEnvelopePq<T::EthSpec>>,
    ) -> Result<VerifiedPqEnvelope<T>, EnvelopeError> {
        let chain = Arc::clone(self);
        let observed = self.slot_clock.now_duration();
        self.task_executor.spawn_blocking_handle(move || {
            let message = &envelope.message;
            let block_root = message.beacon_block_root;
            let slot = message.payload.slot_number;
            let finalized = chain.canonical_head.cached_head().finalized_checkpoint().epoch.start_slot(T::EthSpec::slots_per_epoch());
            if slot < finalized {
                return Err(EnvelopeError::PriorToFinalization { payload_slot: slot, latest_finalized_slot: finalized });
            }
            let proto_block = chain.canonical_head.fork_choice_read_lock().get_block(&block_root)
                .ok_or(EnvelopeError::BlockRootUnknown { block_root })?;
            if proto_block.payload_received {
                return Err(EnvelopeError::EnvelopeAlreadySeen { block_root, builder_index: message.builder_index });
            }
            let Some(DatabaseBlock::Full(SignedBeaconBlock::Pq(block))) = chain.store.try_get_full_block(&block_root)? else {
                return Err(EnvelopeError::from(BeaconChainError::MissingBeaconBlock(block_root)));
            };
            if chain.spec.fork_name_at_slot::<T::EthSpec>(slot) != ForkName::Pq || slot != block.message.slot {
                return Err(EnvelopeError::SlotMismatch { block: block.message.slot, envelope: slot });
            }
            let snapshot = load_snapshot_from_state_root::<T>(block_root, proto_block.state_root, &chain.store)?;
            state_processing::per_block_processing::verify_pq_execution_request_list_lengths(&message.execution_requests)
                .map_err(|error| EnvelopeError::InternalError(format!("invalid PQ execution request counts: {error:?}")))?;
            let _signature_timer = metrics::start_timer(&metrics::PQ_XMSS_VERIFY_SECONDS);
            verify_pq_execution_payload_envelope(&snapshot.pre_state, &envelope, snapshot.state_root, &chain.spec)?;
            drop(_signature_timer);
            let bid = Arc::new(SignedExecutionPayloadBid::Pq(block.message.body.signed_execution_payload_bid.clone()));
            let request = payload_request::<T::EthSpec>(&envelope, &bid);
            if chain.config.verify_envelope_payload_hash_on_cl || chain.execution_layer.is_none() {
                request.perform_optimistic_sync_verifications()
                    .map_err(|error| EnvelopeError::InvalidPayloadHash(format!("{error:?}")))?;
            }
            // The shared pending/storage path retains the exact PQ authentication
            // separately from the common payload header and body.
            if envelope.ssz_bytes_len() > chain.config.max_network_size {
                return Err(EnvelopeError::OperationListTooLong {
                    kind: "pq_envelope_bytes",
                    length: envelope.ssz_bytes_len(),
                    max: chain.config.max_network_size,
                });
            }
            if let Some(timestamp) = observed {
                chain.envelope_times_cache.write().set_time_observed(block_root, slot, timestamp, None);
            }
            if let Some(timestamp) = chain.slot_clock.now_duration() {
                chain.envelope_times_cache.write().set_time_consensus_verified(block_root, slot, timestamp);
            }
            Ok(VerifiedPqEnvelope { envelope, bid, block: Arc::new(SignedBeaconBlock::Pq(block)) })
        }, "pq_verify_envelope")
            .ok_or(BeaconChainError::RuntimeShutdown)?
            .await.map_err(BeaconChainError::TokioJoin)?
    }

    pub async fn process_verified_pq_envelope(
        self: &Arc<Self>,
        verified: VerifiedPqEnvelope<T>,
    ) -> Result<AvailabilityProcessingStatus, BlockError> {
        let VerifiedPqEnvelope { envelope, bid, .. } = verified;
        let message = &envelope.message;
        let block_root = message.beacon_block_root;
        let slot = message.payload.slot_number;
        let request = payload_request::<T::EthSpec>(&envelope, &bid);
        let status = crate::execution_payload::notify_new_payload(self, slot, request)
            .await
            .map_err(EnvelopeError::from)?;
        if let Some(timestamp) = self.slot_clock.now_duration() {
            self.envelope_times_cache
                .write()
                .set_time_executed(block_root, slot, timestamp);
        }
        let projected = SignedExecutionPayloadEnvelopeGloas {
            message: ExecutionPayloadEnvelopeGloas {
                payload: message.payload.clone(),
                execution_requests: message.execution_requests.common_requests(),
                builder_index: message.builder_index,
                beacon_block_root: block_root,
                parent_beacon_block_root: message.parent_beacon_block_root,
            },
            signature: bls::Signature::empty(),
        };
        self.check_envelope_availability_and_import(
            AvailabilityPendingExecutedEnvelope {
                envelope: Arc::new(projected),
                pq_auth: Some(Arc::new((
                    message.execution_requests.clone(),
                    envelope.signature.clone(),
                ))),
                block_root,
                payload_verification_outcome: PayloadVerificationOutcome {
                    payload_verification_status: status,
                },
            },
            &bid,
        )
        .await
    }
}

fn payload_request<'a, E: EthSpec>(
    envelope: &'a SignedExecutionPayloadEnvelopePq<E>,
    bid: &'a SignedExecutionPayloadBid<E>,
) -> NewPayloadRequest<'a, E> {
    NewPayloadRequest::Gloas(NewPayloadRequestGloas {
        execution_payload: &envelope.message.payload,
        versioned_hashes: bid
            .message()
            .blob_kzg_commitments()
            .iter()
            .map(kzg_commitment_to_versioned_hash)
            .collect(),
        parent_beacon_block_root: envelope.message.parent_beacon_block_root,
        execution_requests: ExecutionRequestsRef::Pq(&envelope.message.execution_requests),
    })
}
