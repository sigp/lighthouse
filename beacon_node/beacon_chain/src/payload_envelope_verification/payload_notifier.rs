use std::sync::Arc;

use execution_layer::{
    NewPayloadRequest, NewPayloadRequestGloas, NewPayloadRequestHeze, PayloadStatus,
};
use fork_choice::PayloadVerificationStatus;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use tracing::warn;
use types::{SignedBeaconBlock, SignedExecutionPayloadEnvelope};

use crate::{
    BeaconChain, BeaconChainTypes, NotifyExecutionLayer, PayloadVerificationError,
    execution_payload::notify_new_payload, payload_envelope_verification::EnvelopeError,
};

/// Used to await the result of executing payload with a remote EE.
pub struct PayloadNotifier<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    payload_verification_status: Option<PayloadVerificationStatus>,
}

impl<T: BeaconChainTypes> PayloadNotifier<T> {
    pub fn new(
        chain: Arc<BeaconChain<T>>,
        envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<Self, EnvelopeError> {
        let payload_verification_status = {
            match notify_execution_layer {
                NotifyExecutionLayer::No if chain.config.optimistic_finalized_sync => {
                    let new_payload_request =
                        Self::build_new_payload_request(&envelope, &block, &chain)?;
                    // TODO(gloas): check and test RLP block hash calculation post-Gloas
                    if let Err(e) = new_payload_request.perform_optimistic_sync_verifications() {
                        warn!(
                            block_number = ?envelope.message().payload().block_number(),
                            info = "you can silence this warning with --disable-optimistic-finalized-sync",
                            error = ?e,
                            "Falling back to slow block hash verification"
                        );
                        None
                    } else {
                        Some(PayloadVerificationStatus::Optimistic)
                    }
                }
                _ => None,
            }
        };

        Ok(Self {
            chain,
            envelope,
            block,
            payload_verification_status,
        })
    }

    pub async fn notify_new_payload(
        self,
    ) -> Result<PayloadVerificationStatus, PayloadVerificationError> {
        if let Some(precomputed_status) = self.payload_verification_status {
            Ok(precomputed_status)
        } else {
            let parent_root = self.block.message().parent_root();
            let request =
                Self::build_new_payload_request(&self.envelope, &self.block, &self.chain)?;
            let (verification_status, payload_status) =
                notify_new_payload(&self.chain, self.envelope.slot(), parent_root, request).await?;

            // Record the engine's inclusion-list verdict for fork choice's
            // `should_extend_payload` (spec: `record_payload_inclusion_list_satisfaction`).
            // Satisfaction MUST NOT affect payload validation, so this is tracked
            // separately from the verification status. No verdict is recorded while the
            // engine is syncing.
            if matches!(
                self.envelope.as_ref(),
                SignedExecutionPayloadEnvelope::Heze(_)
            ) {
                let il_satisfied = match payload_status {
                    PayloadStatus::Valid => Some(true),
                    PayloadStatus::InclusionListUnsatisfied => Some(false),
                    _ => None,
                };
                if let Some(satisfied) = il_satisfied {
                    self.chain
                        .record_payload_inclusion_list_satisfaction(
                            self.envelope.beacon_block_root(),
                            satisfied,
                        )
                        .await
                        .map_err(|e| PayloadVerificationError::BeaconChainError(Box::new(e)))?;
                }
            }

            Ok(verification_status)
        }
    }

    fn build_new_payload_request<'a>(
        envelope: &'a SignedExecutionPayloadEnvelope<T::EthSpec>,
        block: &'a SignedBeaconBlock<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<NewPayloadRequest<'a, T::EthSpec>, PayloadVerificationError> {
        let bid = block
            .message()
            .body()
            .signed_execution_payload_bid()
            .map_err(|e| PayloadVerificationError::BeaconChainError(Box::new(e.into())))?;
        let bid_message = bid.message();

        let versioned_hashes = bid_message
            .blob_kzg_commitments()
            .iter()
            .map(kzg_commitment_to_versioned_hash)
            .collect();

        match envelope {
            SignedExecutionPayloadEnvelope::Heze(inner) => {
                // A payload at slot N is constrained by the timely inclusion lists of the
                // slot N - 1 committee (spec: `get_inclusion_list_transactions(store, state,
                // state.slot - 1)`); the engine evaluates EIP-7805 satisfaction against them.
                let il_slot = envelope.slot().saturating_sub(1_u64);
                let il_transactions = chain
                    .inclusion_list_cache
                    .read()
                    .get_inclusion_list_transactions(il_slot, true)
                    .unwrap_or_default();
                Ok(NewPayloadRequest::Heze(NewPayloadRequestHeze {
                    execution_payload: &inner.message.payload,
                    versioned_hashes,
                    parent_beacon_block_root: inner.message.parent_beacon_block_root,
                    execution_requests: &inner.message.execution_requests,
                    il_transactions,
                }))
            }
            SignedExecutionPayloadEnvelope::Gloas(inner) => {
                Ok(NewPayloadRequest::Gloas(NewPayloadRequestGloas {
                    execution_payload: &inner.message.payload,
                    versioned_hashes,
                    parent_beacon_block_root: inner.message.parent_beacon_block_root,
                    execution_requests: &inner.message.execution_requests,
                }))
            }
        }
    }
}
