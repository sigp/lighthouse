use std::sync::Arc;

use execution_layer::{NewPayloadRequest, NewPayloadRequestGloas};
use fork_choice::PayloadVerificationStatus;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use tracing::warn;
use types::{SignedBeaconBlock, SignedExecutionPayloadEnvelope};

use crate::{
    BeaconChain, BeaconChainTypes, BlockError, NotifyExecutionLayer,
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
            let payload_message = &envelope.message;

            match notify_execution_layer {
                NotifyExecutionLayer::No if chain.config.optimistic_finalized_sync => {
                    let new_payload_request = Self::build_new_payload_request(&envelope, &block)
                        .map_err(EnvelopeError::ImportError)?;
                    // TODO(gloas): check and test RLP block hash calculation post-Gloas
                    if let Err(e) = new_payload_request.perform_optimistic_sync_verifications() {
                        warn!(
                            block_number = ?payload_message.payload.block_number,
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

    pub async fn notify_new_payload(self) -> Result<PayloadVerificationStatus, BlockError> {
        if let Some(precomputed_status) = self.payload_verification_status {
            Ok(precomputed_status)
        } else {
            let parent_root = self.block.message().parent_root();
            let request = Self::build_new_payload_request(&self.envelope, &self.block)?;
            notify_new_payload(&self.chain, self.envelope.slot(), parent_root, request).await
        }
    }

    fn build_new_payload_request<'a>(
        envelope: &'a SignedExecutionPayloadEnvelope<T::EthSpec>,
        block: &'a SignedBeaconBlock<T::EthSpec>,
    ) -> Result<NewPayloadRequest<'a, T::EthSpec>, BlockError> {
        let bid = &block
            .message()
            .body()
            .signed_execution_payload_bid()
            .map_err(|e| BlockError::BeaconChainError(Box::new(e.into())))?
            .message;

        let versioned_hashes = bid
            .blob_kzg_commitments
            .iter()
            .map(kzg_commitment_to_versioned_hash)
            .collect();

        Ok(NewPayloadRequest::Gloas(NewPayloadRequestGloas {
            execution_payload: &envelope.message.payload,
            versioned_hashes,
            parent_beacon_block_root: envelope.message.parent_beacon_block_root,
            execution_requests: &envelope.message.execution_requests,
        }))
    }
}
