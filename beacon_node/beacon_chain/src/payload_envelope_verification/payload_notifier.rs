use std::sync::Arc;

use execution_layer::NewPayloadRequest;
use fork_choice::PayloadVerificationStatus;
use state_processing::{
    envelope_processing::partially_verify_payload_envelope,
    per_block_processing::is_execution_enabled,
};
use tracing::warn;
use types::{
    BeaconState, ExecutionPayloadBid, Hash256, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
};

use crate::{
    BeaconChain, BeaconChainTypes, BlockError, ExecutionPayloadError, NotifyExecutionLayer,
    execution_payload::notify_new_payload,
};

/// Used to await the result of executing payload with a remote EE.
pub struct PayloadNotifier<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    pub envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
    payload_verification_status: Option<PayloadVerificationStatus>,
}

impl<T: BeaconChainTypes> PayloadNotifier<T> {
    pub fn new(
        chain: Arc<BeaconChain<T>>,
        bid: &ExecutionPayloadBid<T::EthSpec>,
        envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        state: &BeaconState<T::EthSpec>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<Self, ExecutionPayloadError> {
        let payload_verification_status = {
            // Perform the initial stages of payload verification.
            //
            // We will duplicate these checks again during `per_block_processing`, however these
            // checks are cheap and doing them here ensures we have verified them before marking
            // the block as optimistically imported. This is particularly relevant in the case
            // where we do not send the block to the EL at all.
            let payload_message = &envelope.message;
            partially_verify_payload_envelope(state, &envelope, &chain.spec).unwrap(); // TODO(gloas) unwrap

            match notify_execution_layer {
                NotifyExecutionLayer::No if chain.config.optimistic_finalized_sync => {
                    // Create a NewPayloadRequest (no clones required) and check optimistic sync verifications
                    let new_payload_request: NewPayloadRequest<T::EthSpec> =
                        payload_message.try_into()?;
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
            payload_verification_status,
        })
    }

    pub async fn notify_new_payload(self) -> Result<PayloadVerificationStatus, BlockError> {
        if let Some(precomputed_status) = self.payload_verification_status {
            Ok(precomputed_status)
        } else {
            // tODO(gloas) fix zero
            notify_new_payload(
                &self.chain,
                Hash256::ZERO,
                self.envelope.message.try_into()?,
            )
            .await
        }
    }
}
