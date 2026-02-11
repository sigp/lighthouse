use std::sync::Arc;

use crate::{AvailabilityProcessingStatus, BeaconChain, BeaconChainTypes, payload_envelope_verification::{ExecutedEnvelope, ExecutionPendingEnvelope}};

async fn import_execution_pending_envelope<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    execution_pending_envelope: ExecutionPendingEnvelope<T>,
) -> Result<AvailabilityProcessingStatus, String> {
    match chain
        .clone()
        .into_executed_payload_envelope(execution_pending_envelope)
        .await
        .unwrap()
    {
        ExecutedEnvelope::Available(envelope) => todo!(),
        ExecutedEnvelope::AvailabilityPending() => {
            Err("AvailabilityPending not expected in this test. Block not imported.".to_string())
        }
    }
}
