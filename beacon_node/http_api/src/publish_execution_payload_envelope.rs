use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};
use types::SignedExecutionPayloadEnvelope;
use warp::{Rejection, Reply, reply::Response};

/// Publishes a signed execution payload envelope to the network.
pub async fn publish_execution_payload_envelope<T: BeaconChainTypes>(
    envelope: SignedExecutionPayloadEnvelope<T::EthSpec>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<Response, Rejection> {
    let slot = envelope.message.slot;
    let beacon_block_root = envelope.message.beacon_block_root;

    // Basic validation: check that the slot is reasonable
    let current_slot = chain.slot().map_err(|_| {
        warp_utils::reject::custom_server_error("Unable to get current slot".into())
    })?;

    // Don't accept envelopes too far in the future
    if slot > current_slot + 1 {
        return Err(warp_utils::reject::custom_bad_request(format!(
            "Envelope slot {} is too far in the future (current slot: {})",
            slot, current_slot
        )));
    }

    // TODO(gloas): Add more validation:
    // - Verify the signature
    // - Check builder_index is valid
    // - Verify the envelope references a known block

    info!(
        %slot,
        %beacon_block_root,
        builder_index = envelope.message.builder_index,
        "Publishing signed execution payload envelope to network"
    );

    // Publish to the network
    crate::utils::publish_pubsub_message(
        network_tx,
        PubsubMessage::ExecutionPayload(Box::new(envelope)),
    )
    .map_err(|_| {
        warn!(%slot, "Failed to publish execution payload envelope to network");
        warp_utils::reject::custom_server_error(
            "Unable to publish execution payload envelope to network".into(),
        )
    })?;

    Ok(warp::reply().into_response())
}
