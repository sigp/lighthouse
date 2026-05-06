use crate::BeaconNodeFallback;
use eth2::types::{EventKind, EventTopic, Hash256};
use futures::StreamExt;
use slot_clock::SlotClock;
use std::sync::Arc;
use tracing::{debug, info, warn};
use types::{EthSpec, Slot};

/// Event emitted when an execution payload envelope becomes available for a slot.
#[derive(Debug, Clone)]
pub struct PayloadEnvelopeEvent {
    pub slot: Slot,
    pub block_root: Hash256,
}

/// Runs a non-terminating loop that subscribes to `ExecutionPayloadAvailable` SSE events
/// from all connected beacon nodes and forwards them over an mpsc channel.
///
/// This follows the same pattern as `poll_head_event_from_beacon_nodes`.
pub async fn poll_payload_envelope_event_from_beacon_nodes<E: EthSpec, T: SlotClock + 'static>(
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
) -> Result<(), String> {
    let payload_envelope_send = beacon_nodes
        .payload_envelope_send
        .clone()
        .ok_or("Unable to start payload envelope monitor without payload_envelope_send")?;

    info!("Starting payload envelope monitoring service");
    let candidates = {
        let candidates_guard = beacon_nodes.candidates.read().await;
        candidates_guard.clone()
    };

    // Create Vec of streams, which we will select over.
    let mut streams = vec![];

    for candidate in &candidates {
        let event_stream = candidate
            .beacon_node
            .get_events::<E>(&[EventTopic::ExecutionPayloadAvailable])
            .await;

        let event_stream = match event_stream {
            Ok(stream) => stream,
            Err(e) => {
                warn!(error = ?e, node_index = candidate.index, "Failed to get execution payload available event stream");
                continue;
            }
        };

        streams.push(event_stream.map(|event| (candidate.index, event)));
    }

    if streams.is_empty() {
        return Err(
            "No beacon nodes available for execution payload available event streaming".to_string(),
        );
    }

    // Combine streams into a single stream and poll events from any of them.
    let mut combined_stream = futures::stream::select_all(streams);

    while let Some((candidate_index, event_result)) = combined_stream.next().await {
        match event_result {
            Ok(EventKind::ExecutionPayloadAvailable(payload_event)) => {
                debug!(
                    candidate_index,
                    block_root = ?payload_event.block_root,
                    slot = %payload_event.slot,
                    "Execution payload available from beacon node"
                );

                if payload_envelope_send
                    .send(PayloadEnvelopeEvent {
                        slot: payload_event.slot,
                        block_root: payload_event.block_root,
                    })
                    .await
                    .is_err()
                {
                    return Err("Payload envelope monitoring service channel closed".into());
                }
            }
            Ok(event) => {
                warn!(
                    event_kind = event.topic_name(),
                    candidate_index,
                    "Received unexpected event from BN in payload envelope monitor"
                );
                continue;
            }
            Err(e) => {
                return Err(format!(
                    "Payload envelope monitoring stream error, node: {candidate_index}, error: {e:?}"
                ));
            }
        }
    }

    Err("Payload envelope stream ended unexpectedly".into())
}
