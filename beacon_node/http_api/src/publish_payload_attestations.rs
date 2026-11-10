//! Import payload attestation messages and publish them to the network.
//!
//! This module gracefully handles messages to unknown blocks by requeuing them and then
//! efficiently waiting for them to finish reprocessing (using an async yield).
use crate::task_spawner::{Priority, TaskSpawner};
use beacon_chain::payload_attestation_verification::Error as PayloadAttestationError;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use beacon_processor::work_reprocessing_queue::{QueuedPayloadAttestation, ReprocessQueueMessage};
use beacon_processor::{Work, WorkEvent};
use eth2::types::Failure;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use std::sync::Arc;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use tracing::{debug, error, warn};
use types::PayloadAttestationMessage;

#[derive(Debug)]
pub enum Error {
    Validation(PayloadAttestationError),
    Publication,
    ReprocessFull,
    ReprocessTimeout,
}

enum PublishPayloadAttestationResult {
    Success,
    AlreadyKnown,
    Reprocessing(oneshot::Receiver<Result<(), Error>>),
    Failure(Error),
}

fn verify_and_publish_payload_attestation<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    message: &PayloadAttestationMessage,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<(), Error> {
    let verified = chain
        .verify_payload_attestation_message_for_gossip(message.clone())
        .map_err(Error::Validation)?;

    network_tx
        .send(NetworkMessage::Publish {
            messages: vec![PubsubMessage::PayloadAttestation(Box::new(message.clone()))],
        })
        .map_err(|_| Error::Publication)?;

    if let Err(e) = chain.apply_payload_attestation_to_fork_choice(
        verified.indexed_payload_attestation(),
        verified.ptc(),
    ) {
        warn!(
            error = ?e,
            "Payload attestation invalid for fork choice"
        );
    }

    if let Err(e) = chain.add_payload_attestation_to_pool(&verified) {
        warn!(
            reason = ?e,
            "Failed to add payload attestation to pool"
        );
    }

    Ok(())
}

pub async fn publish_payload_attestations<T: BeaconChainTypes>(
    task_spawner: TaskSpawner<T::EthSpec>,
    chain: Arc<BeaconChain<T>>,
    messages: Vec<PayloadAttestationMessage>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<(), warp::Rejection> {
    // Gossip validate and publish messages that can be immediately processed.
    let mut prelim_results = task_spawner
        .clone()
        .blocking_task(Priority::P0, move || {
            Ok(messages
                .into_iter()
                .map(|message| {
                    match verify_and_publish_payload_attestation(&chain, &message, &network_tx) {
                        Ok(()) => PublishPayloadAttestationResult::Success,
                        Err(Error::Validation(PayloadAttestationError::UnknownHeadBlock {
                            beacon_block_root,
                        })) => {
                            // Re-process.
                            let (tx, rx) = oneshot::channel();
                            let reprocess_chain = chain.clone();
                            let reprocess_network_tx = network_tx.clone();
                            let reprocess_fn = move || {
                                let result = verify_and_publish_payload_attestation(
                                    &reprocess_chain,
                                    &message,
                                    &reprocess_network_tx,
                                );
                                // Ignore failure on the oneshot that reports the result. This
                                // shouldn't happen unless some catastrophe befalls the waiting
                                // thread which causes it to drop.
                                let _ = tx.send(result);
                            };
                            let reprocess_msg =
                                ReprocessQueueMessage::UnknownBlockPayloadAttestation(
                                    QueuedPayloadAttestation {
                                        beacon_block_root,
                                        process_fn: Box::new(reprocess_fn),
                                    },
                                );
                            if task_spawner
                                .try_send(WorkEvent {
                                    drop_during_sync: false,
                                    work: Work::Reprocess(reprocess_msg),
                                })
                                .is_err()
                            {
                                PublishPayloadAttestationResult::Failure(Error::ReprocessFull)
                            } else {
                                PublishPayloadAttestationResult::Reprocessing(rx)
                            }
                        }
                        Err(Error::Validation(
                            PayloadAttestationError::PriorPayloadAttestationMessageKnown { .. },
                        )) => PublishPayloadAttestationResult::AlreadyKnown,
                        Err(e) => PublishPayloadAttestationResult::Failure(e),
                    }
                })
                .map(Some)
                .collect::<Vec<_>>())
        })
        .await?;

    // Asynchronously wait for re-processing of messages to unknown blocks. This avoids blocking
    // any of the beacon processor workers while we wait for reprocessing.
    let (reprocess_indices, reprocess_futures): (Vec<_>, Vec<_>) = prelim_results
        .iter_mut()
        .enumerate()
        .filter_map(|(i, opt_result)| {
            if let Some(PublishPayloadAttestationResult::Reprocessing(..)) = &opt_result {
                let PublishPayloadAttestationResult::Reprocessing(rx) = opt_result.take()? else {
                    // Unreachable.
                    return None;
                };
                Some((i, rx))
            } else {
                None
            }
        })
        .unzip();
    let reprocess_results = futures::future::join_all(reprocess_futures).await;

    // Join everything back together and construct a response.
    // This part should be quick so we just stay in the Tokio executor's async task.
    for (i, reprocess_result) in reprocess_indices.into_iter().zip(reprocess_results) {
        let Some(result_entry) = prelim_results.get_mut(i) else {
            error!(
                case = "prelim out of bounds",
                request_index = i,
                "Unreachable case in payload attestation publishing"
            );
            continue;
        };
        *result_entry = Some(match reprocess_result {
            Ok(Ok(())) => PublishPayloadAttestationResult::Success,
            // Payload attestation failed processing on re-process.
            Ok(Err(Error::Validation(
                PayloadAttestationError::PriorPayloadAttestationMessageKnown { .. },
            ))) => PublishPayloadAttestationResult::AlreadyKnown,
            Ok(Err(e)) => PublishPayloadAttestationResult::Failure(e),
            // Oneshot was dropped, indicating that the message either timed out in the
            // reprocess queue or was dropped due to some error.
            Err(_) => PublishPayloadAttestationResult::Failure(Error::ReprocessTimeout),
        });
    }

    // Construct the response.
    let mut failures = vec![];
    let mut num_already_known = 0;

    for (index, result) in prelim_results.iter().enumerate() {
        match result {
            Some(PublishPayloadAttestationResult::Success) => {}
            Some(PublishPayloadAttestationResult::AlreadyKnown) => num_already_known += 1,
            Some(PublishPayloadAttestationResult::Failure(e)) => {
                error!(
                    error = ?e,
                    request_index = index,
                    "Failure verifying payload attestation for gossip"
                );
                failures.push(Failure::new(index, format!("{e:?}")));
            }
            Some(PublishPayloadAttestationResult::Reprocessing(_)) => {
                error!(
                    case = "reprocessing",
                    request_index = index,
                    "Unreachable case in payload attestation publishing"
                );
                failures.push(Failure::new(index, "reprocess logic error".into()));
            }
            None => {
                error!(
                    case = "result is None",
                    request_index = index,
                    "Unreachable case in payload attestation publishing"
                );
                failures.push(Failure::new(index, "result logic error".into()));
            }
        }
    }

    if num_already_known > 0 {
        debug!(
            count = num_already_known,
            "Some payload attestations already known"
        );
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(warp_utils::reject::indexed_bad_request(
            "error processing payload attestations".to_string(),
            failures,
        ))
    }
}
