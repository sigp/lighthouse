use std::{sync::Arc, time::Duration};

use beacon_chain::inclusion_list_verification::GossipInclusionListError;
use beacon_chain::{validator_monitor::timestamp_now, BeaconChain, BeaconChainTypes};
use beacon_processor::work_reprocessing_queue::ReprocessQueueMessage;
use eth2::types::Failure;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use tokio::sync::{
    mpsc::{Sender, UnboundedSender},
    oneshot,
};
use tracing::{debug, error, info};
use types::SignedInclusionList;

use crate::task_spawner::{Priority, TaskSpawner};

enum PublishInclusionListResult {
    Success,
    #[allow(dead_code)]
    Reprocessing(oneshot::Receiver<Result<(), Error>>),
    Failure(Error),
    AlreadyKnown,
}

#[derive(Debug)]
pub enum Error {
    Validation(GossipInclusionListError),
    Publication,
    ReprocessTimeout,
}

pub async fn publish_inclusion_lists<T: BeaconChainTypes>(
    task_spawner: TaskSpawner<T::EthSpec>,
    chain: Arc<BeaconChain<T>>,
    inclusion_lists: Vec<SignedInclusionList<T::EthSpec>>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    _reprocess_send: Option<Sender<ReprocessQueueMessage>>,
) -> Result<(), warp::Rejection> {
    // Gossip validate and publish inclusion lists that can be immediately processed.
    let seen_timestamp = timestamp_now();
    let inclusion_list_metadata = inclusion_lists
        .iter()
        .map(|inclusion_list| {
            (
                inclusion_list.message.slot,
                inclusion_list.message.validator_index,
            )
        })
        .collect::<Vec<_>>();

    let mut prelim_results = task_spawner
        .blocking_task(Priority::P0, move || {
            Ok(inclusion_lists
                .into_iter()
                .map(move |inclusion_list| {
                    match verify_and_publish_inclusion_list(
                        &chain,
                        &inclusion_list,
                        seen_timestamp,
                        &network_tx,
                    ) {
                        Ok(()) => {
                            debug!("Successfully verified gossip inclusion list");
                            PublishInclusionListResult::Success
                        }
                        Err(e) => {
                            debug!(
                                error = ?e,
                                "Failed to verify gossip inclusion list"
                            );
                            PublishInclusionListResult::Failure(e)
                        }
                    }
                })
                .map(Some)
                .collect::<Vec<_>>())
        })
        .await?;

    let (reprocess_indices, reprocess_futures): (Vec<_>, Vec<_>) = prelim_results
        .iter_mut()
        .enumerate()
        .filter_map(|(i, opt_result)| {
            if let Some(PublishInclusionListResult::Reprocessing(..)) = &opt_result {
                let PublishInclusionListResult::Reprocessing(rx) = opt_result.take()? else {
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
                "Unreachable case in inclusion list publishing",
            );
            continue;
        };
        *result_entry = Some(match reprocess_result {
            Ok(Ok(())) => PublishInclusionListResult::Success,
            // Inclusion list already known
            Ok(Err(Error::Validation(GossipInclusionListError::PriorInclusionListKnown))) => {
                PublishInclusionListResult::AlreadyKnown
            }
            Ok(Err(e)) => PublishInclusionListResult::Failure(e),
            // Oneshot was dropped, indicating that the inclusion list either timed out in the
            // reprocess queue or was dropped due to some error.
            Err(_) => PublishInclusionListResult::Failure(Error::ReprocessTimeout),
        });
    }

    // Construct the response.
    let mut failures = vec![];
    let mut num_already_known = 0;

    for (index, result) in prelim_results.iter().enumerate() {
        match result {
            Some(PublishInclusionListResult::Success) => {}
            Some(PublishInclusionListResult::AlreadyKnown) => num_already_known += 1,
            Some(PublishInclusionListResult::Failure(e)) => {
                if let Some((slot, validator_index)) = inclusion_list_metadata.get(index) {
                    error!(
                        error = ?e,
                        request_index = index,
                        validator_index,
                        il_slot = ?slot,
                        "Failure verifying attestation for gossip"
                    );
                    failures.push(Failure::new(index, format!("{e:?}")));
                } else {
                    error!(
                        case = "out of bounds",
                        request_index = index,
                        "Unreachable case in inclusion list publishing",
                    );
                    failures.push(Failure::new(index, "metadata logic error".into()));
                }
            }
            Some(PublishInclusionListResult::Reprocessing(_)) => {
                // TODO(focil) reprocessing
                info!("Reprocessing result");
            }
            None => {
                error!(
                    case = "result is None",
                    request_index = index,
                    "Unreachable case in inclusion list publishing",
                );
                failures.push(Failure::new(index, "result logic error".into()));
            }
        }
    }

    if num_already_known > 0 {
        debug!(num_already_known, "Some inclusion lists already known");
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(warp_utils::reject::indexed_bad_request(
            "error processing inclusion list".to_string(),
            failures,
        ))
    }
}

fn verify_and_publish_inclusion_list<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    inclusion_list: &SignedInclusionList<T::EthSpec>,
    seen_timestamp: Duration,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<(), Error> {
    let verified_inclusion_list = chain
        .verify_inclusion_list_for_gossip(inclusion_list)
        .map_err(Error::Validation)?;

    network_tx
        .send(NetworkMessage::Publish {
            messages: vec![PubsubMessage::InclusionList(Box::new(
                verified_inclusion_list.signed_il.clone(),
            ))],
        })
        .map_err(|_| Error::Publication)?;

    info!(
        slot = ?verified_inclusion_list.signed_il.message.slot,
        validator_index = verified_inclusion_list.signed_il.message.validator_index,
        "Verified inclusion list and republished"
    );

    // TODO(focil) add reprocess logic?

    // Notify the validator monitor.
    chain.validator_monitor.read().register_api_inclusion_list(
        seen_timestamp,
        &verified_inclusion_list.signed_il,
        &chain.slot_clock,
    );

    // Store verified IL in the IL cache
    chain.on_verified_inclusion_list(verified_inclusion_list.signed_il);

    Ok(())
}
