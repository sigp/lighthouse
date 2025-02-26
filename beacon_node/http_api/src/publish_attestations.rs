//! Import attestations and publish them to the network.
//!
//! This module gracefully handles attestations to unknown blocks by requeuing them and then
//! efficiently waiting for them to finish reprocessing (using an async yield).
//!
//! The following comments relate to the handling of duplicate attestations (relocated here during
//! refactoring):
//!
//! Skip to the next attestation since an attestation for this
//! validator is already known in this epoch.
//!
//! There's little value for the network in validating a second
//! attestation for another validator since it is either:
//!
//! 1. A duplicate.
//! 2. Slashable.
//! 3. Invalid.
//!
//! We are likely to get duplicates in the case where a VC is using
//! fallback BNs. If the first BN actually publishes some/all of a
//! batch of attestations but fails to respond in a timely fashion,
//! the VC is likely to try publishing the attestations on another
//! BN. That second BN may have already seen the attestations from
//! the first BN and therefore indicate that the attestations are
//! "already seen". An attestation that has already been seen has
//! been published on the network so there's no actual error from
//! the perspective of the user.
//!
//! It's better to prevent slashable attestations from ever
//! appearing on the network than trying to slash validators,
//! especially those validators connected to the local API.
//!
//! There might be *some* value in determining that this attestation
//! is invalid, but since a valid attestation already it exists it
//! appears that this validator is capable of producing valid
//! attestations and there's no immediate cause for concern.
use crate::task_spawner::{Priority, TaskSpawner};
use beacon_chain::{
    single_attestation::single_attestation_to_attestation, validator_monitor::timestamp_now,
    AttestationError, BeaconChain, BeaconChainError, BeaconChainTypes,
};
use beacon_processor::work_reprocessing_queue::{QueuedUnaggregate, ReprocessQueueMessage};
use either::Either;
use eth2::types::Failure;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use serde_json::Value;
use slog::{debug, error, warn, Logger};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{
    mpsc::{Sender, UnboundedSender},
    oneshot,
};
use types::{Attestation, EthSpec, ForkName, SingleAttestation};

// Error variants are only used in `Debug` and considered `dead_code` by the compiler.
#[derive(Debug)]
pub enum Error {
    Validation(AttestationError),
    Publication,
    ForkChoice(#[allow(dead_code)] BeaconChainError),
    AggregationPool(#[allow(dead_code)] AttestationError),
    ReprocessDisabled,
    ReprocessFull,
    ReprocessTimeout,
    InvalidJson(#[allow(dead_code)] serde_json::Error),
    FailedConversion(#[allow(dead_code)] BeaconChainError),
}

enum PublishAttestationResult {
    Success,
    AlreadyKnown,
    Reprocessing(oneshot::Receiver<Result<(), Error>>),
    Failure(Error),
}

#[allow(clippy::type_complexity)]
pub fn deserialize_attestation_payload<T: BeaconChainTypes>(
    payload: Value,
    fork_name: Option<ForkName>,
    log: &Logger,
) -> Result<Vec<Either<Attestation<T::EthSpec>, SingleAttestation>>, Error> {
    if fork_name.is_some_and(|fork_name| fork_name.electra_enabled()) || fork_name.is_none() {
        if fork_name.is_none() {
            warn!(
                log,
                "No Consensus Version header specified.";
            );
        }

        Ok(serde_json::from_value::<Vec<SingleAttestation>>(payload)
            .map_err(Error::InvalidJson)?
            .into_iter()
            .map(Either::Right)
            .collect())
    } else {
        Ok(
            serde_json::from_value::<Vec<Attestation<T::EthSpec>>>(payload)
                .map_err(Error::InvalidJson)?
                .into_iter()
                .map(Either::Left)
                .collect(),
        )
    }
}

fn verify_and_publish_attestation<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    either_attestation: &Either<Attestation<T::EthSpec>, SingleAttestation>,
    seen_timestamp: Duration,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: &Logger,
) -> Result<(), Error> {
    let attestation = convert_to_attestation(chain, either_attestation)?;
    let verified_attestation = chain
        .verify_unaggregated_attestation_for_gossip(&attestation, None)
        .map_err(Error::Validation)?;

    match either_attestation {
        Either::Left(attestation) => {
            // Publish.
            network_tx
                .send(NetworkMessage::Publish {
                    messages: vec![PubsubMessage::Attestation(Box::new((
                        verified_attestation.subnet_id(),
                        attestation.clone(),
                    )))],
                })
                .map_err(|_| Error::Publication)?;
        }
        Either::Right(single_attestation) => {
            network_tx
                .send(NetworkMessage::Publish {
                    messages: vec![PubsubMessage::SingleAttestation(Box::new((
                        verified_attestation.subnet_id(),
                        single_attestation.clone(),
                    )))],
                })
                .map_err(|_| Error::Publication)?;
        }
    }

    // Notify the validator monitor.
    chain
        .validator_monitor
        .read()
        .register_api_unaggregated_attestation(
            seen_timestamp,
            verified_attestation.indexed_attestation(),
            &chain.slot_clock,
        );

    let fc_result = chain.apply_attestation_to_fork_choice(&verified_attestation);
    let naive_aggregation_result = chain.add_to_naive_aggregation_pool(&verified_attestation);

    if let Err(e) = &fc_result {
        warn!(
            log,
            "Attestation invalid for fork choice";
            "err" => ?e,
        );
    }
    if let Err(e) = &naive_aggregation_result {
        warn!(
            log,
            "Attestation invalid for aggregation";
            "err" => ?e
        );
    }

    if let Err(e) = fc_result {
        Err(Error::ForkChoice(e))
    } else if let Err(e) = naive_aggregation_result {
        Err(Error::AggregationPool(e))
    } else {
        Ok(())
    }
}

fn convert_to_attestation<'a, T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    attestation: &'a Either<Attestation<T::EthSpec>, SingleAttestation>,
) -> Result<Cow<'a, Attestation<T::EthSpec>>, Error> {
    match attestation {
        Either::Left(a) => Ok(Cow::Borrowed(a)),
        Either::Right(single_attestation) => {
            let conversion_result = chain.with_committee_cache(
                single_attestation.data.target.root,
                single_attestation
                    .data
                    .slot
                    .epoch(T::EthSpec::slots_per_epoch()),
                |committee_cache, _| {
                    let Some(committee) = committee_cache.get_beacon_committee(
                        single_attestation.data.slot,
                        single_attestation.committee_index,
                    ) else {
                        return Ok(Err(AttestationError::NoCommitteeForSlotAndIndex {
                            slot: single_attestation.data.slot,
                            index: single_attestation.committee_index,
                        }));
                    };

                    Ok(single_attestation_to_attestation::<T::EthSpec>(
                        single_attestation,
                        committee.committee,
                    )
                    .map(Cow::Owned))
                },
            );
            match conversion_result {
                Ok(Ok(attestation)) => Ok(attestation),
                Ok(Err(e)) => Err(Error::Validation(e)),
                // Map the error returned by `with_committee_cache` for unknown blocks into the
                // `UnknownHeadBlock` error that is gracefully handled.
                Err(BeaconChainError::MissingBeaconBlock(beacon_block_root)) => {
                    Err(Error::Validation(AttestationError::UnknownHeadBlock {
                        beacon_block_root,
                    }))
                }
                Err(e) => Err(Error::FailedConversion(e)),
            }
        }
    }
}

pub async fn publish_attestations<T: BeaconChainTypes>(
    task_spawner: TaskSpawner<T::EthSpec>,
    chain: Arc<BeaconChain<T>>,
    attestations: Vec<Either<Attestation<T::EthSpec>, SingleAttestation>>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    reprocess_send: Option<Sender<ReprocessQueueMessage>>,
    log: Logger,
) -> Result<(), warp::Rejection> {
    // Collect metadata about attestations which we'll use to report failures. We need to
    // move the `attestations` vec into the blocking task, so this small overhead is unavoidable.
    let attestation_metadata = attestations
        .iter()
        .map(|att| match att {
            Either::Left(att) => (att.data().slot, att.committee_index()),
            Either::Right(att) => (att.data.slot, Some(att.committee_index)),
        })
        .collect::<Vec<_>>();

    // Gossip validate and publish attestations that can be immediately processed.
    let seen_timestamp = timestamp_now();
    let inner_log = log.clone();
    let mut prelim_results = task_spawner
        .blocking_task(Priority::P0, move || {
            Ok(attestations
                .into_iter()
                .map(|attestation| {
                    match verify_and_publish_attestation(
                        &chain,
                        &attestation,
                        seen_timestamp,
                        &network_tx,
                        &inner_log,
                    ) {
                        Ok(()) => PublishAttestationResult::Success,
                        Err(Error::Validation(AttestationError::UnknownHeadBlock {
                            beacon_block_root,
                        })) => {
                            let Some(reprocess_tx) = &reprocess_send else {
                                return PublishAttestationResult::Failure(Error::ReprocessDisabled);
                            };
                            // Re-process.
                            let (tx, rx) = oneshot::channel();
                            let reprocess_chain = chain.clone();
                            let reprocess_network_tx = network_tx.clone();
                            let reprocess_log = inner_log.clone();
                            let reprocess_fn = move || {
                                let result = verify_and_publish_attestation(
                                    &reprocess_chain,
                                    &attestation,
                                    seen_timestamp,
                                    &reprocess_network_tx,
                                    &reprocess_log,
                                );
                                // Ignore failure on the oneshot that reports the result. This
                                // shouldn't happen unless some catastrophe befalls the waiting
                                // thread which causes it to drop.
                                let _ = tx.send(result);
                            };
                            let reprocess_msg =
                                ReprocessQueueMessage::UnknownBlockUnaggregate(QueuedUnaggregate {
                                    beacon_block_root,
                                    process_fn: Box::new(reprocess_fn),
                                });
                            if reprocess_tx.try_send(reprocess_msg).is_err() {
                                PublishAttestationResult::Failure(Error::ReprocessFull)
                            } else {
                                PublishAttestationResult::Reprocessing(rx)
                            }
                        }
                        Err(Error::Validation(AttestationError::PriorAttestationKnown {
                            ..
                        })) => PublishAttestationResult::AlreadyKnown,
                        Err(e) => PublishAttestationResult::Failure(e),
                    }
                })
                .map(Some)
                .collect::<Vec<_>>())
        })
        .await?;

    // Asynchronously wait for re-processing of attestations to unknown blocks. This avoids blocking
    // any of the beacon processor workers while we wait for reprocessing.
    let (reprocess_indices, reprocess_futures): (Vec<_>, Vec<_>) = prelim_results
        .iter_mut()
        .enumerate()
        .filter_map(|(i, opt_result)| {
            if let Some(PublishAttestationResult::Reprocessing(..)) = &opt_result {
                let PublishAttestationResult::Reprocessing(rx) = opt_result.take()? else {
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
                log,
                "Unreachable case in attestation publishing";
                "case" => "prelim out of bounds",
                "request_index" => i,
            );
            continue;
        };
        *result_entry = Some(match reprocess_result {
            Ok(Ok(())) => PublishAttestationResult::Success,
            // Attestation failed processing on re-process.
            Ok(Err(Error::Validation(AttestationError::PriorAttestationKnown { .. }))) => {
                PublishAttestationResult::AlreadyKnown
            }
            Ok(Err(e)) => PublishAttestationResult::Failure(e),
            // Oneshot was dropped, indicating that the attestation either timed out in the
            // reprocess queue or was dropped due to some error.
            Err(_) => PublishAttestationResult::Failure(Error::ReprocessTimeout),
        });
    }

    // Construct the response.
    let mut failures = vec![];
    let mut num_already_known = 0;

    for (index, result) in prelim_results.iter().enumerate() {
        match result {
            Some(PublishAttestationResult::Success) => {}
            Some(PublishAttestationResult::AlreadyKnown) => num_already_known += 1,
            Some(PublishAttestationResult::Failure(e)) => {
                if let Some((slot, committee_index)) = attestation_metadata.get(index) {
                    error!(
                        log,
                        "Failure verifying attestation for gossip";
                        "error" => ?e,
                        "request_index" => index,
                        "committee_index" => committee_index,
                        "attestation_slot" => slot,
                    );
                    failures.push(Failure::new(index, format!("{e:?}")));
                } else {
                    error!(
                        log,
                        "Unreachable case in attestation publishing";
                        "case" => "out of bounds",
                        "request_index" => index
                    );
                    failures.push(Failure::new(index, "metadata logic error".into()));
                }
            }
            Some(PublishAttestationResult::Reprocessing(_)) => {
                error!(
                    log,
                    "Unreachable case in attestation publishing";
                    "case" => "reprocessing",
                    "request_index" => index
                );
                failures.push(Failure::new(index, "reprocess logic error".into()));
            }
            None => {
                error!(
                    log,
                    "Unreachable case in attestation publishing";
                    "case" => "result is None",
                    "request_index" => index
                );
                failures.push(Failure::new(index, "result logic error".into()));
            }
        }
    }

    if num_already_known > 0 {
        debug!(
            log,
            "Some unagg attestations already known";
            "count" => num_already_known
        );
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(warp_utils::reject::indexed_bad_request(
            "error processing attestations".to_string(),
            failures,
        ))
    }
}
