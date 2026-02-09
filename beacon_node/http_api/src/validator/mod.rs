use crate::produce_block::{produce_blinded_block_v2, produce_block_v2, produce_block_v3};
use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{
    AnyVersionFilter, ChainFilter, EthV1Filter, NetworkTxFilter, NotWhileSyncingFilter,
    ResponseFilter, TaskSpawnerFilter, ValidatorSubscriptionTxFilter, publish_network_message,
};
use crate::version::V3;
use crate::{StateId, attester_duties, proposer_duties, sync_committees};
use beacon_chain::attestation_verification::VerifiedAttestation;
use beacon_chain::validator_monitor::timestamp_now;
use beacon_chain::{AttestationError, BeaconChain, BeaconChainError, BeaconChainTypes};
use bls::PublicKeyBytes;
use eth2::StatusCode;
use eth2::types::{
    Accept, BeaconCommitteeSubscription, EndpointVersion, Failure, GenericResponse,
    StandardLivenessResponseData, StateId as CoreStateId, ValidatorAggregateAttestationQuery,
    ValidatorAttestationDataQuery, ValidatorBlocksQuery, ValidatorIndexData, ValidatorStatus,
};
use lighthouse_network::PubsubMessage;
use network::{NetworkMessage, ValidatorSubscriptionMessage};
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};
use types::{
    BeaconState, Epoch, EthSpec, ProposerPreparationData, SignedAggregateAndProof,
    SignedContributionAndProof, SignedValidatorRegistrationData, Slot, SyncContributionData,
    ValidatorSubscription,
};
use warp::{Filter, Rejection, Reply};
use warp_utils::reject::convert_rejection;

/// Uses the `chain.validator_pubkey_cache` to resolve a pubkey to a validator
/// index and then ensures that the validator exists in the given `state`.
pub fn pubkey_to_validator_index<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    pubkey: &PublicKeyBytes,
) -> Result<Option<usize>, Box<BeaconChainError>> {
    chain
        .validator_index(pubkey)
        .map_err(Box::new)?
        .filter(|&index| {
            state
                .validators()
                .get(index)
                .is_some_and(|v| v.pubkey == *pubkey)
        })
        .map(Result::Ok)
        .transpose()
}

// GET validator/sync_committee_contribution
pub fn get_validator_sync_committee_contribution<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("sync_committee_contribution"))
        .and(warp::path::end())
        .and(warp::query::<SyncContributionData>())
        .and(not_while_syncing_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |sync_committee_data: SyncContributionData,
             not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    not_synced_filter?;
                    chain
                        .get_aggregated_sync_committee_contribution(&sync_committee_data)
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!(
                                "unable to fetch sync contribution: {:?}",
                                e
                            ))
                        })?
                        .map(GenericResponse::from)
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(
                                "no matching sync contribution found".to_string(),
                            )
                        })
                })
            },
        )
        .boxed()
}

// POST validator/duties/sync/{epoch}
pub fn post_validator_duties_sync<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("duties"))
        .and(warp::path("sync"))
        .and(warp::path::param::<Epoch>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid epoch".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |epoch: Epoch,
             not_synced_filter: Result<(), Rejection>,
             indices: ValidatorIndexData,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    not_synced_filter?;
                    sync_committees::sync_committee_duties(epoch, &indices.0, &chain)
                })
            },
        )
        .boxed()
}

// POST validator/duties/attester/{epoch}
pub fn post_validator_duties_attester<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("duties"))
        .and(warp::path("attester"))
        .and(warp::path::param::<Epoch>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid epoch".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |epoch: Epoch,
             not_synced_filter: Result<(), Rejection>,
             indices: ValidatorIndexData,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    not_synced_filter?;
                    attester_duties::attester_duties(epoch, &indices.0, &chain)
                })
            },
        )
        .boxed()
}

// GET validator/aggregate_attestation?attestation_data_root,slot
pub fn get_validator_aggregate_attestation<T: BeaconChainTypes>(
    any_version: AnyVersionFilter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    any_version
        .and(warp::path("validator"))
        .and(warp::path("aggregate_attestation"))
        .and(warp::path::end())
        .and(warp::query::<ValidatorAggregateAttestationQuery>())
        .and(not_while_syncing_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |endpoint_version: EndpointVersion,
             query: ValidatorAggregateAttestationQuery,
             not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_response_task(Priority::P0, move || {
                    not_synced_filter?;
                    crate::aggregate_attestation::get_aggregate_attestation(
                        query.slot,
                        &query.attestation_data_root,
                        query.committee_index,
                        endpoint_version,
                        chain,
                    )
                })
            },
        )
        .boxed()
}

// GET validator/attestation_data?slot,committee_index
pub fn get_validator_attestation_data<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("attestation_data"))
        .and(warp::path::end())
        .and(warp::query::<ValidatorAttestationDataQuery>())
        .and(not_while_syncing_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |query: ValidatorAttestationDataQuery,
             not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    not_synced_filter?;

                    let current_slot = chain.slot().map_err(warp_utils::reject::unhandled_error)?;

                    // allow a tolerance of one slot to account for clock skew
                    if query.slot > current_slot + 1 {
                        return Err(warp_utils::reject::custom_bad_request(format!(
                            "request slot {} is more than one slot past the current slot {}",
                            query.slot, current_slot
                        )));
                    }

                    chain
                        .produce_unaggregated_attestation(query.slot, query.committee_index)
                        .map(|attestation| attestation.data().clone())
                        .map(GenericResponse::from)
                        .map_err(warp_utils::reject::unhandled_error)
                })
            },
        )
        .boxed()
}

// GET validator/blinded_blocks/{slot}
pub fn get_validator_blinded_blocks<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("blinded_blocks"))
        .and(warp::path::param::<Slot>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid slot".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(warp::query::<ValidatorBlocksQuery>())
        .and(warp::header::optional::<Accept>("accept"))
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |slot: Slot,
             not_synced_filter: Result<(), Rejection>,
             query: ValidatorBlocksQuery,
             accept_header: Option<Accept>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    not_synced_filter?;
                    produce_blinded_block_v2(accept_header, chain, slot, query).await
                })
            },
        )
        .boxed()
}

// GET validator/blocks/{slot}
pub fn get_validator_blocks<T: BeaconChainTypes>(
    any_version: AnyVersionFilter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    any_version
        .and(warp::path("validator"))
        .and(warp::path("blocks"))
        .and(warp::path::param::<Slot>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid slot".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(warp::header::optional::<Accept>("accept"))
        .and(not_while_syncing_filter)
        .and(warp::query::<ValidatorBlocksQuery>())
        .and(task_spawner_filter)
        .and(chain_filter)
        .then(
            |endpoint_version: EndpointVersion,
             slot: Slot,
             accept_header: Option<Accept>,
             not_synced_filter: Result<(), Rejection>,
             query: ValidatorBlocksQuery,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    debug!(?slot, "Block production request from HTTP API");

                    not_synced_filter?;

                    if endpoint_version == V3 {
                        produce_block_v3(accept_header, chain, slot, query).await
                    } else {
                        produce_block_v2(accept_header, chain, slot, query).await
                    }
                })
            },
        )
        .boxed()
}

// POST validator/liveness/{epoch}
pub fn post_validator_liveness_epoch<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("liveness"))
        .and(warp::path::param::<Epoch>())
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |epoch: Epoch,
             indices: ValidatorIndexData,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    // Ensure the request is for either the current, previous or next epoch.
                    let current_epoch =
                        chain.epoch().map_err(warp_utils::reject::unhandled_error)?;
                    let prev_epoch = current_epoch.saturating_sub(Epoch::new(1));
                    let next_epoch = current_epoch.saturating_add(Epoch::new(1));

                    if epoch < prev_epoch || epoch > next_epoch {
                        return Err(warp_utils::reject::custom_bad_request(format!(
                            "request epoch {} is more than one epoch from the current epoch {}",
                            epoch, current_epoch
                        )));
                    }

                    let liveness: Vec<StandardLivenessResponseData> = indices
                        .0
                        .iter()
                        .cloned()
                        .map(|index| {
                            let is_live = chain.validator_seen_at_epoch(index as usize, epoch);
                            StandardLivenessResponseData { index, is_live }
                        })
                        .collect();

                    Ok(GenericResponse::from(liveness))
                })
            },
        )
        .boxed()
}

// POST validator/sync_committee_subscriptions
pub fn post_validator_sync_committee_subscriptions<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    validator_subscription_tx_filter: ValidatorSubscriptionTxFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("sync_committee_subscriptions"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(validator_subscription_tx_filter)
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |subscriptions: Vec<types::SyncCommitteeSubscription>,
             validator_subscription_tx: Sender<ValidatorSubscriptionMessage>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
            | {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    for subscription in subscriptions {
                        chain
                            .validator_monitor
                            .write()
                            .auto_register_local_validator(subscription.validator_index);

                        let message = ValidatorSubscriptionMessage::SyncCommitteeSubscribe {
                            subscriptions: vec![subscription],
                        };
                        if let Err(e) = validator_subscription_tx.try_send(message) {
                            warn!(
                                info = "the host may be overloaded or resource-constrained",
                                error = ?e,
                                "Unable to process sync subscriptions"
                            );
                            return Err(warp_utils::reject::custom_server_error(
                                "unable to queue subscription, host may be overloaded or shutting down".to_string(),
                            ));
                        }
                    }

                    Ok(())
                })
            },
        ).boxed()
}

// POST validator/register_validator
pub fn post_validator_register_validator<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("register_validator"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(warp_utils::json::json())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             register_val_data: Vec<SignedValidatorRegistrationData>| async {
                let (tx, rx) = oneshot::channel();

                let initial_result = task_spawner
                    .spawn_async_with_rejection_no_conversion(Priority::P0, async move {
                        let execution_layer = chain
                            .execution_layer
                            .as_ref()
                            .ok_or(BeaconChainError::ExecutionLayerMissing)
                            .map_err(warp_utils::reject::unhandled_error)?;
                        let current_slot = chain
                            .slot_clock
                            .now_or_genesis()
                            .ok_or(BeaconChainError::UnableToReadSlot)
                            .map_err(warp_utils::reject::unhandled_error)?;
                        let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());

                        debug!(
                            count = register_val_data.len(),
                            "Received register validator request"
                        );

                        let head_snapshot = chain.head_snapshot();
                        let spec = &chain.spec;

                        let (preparation_data, filtered_registration_data): (
                            Vec<(ProposerPreparationData, Option<u64>)>,
                            Vec<SignedValidatorRegistrationData>,
                        ) = register_val_data
                            .into_iter()
                            .filter_map(|register_data| {
                                chain
                                    .validator_index(&register_data.message.pubkey)
                                    .ok()
                                    .flatten()
                                    .and_then(|validator_index| {
                                        let validator = head_snapshot
                                            .beacon_state
                                            .get_validator(validator_index)
                                            .ok()?;
                                        let validator_status = ValidatorStatus::from_validator(
                                            validator,
                                            current_epoch,
                                            spec.far_future_epoch,
                                        )
                                        .superstatus();
                                        let is_active_or_pending =
                                            matches!(validator_status, ValidatorStatus::Pending)
                                                || matches!(
                                                    validator_status,
                                                    ValidatorStatus::Active
                                                );

                                        // Filter out validators who are not 'active' or 'pending'.
                                        is_active_or_pending.then_some({
                                            (
                                                (
                                                    ProposerPreparationData {
                                                        validator_index: validator_index as u64,
                                                        fee_recipient: register_data
                                                            .message
                                                            .fee_recipient,
                                                    },
                                                    Some(register_data.message.gas_limit),
                                                ),
                                                register_data,
                                            )
                                        })
                                    })
                            })
                            .unzip();

                        // Update the prepare beacon proposer cache based on this request.
                        execution_layer
                            .update_proposer_preparation(
                                current_epoch,
                                preparation_data.iter().map(|(data, limit)| (data, limit)),
                            )
                            .await;

                        // Call prepare beacon proposer blocking with the latest update in order to make
                        // sure we have a local payload to fall back to in the event of the blinded block
                        // flow failing.
                        chain
                            .prepare_beacon_proposer(current_slot)
                            .await
                            .map_err(|e| {
                                warp_utils::reject::custom_bad_request(format!(
                                    "error updating proposer preparations: {:?}",
                                    e
                                ))
                            })?;

                        info!(
                            count = filtered_registration_data.len(),
                            "Forwarding register validator request to connected builder"
                        );

                        // It's a waste of a `BeaconProcessor` worker to just
                        // wait on a response from the builder (especially since
                        // they have frequent timeouts). Spawn a new task and
                        // send the response back to our original HTTP request
                        // task via a channel.
                        let builder_future = async move {
                            let arc_builder = chain
                                .execution_layer
                                .as_ref()
                                .ok_or(BeaconChainError::ExecutionLayerMissing)
                                .map_err(warp_utils::reject::unhandled_error)?
                                .builder();
                            let builder = arc_builder
                                .as_ref()
                                .ok_or(BeaconChainError::BuilderMissing)
                                .map_err(warp_utils::reject::unhandled_error)?;
                            builder
                                .post_builder_validators(&filtered_registration_data)
                                .await
                                .map(|resp| warp::reply::json(&resp).into_response())
                                .map_err(|e| {
                                    warn!(
                                        num_registrations = filtered_registration_data.len(),
                                        error = ?e,
                                        "Relay error when registering validator(s)"
                                    );
                                    // Forward the HTTP status code if we are able to, otherwise fall back
                                    // to a server error.
                                    if let eth2::Error::ServerMessage(message) = e {
                                        if message.code == StatusCode::BAD_REQUEST.as_u16() {
                                            return warp_utils::reject::custom_bad_request(
                                                message.message,
                                            );
                                        } else {
                                            // According to the spec this response should only be a 400 or 500,
                                            // so we fall back to a 500 here.
                                            return warp_utils::reject::custom_server_error(
                                                message.message,
                                            );
                                        }
                                    }
                                    warp_utils::reject::custom_server_error(format!("{e:?}"))
                                })
                        };
                        tokio::task::spawn(async move { tx.send(builder_future.await) });

                        // Just send a generic 200 OK from this closure. We'll
                        // ignore the `Ok` variant and form a proper response
                        // from what is sent back down the channel.
                        Ok(warp::reply::reply().into_response())
                    })
                    .await;

                if initial_result.is_err() {
                    return convert_rejection(initial_result).await;
                }

                // Await a response from the builder without blocking a
                // `BeaconProcessor` worker.
                convert_rejection(rx.await.unwrap_or_else(|_| {
                    Ok(warp::reply::with_status(
                        warp::reply::json(&"No response from channel"),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    )
                    .into_response())
                }))
                .await
            },
        )
        .boxed()
}

// POST validator/prepare_beacon_proposer
pub fn post_validator_prepare_beacon_proposer<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("prepare_beacon_proposer"))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(network_tx_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(warp_utils::json::json())
        .then(
            |not_synced_filter: Result<(), Rejection>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             preparation_data: Vec<ProposerPreparationData>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    not_synced_filter?;
                    let execution_layer = chain
                        .execution_layer
                        .as_ref()
                        .ok_or(BeaconChainError::ExecutionLayerMissing)
                        .map_err(warp_utils::reject::unhandled_error)?;

                    let current_slot = chain
                        .slot_clock
                        .now_or_genesis()
                        .ok_or(BeaconChainError::UnableToReadSlot)
                        .map_err(warp_utils::reject::unhandled_error)?;
                    let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());

                    debug!(
                        count = preparation_data.len(),
                        "Received proposer preparation data"
                    );

                    execution_layer
                        .update_proposer_preparation(
                            current_epoch,
                            preparation_data.iter().map(|data| (data, &None)),
                        )
                        .await;

                    chain
                        .prepare_beacon_proposer(current_slot)
                        .await
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!(
                                "error updating proposer preparations: {:?}",
                                e
                            ))
                        })?;

                    if chain.spec.is_peer_das_scheduled() {
                        let (finalized_beacon_state, _, _) =
                            StateId(CoreStateId::Finalized).state(&chain)?;
                        let validators_and_balances = preparation_data
                            .iter()
                            .filter_map(|preparation| {
                                if let Ok(effective_balance) = finalized_beacon_state
                                    .get_effective_balance(preparation.validator_index as usize)
                                {
                                    Some((preparation.validator_index as usize, effective_balance))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>();

                        let current_slot =
                            chain.slot().map_err(warp_utils::reject::unhandled_error)?;
                        if let Some(cgc_change) = chain
                            .data_availability_checker
                            .custody_context()
                            .register_validators(validators_and_balances, current_slot, &chain.spec)
                        {
                            chain.update_data_column_custody_info(Some(
                                cgc_change
                                    .effective_epoch
                                    .start_slot(T::EthSpec::slots_per_epoch()),
                            ));

                            network_tx.send(NetworkMessage::CustodyCountChanged {
                                new_custody_group_count: cgc_change.new_custody_group_count,
                                sampling_count: cgc_change.sampling_count,
                            }).unwrap_or_else(|e| {
                                debug!(error = %e, "Could not send message to the network service. \
                                Likely shutdown")
                            });
                        }
                    }

                    Ok::<_, warp::reject::Rejection>(warp::reply::json(&()).into_response())
                })
            },
        )
        .boxed()
}

// POST validator/beacon_committee_subscriptions
pub fn post_validator_beacon_committee_subscriptions<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    validator_subscription_tx_filter: ValidatorSubscriptionTxFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("beacon_committee_subscriptions"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(validator_subscription_tx_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |committee_subscriptions: Vec<BeaconCommitteeSubscription>,
             validator_subscription_tx: Sender<ValidatorSubscriptionMessage>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let subscriptions: std::collections::BTreeSet<_> = committee_subscriptions
                        .iter()
                        .map(|subscription| {
                            chain
                                .validator_monitor
                                .write()
                                .auto_register_local_validator(subscription.validator_index);
                            ValidatorSubscription {
                                attestation_committee_index: subscription.committee_index,
                                slot: subscription.slot,
                                committee_count_at_slot: subscription.committees_at_slot,
                                is_aggregator: subscription.is_aggregator,
                            }
                        })
                        .collect();

                    let message =
                        ValidatorSubscriptionMessage::AttestationSubscribe { subscriptions };
                    if let Err(e) = validator_subscription_tx.try_send(message) {
                        warn!(
                            info = "the host may be overloaded or resource-constrained",
                            error = ?e,
                            "Unable to process committee subscriptions"
                        );
                        return Err(warp_utils::reject::custom_server_error(
                            "unable to queue subscription, host may be overloaded or shutting down"
                                .to_string(),
                        ));
                    }
                    Ok(())
                })
            },
        )
        .boxed()
}

pub fn post_validator_contribution_and_proofs<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("contribution_and_proofs"))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(warp_utils::json::json())
        .and(network_tx_filter.clone())
        .then(
            |not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             contributions: Vec<SignedContributionAndProof<T::EthSpec>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    not_synced_filter?;
                    sync_committees::process_signed_contribution_and_proofs(
                        contributions,
                        network_tx,
                        &chain,
                    )?;
                    Ok(GenericResponse::from(()))
                })
            },
        )
        .boxed()
}

// POST validator/aggregate_and_proofs
pub fn post_validator_aggregate_and_proofs<T: BeaconChainTypes>(
    any_version: AnyVersionFilter,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    any_version
        .and(warp::path("validator"))
        .and(warp::path("aggregate_and_proofs"))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(warp_utils::json::json())
        .and(network_tx_filter.clone())
        .then(
            // V1 and V2 are identical except V2 has a consensus version header in the request.
            // We only require this header for SSZ deserialization, which isn't supported for
            // this endpoint presently.
            |_endpoint_version: EndpointVersion,
             not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             aggregates: Vec<SignedAggregateAndProof<T::EthSpec>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    not_synced_filter?;
                    let seen_timestamp = timestamp_now();
                    let mut verified_aggregates = Vec::with_capacity(aggregates.len());
                    let mut messages = Vec::with_capacity(aggregates.len());
                    let mut failures = Vec::new();

                    // Verify that all messages in the post are valid before processing further
                    for (index, aggregate) in aggregates.iter().enumerate() {
                        match chain.verify_aggregated_attestation_for_gossip(aggregate) {
                            Ok(verified_aggregate) => {
                                messages.push(PubsubMessage::AggregateAndProofAttestation(Box::new(
                                    verified_aggregate.aggregate().clone(),
                                )));

                                // Notify the validator monitor.
                                chain
                                    .validator_monitor
                                    .read()
                                    .register_api_aggregated_attestation(
                                        seen_timestamp,
                                        verified_aggregate.aggregate(),
                                        verified_aggregate.indexed_attestation(),
                                        &chain.slot_clock,
                                        &chain.spec,
                                    );

                                verified_aggregates.push((index, verified_aggregate));
                            }
                            // If we already know the attestation, don't broadcast it or attempt to
                            // further verify it. Return success.
                            //
                            // It's reasonably likely that two different validators produce
                            // identical aggregates, especially if they're using the same beacon
                            // node.
                            Err(AttestationError::AttestationSupersetKnown(_)) => continue,
                            // If we've already seen this aggregator produce an aggregate, just
                            // skip this one.
                            //
                            // We're likely to see this with VCs that use fallback BNs. The first
                            // BN might time-out *after* publishing the aggregate and then the
                            // second BN will indicate it's already seen the aggregate.
                            //
                            // There's no actual error for the user or the network since the
                            // aggregate has been successfully published by some other node.
                            Err(AttestationError::AggregatorAlreadyKnown(_)) => continue,
                            Err(e) => {
                                error!(
                                    error = ?e,
                                    request_index = index,
                                    aggregator_index = aggregate.message().aggregator_index(),
                                    attestation_index = aggregate.message().aggregate().committee_index(),
                                    attestation_slot = %aggregate.message().aggregate().data().slot,
                                    "Failure verifying aggregate and proofs"
                                );
                                failures.push(Failure::new(index, format!("Verification: {:?}", e)));
                            }
                        }
                    }

                    // Publish aggregate attestations to the libp2p network
                    if !messages.is_empty() {
                        publish_network_message(&network_tx, NetworkMessage::Publish { messages })?;
                    }

                    // Import aggregate attestations
                    for (index, verified_aggregate) in verified_aggregates {
                        if let Err(e) = chain.apply_attestation_to_fork_choice(&verified_aggregate) {
                            error!(
                                error = ?e,
                                request_index = index,
                                aggregator_index = verified_aggregate.aggregate().message().aggregator_index(),
                                attestation_index = verified_aggregate.attestation().committee_index(),
                                attestation_slot = %verified_aggregate.attestation().data().slot,
                                    "Failure applying verified aggregate attestation to fork choice"
                                );
                            failures.push(Failure::new(index, format!("Fork choice: {:?}", e)));
                        }
                        if let Err(e) = chain.add_to_block_inclusion_pool(verified_aggregate) {
                            warn!(
                                error = ?e,
                                request_index = index,
                                "Could not add verified aggregate attestation to the inclusion pool"
                            );
                            failures.push(Failure::new(index, format!("Op pool: {:?}", e)));
                        }
                    }

                    if !failures.is_empty() {
                        Err(warp_utils::reject::indexed_bad_request("error processing aggregate and proofs".to_string(),
                                                                    failures,
                        ))
                    } else {
                        Ok(())
                    }
                })
            },
        ).boxed()
}

// GET validator/duties/proposer/{epoch}
pub fn get_validator_duties_proposer<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    chain_filter: ChainFilter<T>,
    not_while_syncing_filter: NotWhileSyncingFilter,
    task_spawner_filter: TaskSpawnerFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("validator"))
        .and(warp::path("duties"))
        .and(warp::path("proposer"))
        .and(warp::path::param::<Epoch>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid epoch".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(not_while_syncing_filter)
        .and(task_spawner_filter)
        .and(chain_filter)
        .then(
            |epoch: Epoch,
             not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    not_synced_filter?;
                    proposer_duties::proposer_duties(epoch, &chain)
                })
            },
        )
        .boxed()
}
