use crate::block_id::BlockId;
use crate::publish_blocks::{check_slashable, publish_column_sidecars};
use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{ChainFilter, EthV1Filter, NetworkTxFilter, ResponseFilter, TaskSpawnerFilter};
use crate::version::{
    ResponseIncludesVersion, add_consensus_version_header, add_ssz_content_type_header,
    execution_optimistic_finalized_beacon_response,
};
use beacon_chain::data_column_verification::{GossipDataColumnError, GossipVerifiedDataColumn};
use beacon_chain::payload_envelope_verification::EnvelopeError;
use beacon_chain::{
    AvailabilityProcessingStatus, BeaconChain, BeaconChainError, BeaconChainTypes, BlockError,
    NotifyExecutionLayer,
};
use bytes::Bytes;
use eth2::{
    BLOB_DATA_INCLUDED_HEADER, CONSENSUS_VERSION_HEADER,
    types::{self as api_types, BroadcastValidation},
};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use ssz::{Decode, Encode};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info, warn};
use types::{BlockImportSource, EthSpec, ForkName, SignedExecutionPayloadEnvelope};
use warp::{
    Filter, Rejection,
    http::response::Builder,
    reply::{Reply, Response},
};

// POST beacon/execution_payload_envelopes (SSZ)
pub(crate) fn post_beacon_execution_payload_envelopes_ssz<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_envelopes"))
        .and(warp::query::<api_types::BroadcastValidationQuery>())
        .and(warp::path::end())
        .and(warp::header::<ForkName>(CONSENSUS_VERSION_HEADER))
        .and(warp::header::<bool>(BLOB_DATA_INCLUDED_HEADER))
        .and(warp::body::bytes())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(network_tx_filter)
        .then(
            |validation_level: api_types::BroadcastValidationQuery,
             _fork_name: ForkName,
             blob_data_included: bool,
             body_bytes: Bytes,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    ensure_stateful_submission(blob_data_included)?;
                    let envelope =
                        SignedExecutionPayloadEnvelope::<T::EthSpec>::from_ssz_bytes(&body_bytes)
                            .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}"))
                        })?;
                    publish_execution_payload_envelope(
                        envelope,
                        validation_level.broadcast_validation,
                        chain,
                        &network_tx,
                    )
                    .await
                })
            },
        )
        .boxed()
}

// POST beacon/execution_payload_envelopes
pub(crate) fn post_beacon_execution_payload_envelopes<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_envelopes"))
        .and(warp::query::<api_types::BroadcastValidationQuery>())
        .and(warp::path::end())
        .and(warp::header::<ForkName>(CONSENSUS_VERSION_HEADER))
        .and(warp::header::<bool>(BLOB_DATA_INCLUDED_HEADER))
        .and(warp::body::bytes())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(network_tx_filter)
        .then(
            |validation_level: api_types::BroadcastValidationQuery,
             _fork_name: ForkName,
             blob_data_included: bool,
             body_bytes: Bytes,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    ensure_stateful_submission(blob_data_included)?;
                    let envelope = serde_json::from_slice(&body_bytes).map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid JSON: {e:?}"))
                    })?;
                    publish_execution_payload_envelope(
                        envelope,
                        validation_level.broadcast_validation,
                        chain,
                        &network_tx,
                    )
                    .await
                })
            },
        )
        .boxed()
}

// TODO(gloas): support Eth-Blob-Data-Included: true (stateless
// SignedExecutionPayloadEnvelopeContents) instead of rejecting it (#9568 / #8828).
fn ensure_stateful_submission(blob_data_included: bool) -> Result<(), Rejection> {
    if blob_data_included {
        return Err(warp_utils::reject::custom_bad_request(
            "SignedExecutionPayloadEnvelopeContents is not supported".into(),
        ));
    }
    Ok(())
}

/// Publishes a signed execution payload envelope to the network.
pub async fn publish_execution_payload_envelope<T: BeaconChainTypes>(
    envelope: SignedExecutionPayloadEnvelope<T::EthSpec>,
    validation_level: BroadcastValidation,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<Response, Rejection> {
    let slot = envelope.slot();
    let beacon_block_root = envelope.message.beacon_block_root;

    if !chain.spec.is_gloas_scheduled() {
        return Err(warp_utils::reject::custom_bad_request(
            "Execution payload envelopes are not supported before the Gloas fork".into(),
        ));
    }

    info!(
        %slot,
        %beacon_block_root,
        builder_index = envelope.message.builder_index,
        "Publishing signed execution payload envelope to network"
    );

    // TODO(gloas): if the block commits to blobs but none are cached, return 400 before
    // publishing (beacon-APIs "no cached blobs and KZG proofs to attach"), rather than
    // proceeding to a 202 via MissingComponents.
    let blobs_and_proofs = chain.pending_payload_envelopes.write().take_blobs(slot);

    // Spawn the column-build task (CPU-bound KZG cell-and-proof computation) before
    // publishing the envelope so it runs in parallel with envelope gossip, narrowing
    // the window in which peers see envelope-without-columns. If envelope import
    // fails below, dropping this future drops the spawned `JoinHandle` (the running
    // closure on the blocking pool finishes and is then discarded — no work cancellation).
    let column_build_future = match blobs_and_proofs {
        Some(blobs) if !blobs.is_empty() => Some(spawn_build_gloas_data_columns_task(
            &chain,
            beacon_block_root,
            slot,
            blobs,
        )?),
        _ => None,
    };

    // Gossip-verify the envelope before publishing.
    let gossip_verified = chain
        .verify_envelope_for_gossip(Arc::new(envelope))
        .await
        .map_err(|e| {
            warn!(%slot, error = ?e, "Execution payload envelope failed gossip verification");
            warp_utils::reject::custom_bad_request(format!(
                "envelope failed gossip verification: {e}"
            ))
        })?;

    let network_tx_clone = network_tx.clone();
    let block_for_equivocation_check = gossip_verified.block.clone();
    let envelope_for_gossip = gossip_verified.signed_envelope.clone();
    let publish_envelope = || {
        crate::utils::publish_pubsub_message(
            &network_tx_clone,
            PubsubMessage::ExecutionPayload(Box::new(envelope_for_gossip.as_ref().clone())),
        )
        .map_err(|_| {
            EnvelopeError::BeaconChainError(Box::new(
                beacon_chain::BeaconChainError::UnableToPublish,
            ))
        })
    };

    let published = AtomicBool::new(false);
    if validation_level == BroadcastValidation::Gossip {
        publish_envelope().map_err(|_| {
            warp_utils::reject::custom_server_error(
                "unable to publish to network channel".to_string(),
            )
        })?;
        published.store(true, Ordering::SeqCst);
    }

    let publish_fn = || {
        match validation_level {
            BroadcastValidation::Gossip => return Ok(()),
            BroadcastValidation::Consensus => {}
            BroadcastValidation::ConsensusAndEquivocation => {
                check_slashable(&chain, beacon_block_root, &block_for_equivocation_check).map_err(
                    |e| match e {
                        BlockError::BeaconChainError(e) => EnvelopeError::BeaconChainError(e),
                        e => EnvelopeError::InternalError(format!("{e:?}")),
                    },
                )?;
            }
        }

        publish_envelope()?;
        published.store(true, Ordering::SeqCst);
        Ok(())
    };

    let import_result = chain
        .process_execution_payload_envelope(
            beacon_block_root,
            gossip_verified,
            NotifyExecutionLayer::Yes,
            BlockImportSource::HttpApi,
            publish_fn,
        )
        .await;

    let mut envelope_imported = match import_result {
        Ok(AvailabilityProcessingStatus::Imported(_, _)) => true,
        Ok(AvailabilityProcessingStatus::MissingComponents(_, _)) => false,
        Err(e) => {
            if is_unable_to_publish(&e) {
                return Err(warp_utils::reject::custom_server_error(
                    "unable to publish to network channel".to_string(),
                ));
            }

            if published.load(Ordering::SeqCst) {
                warn!(%slot, error = ?e, "Failed to import execution payload envelope after broadcast");
                return Err(warp_utils::reject::broadcast_without_import(format!(
                    "envelope import failed: {e:?}"
                )));
            }

            warn!(%slot, error = ?e, "Rejecting execution payload envelope before broadcast");
            return Err(warp_utils::reject::custom_bad_request(format!(
                "envelope rejected: {e:?}"
            )));
        }
    };

    // Column failures leave `envelope_imported` unchanged for the response below.
    if let Some(column_build_future) = column_build_future {
        match column_build_future.await {
            Ok(columns) => {
                if publish_and_import_columns(&chain, network_tx, slot, columns).await {
                    envelope_imported = true;
                }
            }
            Err(e) => {
                error!(
                    %slot,
                    error = ?e,
                    "Failed to build data columns after envelope publication"
                );
            }
        }
    }

    // Return 202 when broadcast succeeds but integration does not. Unlike the block path,
    // 202 applies at every validation level: missing components here are node-cached columns
    // rather than request-supplied blobs, so incomplete import is not the submitter's fault.
    if envelope_imported {
        chain.recompute_head_at_current_slot().await;
        Ok(warp::reply().into_response())
    } else {
        Err(warp_utils::reject::broadcast_without_import(format!(
            "envelope for slot {slot} was broadcast but not fully imported"
        )))
    }
}

/// Publishes locally-built data columns and imports the node's sampling subset.
///
/// Returns `true` iff sampling-column processing completed envelope import. All failures are
/// logged and swallowed: the envelope is already on the wire, so the caller's final
/// 200-vs-202 decision reflects import state rather than column errors.
async fn publish_and_import_columns<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    slot: types::Slot,
    gossip_verified_columns: Vec<GossipVerifiedDataColumn<T>>,
) -> bool {
    if gossip_verified_columns.is_empty() {
        return false;
    }

    if let Err(e) = publish_column_sidecars(network_tx, &gossip_verified_columns, chain) {
        error!(
            %slot,
            error = ?e,
            "Failed to publish data column sidecars after envelope publication"
        );
        return false;
    }

    let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
    let sampling_column_indices = chain.custody_context.sampling_columns_for_epoch(epoch);
    let sampling_columns = gossip_verified_columns
        .into_iter()
        .filter(|col| sampling_column_indices.contains(&col.index()))
        .collect::<Vec<_>>();

    if sampling_columns.is_empty() {
        return false;
    }

    match Box::pin(chain.process_gossip_data_columns(sampling_columns, || Ok(()))).await {
        Ok(AvailabilityProcessingStatus::Imported(_, _)) => true,
        Ok(AvailabilityProcessingStatus::MissingComponents(_, _)) => false,
        Err(e) => {
            error!(
                %slot,
                error = ?e,
                "Failed to process sampling data columns during envelope publication"
            );
            false
        }
    }
}

fn is_unable_to_publish(error: &BlockError) -> bool {
    match error {
        BlockError::BeaconChainError(error) => {
            matches!(error.as_ref(), BeaconChainError::UnableToPublish)
        }
        BlockError::EnvelopeError(error) => matches!(
            error.as_ref(),
            EnvelopeError::BeaconChainError(error)
                if matches!(error.as_ref(), BeaconChainError::UnableToPublish)
        ),
        _ => false,
    }
}

fn spawn_build_gloas_data_columns_task<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    beacon_block_root: types::Hash256,
    slot: types::Slot,
    blobs: types::BlobsList<T::EthSpec>,
) -> Result<impl Future<Output = Result<Vec<GossipVerifiedDataColumn<T>>, Rejection>>, Rejection> {
    let chain_for_build = chain.clone();
    let handle = chain
        .task_executor
        .spawn_blocking_handle(
            move || build_gloas_data_columns(&chain_for_build, beacon_block_root, slot, &blobs),
            "build_gloas_data_columns",
        )
        .ok_or_else(|| warp_utils::reject::custom_server_error("runtime shutdown".to_string()))?;

    Ok(async move {
        handle
            .await
            .map_err(|_| warp_utils::reject::custom_server_error("join error".to_string()))?
    })
}

fn build_gloas_data_columns<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    beacon_block_root: types::Hash256,
    slot: types::Slot,
    blobs: &types::BlobsList<T::EthSpec>,
) -> Result<Vec<GossipVerifiedDataColumn<T>>, Rejection> {
    let blob_refs: Vec<_> = blobs.iter().collect();
    let data_column_sidecars = beacon_chain::kzg_utils::blobs_to_data_column_sidecars_gloas(
        &blob_refs,
        beacon_block_root,
        slot,
        &chain.kzg,
        &chain.spec,
    )
    .map_err(|e| {
        error!(
            error = ?e,
            %slot,
            "Failed to build data column sidecars for envelope"
        );
        warp_utils::reject::custom_server_error(format!("{e:?}"))
    })?;

    let gossip_verified_columns = data_column_sidecars
        .into_iter()
        .filter_map(|col| {
            let index = *col.index();
            match GossipVerifiedDataColumn::new_for_block_publishing(col, chain) {
                Ok(verified) => Some(verified),
                Err(GossipDataColumnError::PriorKnown { .. }) => None,
                Err(e) => {
                    warn!(
                        %slot,
                        column_index = index,
                        error = ?e,
                        "Locally-built data column failed gossip verification"
                    );
                    None
                }
            }
        })
        .collect::<Vec<_>>();

    debug!(
        %slot,
        column_count = gossip_verified_columns.len(),
        "Built data columns for envelope publication"
    );

    Ok(gossip_verified_columns)
}

// TODO(gloas): add tests for this endpoint once we support importing payloads into the db
// GET beacon/execution_payload_envelopes/{block_id}
pub(crate) fn get_beacon_execution_payload_envelopes<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    block_id_or_err: impl Filter<Extract = (BlockId,), Error = Rejection>
    + Clone
    + Send
    + Sync
    + 'static,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_envelopes"))
        .and(block_id_or_err)
        .and(warp::path::end())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |block_id: BlockId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let (root, execution_optimistic, finalized) = block_id.root(&chain)?;

                    let envelope = chain
                        .get_payload_envelope(&root)
                        .map_err(warp_utils::reject::unhandled_error)?
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(format!(
                                "execution payload envelope for block root {root}"
                            ))
                        })?;

                    let fork_name = chain.spec.fork_name_at_slot::<T::EthSpec>(envelope.slot());

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Builder::new()
                            .status(200)
                            .body(envelope.as_ssz_bytes())
                            .map(add_ssz_content_type_header)
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => {
                            let res = execution_optimistic_finalized_beacon_response(
                                ResponseIncludesVersion::Yes(fork_name),
                                execution_optimistic,
                                finalized,
                                &envelope,
                            )?;
                            Ok(warp::reply::json(&res).into_response())
                        }
                    }
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        )
        .boxed()
}
