use crate::block_id::BlockId;
use crate::publish_blocks::publish_column_sidecars;
use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{ChainFilter, EthV1Filter, NetworkTxFilter, ResponseFilter, TaskSpawnerFilter};
use crate::version::{
    ResponseIncludesVersion, add_consensus_version_header, add_ssz_content_type_header,
    execution_optimistic_finalized_beacon_response,
};
use beacon_chain::data_column_verification::{GossipDataColumnError, GossipVerifiedDataColumn};
use beacon_chain::payload_envelope_verification::EnvelopeError;
use beacon_chain::{BeaconChain, BeaconChainTypes, NotifyExecutionLayer};
use bytes::Bytes;
use eth2::types as api_types;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use ssz::{Decode, Encode};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info, warn};
use types::{BlockImportSource, EthSpec, SignedExecutionPayloadEnvelope};
use warp::{
    Filter, Rejection, Reply,
    hyper::{Body, Response},
};

// POST beacon/execution_payload_envelope (SSZ)
pub(crate) fn post_beacon_execution_payload_envelope_ssz<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_envelope"))
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(network_tx_filter)
        .then(
            |body_bytes: Bytes,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    let envelope =
                        SignedExecutionPayloadEnvelope::<T::EthSpec>::from_ssz_bytes(&body_bytes)
                            .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}"))
                        })?;
                    publish_execution_payload_envelope(envelope, chain, &network_tx).await
                })
            },
        )
        .boxed()
}

// POST beacon/execution_payload_envelope
pub(crate) fn post_beacon_execution_payload_envelope<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_envelope"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .then(
            |envelope: SignedExecutionPayloadEnvelope<T::EthSpec>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    publish_execution_payload_envelope(envelope, chain, &network_tx).await
                })
            },
        )
        .boxed()
}
/// Publishes a signed execution payload envelope to the network. Implements
/// `POST /eth/v1/beacon/execution_payload_envelope` per the in-flight beacon-APIs PR
/// <https://github.com/ethereum/beacon-APIs/pull/580>.
pub async fn publish_execution_payload_envelope<T: BeaconChainTypes>(
    envelope: SignedExecutionPayloadEnvelope<T::EthSpec>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<Response<Body>, Rejection> {
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
    let envelope_for_gossip = gossip_verified.signed_envelope.as_ref().clone();
    let publish_fn = || {
        crate::utils::publish_pubsub_message(
            &network_tx_clone,
            PubsubMessage::ExecutionPayload(Box::new(envelope_for_gossip)),
        )
        .map_err(|_| {
            EnvelopeError::BeaconChainError(Arc::new(
                beacon_chain::BeaconChainError::UnableToPublish,
            ))
        })
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

    if let Err(e) = import_result {
        warn!(%slot, error = ?e, "Failed to import execution payload envelope");
        return Err(warp_utils::reject::custom_server_error(format!(
            "envelope import failed: {e}"
        )));
    }

    // From here on the envelope is on the wire. `take_blobs` already consumed the cache
    // entry, so a retry would not republish columns; returning Err would mislead the
    // caller. Log column-build/publish failures and fall through to `Ok`.
    if let Some(column_build_future) = column_build_future {
        let gossip_verified_columns = match column_build_future.await {
            Ok(columns) => columns,
            Err(e) => {
                error!(
                    %slot,
                    error = ?e,
                    "Failed to build data columns after envelope publication"
                );
                return Ok(warp::reply().into_response());
            }
        };

        if !gossip_verified_columns.is_empty() {
            if let Err(e) = publish_column_sidecars(network_tx, &gossip_verified_columns, &chain) {
                error!(
                    %slot,
                    error = ?e,
                    "Failed to publish data column sidecars after envelope publication"
                );
                return Ok(warp::reply().into_response());
            }

            let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
            let sampling_column_indices = chain.sampling_columns_for_epoch(epoch);
            let sampling_columns = gossip_verified_columns
                .into_iter()
                .filter(|col| sampling_column_indices.contains(&col.index()))
                .collect::<Vec<_>>();

            // Local processing only — envelope already broadcast, so log and fall through.
            if !sampling_columns.is_empty()
                && let Err(e) =
                    Box::pin(chain.process_gossip_data_columns(sampling_columns, || Ok(()))).await
            {
                error!(
                    %slot,
                    error = ?e,
                    "Failed to process sampling data columns during envelope publication"
                );
            }
        }
    }

    Ok(warp::reply().into_response())
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
// GET beacon/execution_payload_envelope/{block_id}
pub(crate) fn get_beacon_execution_payload_envelope<T: BeaconChainTypes>(
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
        .and(warp::path("execution_payload_envelope"))
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
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .body(envelope.as_ssz_bytes().into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
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
