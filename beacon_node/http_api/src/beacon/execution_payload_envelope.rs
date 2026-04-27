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
use beacon_chain::payload_envelope_verification::gossip_verified_envelope::GossipVerifiedEnvelope;
use beacon_chain::{BeaconChain, BeaconChainTypes, NotifyExecutionLayer};
use bytes::Bytes;
use eth2::types as api_types;
use eth2::{CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER};
use futures::TryFutureExt;
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
        .and(warp::header::exact(
            CONTENT_TYPE_HEADER,
            SSZ_CONTENT_TYPE_HEADER,
        ))
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
/// Publishes a signed execution payload envelope to the network.
pub async fn publish_execution_payload_envelope<T: BeaconChainTypes>(
    envelope: SignedExecutionPayloadEnvelope<T::EthSpec>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<Response<Body>, Rejection> {
    let slot = envelope.slot();
    let beacon_block_root = envelope.message.beacon_block_root;
    let builder_index = envelope.message.builder_index;

    if !chain.spec.is_gloas_scheduled() {
        return Err(warp_utils::reject::custom_bad_request(
            "Execution payload envelopes are not supported before the Gloas fork".into(),
        ));
    }

    let signed_envelope = Arc::new(envelope);

    let blobs_and_proofs = chain.pending_payload_envelopes.write().take_blobs(slot);

    // The publish_fn is called inside process_execution_payload_envelope after consensus
    // verification but before the EL call.
    let envelope_for_publish = signed_envelope.clone();
    let sender = network_tx.clone();
    let publish_fn = move || {
        info!(
            %slot,
            %beacon_block_root,
            builder_index,
            "Publishing signed execution payload envelope to network"
        );
        crate::utils::publish_pubsub_message(
            &sender,
            PubsubMessage::ExecutionPayload(Box::new((*envelope_for_publish).clone())),
        )
        .map_err(|_| {
            warn!(%slot, "Failed to publish execution payload envelope to network");
            EnvelopeError::InternalError(
                "Unable to publish execution payload envelope to network".to_owned(),
            )
        })
    };

    let ctx = chain.payload_envelope_gossip_verification_context();
    let gossip_verified_envelope = match GossipVerifiedEnvelope::new(signed_envelope, &ctx) {
        Ok(envelope) => envelope,
        Err(e) => {
            warn!(%slot, %beacon_block_root, error = ?e, "Execution payload envelope rejected");
            return Err(warp_utils::reject::custom_bad_request(format!(
                "execution payload envelope rejected: {e:?}",
            )));
        }
    };

    // Import the envelope locally (runs state transition and notifies the EL).
    chain
        .process_execution_payload_envelope(
            beacon_block_root,
            gossip_verified_envelope,
            NotifyExecutionLayer::Yes,
            BlockImportSource::HttpApi,
            publish_fn,
        )
        .await
        .map_err(|e| {
            warn!(%slot, %beacon_block_root, reason = ?e, "Execution payload envelope rejected");
            warp_utils::reject::custom_bad_request(format!(
                "execution payload envelope rejected: {e:?}"
            ))
        })?;

    // Build and publish data column sidecars from the blobs.
    if let Some((blobs, _kzg_proofs)) = blobs_and_proofs
        && !blobs.is_empty()
    {
        let gossip_verified_columns =
            spawn_build_gloas_data_columns_task(chain.clone(), beacon_block_root, slot, blobs)?
                .await?;

        if !gossip_verified_columns.is_empty() {
            publish_column_sidecars(network_tx, &gossip_verified_columns, &chain).map_err(
                |_| {
                    warp_utils::reject::custom_server_error(
                        "unable to publish data column sidecars".into(),
                    )
                },
            )?;

            let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
            let sampling_column_indices = chain.sampling_columns_for_epoch(epoch);
            let sampling_columns = gossip_verified_columns
                .into_iter()
                .filter(|col| sampling_column_indices.contains(&col.index()))
                .collect::<Vec<_>>();

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
    chain: Arc<BeaconChain<T>>,
    beacon_block_root: types::Hash256,
    slot: types::Slot,
    blobs: types::BlobsList<T::EthSpec>,
) -> Result<impl Future<Output = Result<Vec<GossipVerifiedDataColumn<T>>, Rejection>>, Rejection> {
    chain
        .clone()
        .task_executor
        .spawn_blocking_handle(
            move || build_gloas_data_columns(&chain, beacon_block_root, slot, &blobs),
            "build_gloas_data_columns",
        )
        .ok_or_else(|| warp_utils::reject::custom_server_error("runtime shutdown".to_string()))
        .map(|r| {
            r.map_err(|_| warp_utils::reject::custom_server_error("join error".to_string()))
                .and_then(|output| async move { output })
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
                Err(GossipDataColumnError::PriorKnownUnpublished) => None,
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
