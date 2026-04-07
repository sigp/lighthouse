use crate::block_id::BlockId;
use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{ChainFilter, EthV1Filter, NetworkTxFilter, ResponseFilter, TaskSpawnerFilter};
use crate::version::{
    ResponseIncludesVersion, add_consensus_version_header, add_ssz_content_type_header,
    execution_optimistic_finalized_beacon_response,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bytes::Bytes;
use eth2::types as api_types;
use eth2::{CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use ssz::{Decode, Encode};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};
use types::SignedExecutionPayloadEnvelope;
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
    let slot = envelope.message.slot;
    let beacon_block_root = envelope.message.beacon_block_root;

    // TODO(gloas): Replace this check once we have gossip validation.
    if !chain.spec.is_gloas_scheduled() {
        return Err(warp_utils::reject::custom_bad_request(
            "Execution payload envelopes are not supported before the Gloas fork".into(),
        ));
    }

    // TODO(gloas): We should probably add validation here i.e. BroadcastValidation::Gossip
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

                    let fork_name = chain
                        .spec
                        .fork_name_at_slot::<T::EthSpec>(envelope.message.slot);

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
