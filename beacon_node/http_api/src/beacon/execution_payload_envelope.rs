use crate::block_id::BlockId;
use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{ChainFilter, EthV1Filter, NetworkTxFilter, ResponseFilter, TaskSpawnerFilter};
use crate::version::{
    ResponseIncludesVersion, add_consensus_version_header, add_ssz_content_type_header,
    execution_optimistic_finalized_beacon_response,
};
use beacon_chain::{
    BeaconChain, BeaconChainTypes, NotifyExecutionLayer,
    payload_envelope_verification::EnvelopeError,
};
use bytes::Bytes;
use eth2::types as api_types;
use eth2::{CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use ssz::{Decode, Encode};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};
use types::{BlockImportSource, SignedExecutionPayloadEnvelope};
use warp::{Filter, Rejection, Reply, reply::Response};

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
/// Locally imports and publishes a signed execution payload envelope to the network.
///
/// TODO(gloas): Add gossip verification (BroadcastValidation::Gossip) before import.
pub async fn publish_execution_payload_envelope<T: BeaconChainTypes>(
    envelope: SignedExecutionPayloadEnvelope<T::EthSpec>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<Response, Rejection> {
    let slot = envelope.message.slot;
    let beacon_block_root = envelope.message.beacon_block_root;
    let builder_index = envelope.message.builder_index;

    if !chain.spec.is_gloas_scheduled() {
        return Err(warp_utils::reject::custom_bad_request(
            "Execution payload envelopes are not supported before the Gloas fork".into(),
        ));
    }

    let signed_envelope = Arc::new(envelope);

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

    // Import the envelope locally (runs state transition and notifies the EL).
    chain
        .process_execution_payload_envelope(
            beacon_block_root,
            signed_envelope,
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

    Ok(warp::reply().into_response())
}

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
                        Some(api_types::Accept::Ssz) => warp::http::Response::builder()
                            .status(200)
                            .body(warp::hyper::Body::from(envelope.as_ssz_bytes()))
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
