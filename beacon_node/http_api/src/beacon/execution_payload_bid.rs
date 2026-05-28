use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{
    ChainFilter, EthV1Filter, NetworkTxFilter, ResponseFilter, TaskSpawnerFilter,
    publish_pubsub_message,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bytes::Bytes;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use ssz::Decode;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, warn};
use types::SignedExecutionPayloadBid;
use warp::{Filter, Rejection, Reply, hyper::Body, hyper::Response};

// POST /eth/v1/beacon/execution_payload_bid (SSZ)
pub(crate) fn post_beacon_execution_payload_bid_ssz<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_bid"))
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
                task_spawner.blocking_response_task(Priority::P0, move || {
                    let bid = SignedExecutionPayloadBid::<T::EthSpec>::from_ssz_bytes(&body_bytes)
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}"))
                        })?;
                    publish_execution_payload_bid(bid, &chain, &network_tx)
                })
            },
        )
        .boxed()
}

// POST /eth/v1/beacon/execution_payload_bid
pub(crate) fn post_beacon_execution_payload_bid<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_payload_bid"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(network_tx_filter)
        .then(
            |bid: SignedExecutionPayloadBid<T::EthSpec>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_response_task(Priority::P0, move || {
                    publish_execution_payload_bid(bid, &chain, &network_tx)
                })
            },
        )
        .boxed()
}

pub fn publish_execution_payload_bid<T: BeaconChainTypes>(
    bid: SignedExecutionPayloadBid<T::EthSpec>,
    chain: &Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<Response<Body>, Rejection> {
    let slot = bid.slot();
    let builder_index = bid.message.builder_index;

    if !chain.spec.is_gloas_scheduled() {
        return Err(warp_utils::reject::custom_bad_request(
            "Execution payload bids are not supported before the Gloas fork".into(),
        ));
    }

    debug!(
        %slot,
        builder_index,
        "Publishing signed execution payload bid to network"
    );

    let gossip_verified_bid = chain
        .verify_payload_bid_for_gossip(Arc::new(bid))
        .map_err(|e| {
            warn!(%slot, error = ?e, "Execution payload bid failed gossip verification");
            warp_utils::reject::custom_bad_request(format!("bid failed gossip verification: {e}"))
        })?;

    let bid_for_gossip = gossip_verified_bid.signed_bid.as_ref().clone();

    publish_pubsub_message(
        network_tx,
        PubsubMessage::ExecutionPayloadBid(Box::new(bid_for_gossip)),
    )?;

    Ok(warp::reply().into_response())
}
