use crate::task_spawner::TaskSpawner;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::EndpointVersion;
use lighthouse_network::PubsubMessage;
use lighthouse_network::rpc::methods::MetaData;
use network::{NetworkMessage, ValidatorSubscriptionMessage};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use types::{ChainSpec, EthSpec, ForkName};
use warp::Rejection;
use warp::filters::BoxedFilter;

pub type ResponseFilter = BoxedFilter<(warp::reply::Response,)>;
pub type AnyVersionFilter = BoxedFilter<(EndpointVersion,)>;
pub type EthV1Filter = BoxedFilter<()>;
pub type ChainFilter<T> = BoxedFilter<(Arc<BeaconChain<T>>,)>;
pub type NotWhileSyncingFilter = BoxedFilter<(Result<(), Rejection>,)>;
pub type TaskSpawnerFilter<T> = BoxedFilter<(TaskSpawner<<T as BeaconChainTypes>::EthSpec>,)>;
pub type ValidatorSubscriptionTxFilter = BoxedFilter<(Sender<ValidatorSubscriptionMessage>,)>;
pub type NetworkTxFilter<T> =
    BoxedFilter<(UnboundedSender<NetworkMessage<<T as BeaconChainTypes>::EthSpec>>,)>;
pub type OptionalConsensusVersionHeaderFilter = BoxedFilter<(Option<ForkName>,)>;

pub fn from_meta_data<E: EthSpec>(
    meta_data: &RwLock<MetaData<E>>,
    spec: &ChainSpec,
) -> eth2::types::MetaData {
    let meta_data = meta_data.read();
    let format_hex = |bytes: &[u8]| format!("0x{}", hex::encode(bytes));

    let seq_number = *meta_data.seq_number();
    let attnets = format_hex(&meta_data.attnets().clone().into_bytes());
    let syncnets = format_hex(
        &meta_data
            .syncnets()
            .cloned()
            .unwrap_or_default()
            .into_bytes(),
    );

    if spec.is_peer_das_scheduled() {
        eth2::types::MetaData::V3(eth2::types::MetaDataV3 {
            seq_number,
            attnets,
            syncnets,
            custody_group_count: meta_data.custody_group_count().cloned().unwrap_or_default(),
        })
    } else {
        eth2::types::MetaData::V2(eth2::types::MetaDataV2 {
            seq_number,
            attnets,
            syncnets,
        })
    }
}

/// Publish a message to the libp2p pubsub network.
pub fn publish_pubsub_message<E: EthSpec>(
    network_tx: &UnboundedSender<NetworkMessage<E>>,
    message: PubsubMessage<E>,
) -> Result<(), warp::Rejection> {
    publish_network_message(
        network_tx,
        NetworkMessage::Publish {
            messages: vec![message],
        },
    )
}

/// Publish a message to the libp2p pubsub network.
pub fn publish_pubsub_messages<E: EthSpec>(
    network_tx: &UnboundedSender<NetworkMessage<E>>,
    messages: Vec<PubsubMessage<E>>,
) -> Result<(), warp::Rejection> {
    publish_network_message(network_tx, NetworkMessage::Publish { messages })
}

/// Publish a message to the libp2p network.
pub fn publish_network_message<E: EthSpec>(
    network_tx: &UnboundedSender<NetworkMessage<E>>,
    message: NetworkMessage<E>,
) -> Result<(), warp::Rejection> {
    network_tx.send(message).map_err(|e| {
        warp_utils::reject::custom_server_error(format!(
            "unable to publish to network channel: {}",
            e
        ))
    })
}
