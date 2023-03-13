#![cfg(test)]
use std::sync::Weak;
use tokio::runtime::Runtime;
use types::{
    ForkName, 
};
use slog::{o, debug, error};
use std::time::Duration;
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourAction};


use lighthouse_network::{NetworkEvent, EnrExt};
mod common;
use common::build_libp2p_instance;
use common::Libp2pInstance;

pub struct MockLibp2pLightClientInstance(MockLibP2PLightClientService, exit_future::Signal);

pub async fn build_mock_libp2p_light_client_instance() -> MockLibp2pLightClientInstance {
    unimplemented!()
}

#[allow(dead_code)]
pub async fn build_node_and_light_client(
    rt: Weak<Runtime>,
    log: &slog::Logger,
    fork_name: ForkName,
) -> (MockLibp2pLightClientInstance, Libp2pInstance) {
    let sender_log = log.new(o!("who" => "sender"));
    let receiver_log = log.new(o!("who" => "receiver"));

    // sender is light client
    let mut sender = build_mock_libp2p_light_client_instance().await;
    // receiver is full node
    let mut receiver = build_libp2p_instance(rt, vec![], receiver_log, fork_name).await;

    let receiver_multiaddr = receiver.local_enr().multiaddr()[1].clone();

    // let the two nodes set up listeners
    // TODO: use a differtent NetworkEvent for sender because it is a light client
    let sender_fut = async {
        loop {
            if let NetworkEvent::NewListenAddr(_) = sender.next_event().await {
                return;
            }
        }
    };
    let receiver_fut = async {
        loop {
            if let NetworkEvent::NewListenAddr(_) = receiver.next_event().await {
                return;
            }
        }
    };

    let joined = futures::future::join(sender_fut, receiver_fut);

    // wait for either both nodes to listen or a timeout
    tokio::select! {
        _  = tokio::time::sleep(Duration::from_millis(500)) => {}
        _ = joined => {}
    }

    // sender.dial_peer(peer_id);
    match sender.0.swarm.dial(receiver_multiaddr.clone()) {
        Ok(()) => {
            debug!(log, "Sender dialed receiver"; "address" => format!("{:?}", receiver_multiaddr))
        }
        Err(_) => error!(log, "Dialing failed"),
    };
    (sender, receiver)
}

//pub struct MockLibP2PLightClientService {
//    swarm: libp2p::swarm::Swarm<RPC>,
//}

type BehaviourAction =
    NetworkBehaviourAction<RPCMessage<Id, TSpec>, RPCHandler<Id, TSpec>>;

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC {
    /// Queue of events to be processed.
    events: Vec<BehaviourAction>,
//    fork_context: Arc<ForkContext>,
    /// Slog logger for RPC behaviour.
    log: slog::Logger,
}


