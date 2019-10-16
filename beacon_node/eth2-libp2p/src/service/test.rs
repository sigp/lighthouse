#![cfg(test)]
use super::*;
use crate::rpc::{HelloMessage, RPCRequest};
use crate::NetworkConfig;
use enr::Enr;
use futures;
use slog::{debug, error, o, Drain};
use slog_stdlog;
use types::{Epoch, Hash256, Slot};
use Service as LibP2PService;

fn setup_log() -> slog::Logger {
    slog::Logger::root(slog_stdlog::StdLog.fuse(), o!())
}

// Testing
// 1) Test gossipsub and rpc without discovery with just 2 nodes
// 1.1) Use libp2p's boot_nodes to connect 2 nodes
// 1.2) Send message on all of the subscribed topics
// 1.3) Send message on unsubscribed topics
// 1.4) Subscribe to a new topic
// 2) RPC communication between 2 nodes for every type of RPC message

fn build_config(port: u16, mut boot_nodes: Vec<Enr>) -> NetworkConfig {
    let mut config = NetworkConfig::default();
    config.libp2p_port = port; // tcp port
    config.discovery_port = port; // udp port
    config.boot_nodes.append(&mut boot_nodes);
    config.network_dir.push(port.to_string());
    config
}

fn build_libp2p_instance(port: u16, boot_nodes: Vec<Enr>, log: slog::Logger) -> LibP2PService {
    let config = build_config(port, boot_nodes);
    let network_log = log.new(o!("Service" => "Libp2p"));
    // launch libp2p service
    let libp2p_service = LibP2PService::new(config.clone(), network_log.clone()).unwrap();
    libp2p_service
}

fn get_enr(node: &LibP2PService) -> Enr {
    node.swarm.discovery().local_enr().clone()
}

// Constructs, connects and returns 2 libp2p peers without discovery
fn build_nodes() -> Vec<LibP2PService> {
    let log = setup_log();
    let mut node1 = build_libp2p_instance(9000, vec![], log.clone());
    let node2 = build_libp2p_instance(9001, vec![], log.clone());
    match libp2p::Swarm::dial_addr(&mut node1.swarm, get_enr(&node2).multiaddr()[1].clone()) {
        Ok(()) => debug!(log, "Connected"),
        Err(_) => error!(log, "Failed to connect"),
    };
    vec![node1, node2]
}

#[test]
fn test_gossipsub() {
    let mut nodes = build_nodes();
    let pubsub_message = PubsubMessage::Block(vec![0; 4]);
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        for node in nodes.iter_mut() {
            loop {
                match node.poll().unwrap() {
                    Async::Ready(Some(Libp2pEvent::PubsubMessage {
                        topics, message, ..
                    })) => {
                        // Assert topics are eth2 topics
                        assert!(topics
                            .clone()
                            .iter()
                            .all(|t| t.clone().into_string() == "/eth2/beacon_block/ssz"));

                        // Assert message received is the correct one
                        assert_eq!(message, pubsub_message.clone());
                        return Ok(Async::Ready(()));
                    }
                    Async::Ready(Some(Libp2pEvent::PeerSubscribed(.., topic))) => {
                        // Received topics is one of subscribed eth2 topics
                        assert!(topic.clone().into_string().starts_with("/eth2/"));
                        // Publish on beacon block topic
                        if topic == TopicHash::from_raw("/eth2/beacon_block/ssz") {
                            node.swarm.publish(
                                &vec![Topic::new(topic.into_string())],
                                pubsub_message.clone(),
                            );
                        }
                    }
                    Async::Ready(Some(_)) => (),
                    Async::Ready(None) | Async::NotReady => break,
                }
            }
        }
        Ok(Async::NotReady)
    }))
}

#[test]
fn test_rpc() {
    let mut nodes = build_nodes();
    // Random rpc message
    let rpc_request = RPCRequest::Hello(HelloMessage {
        fork_version: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        for node in nodes.iter_mut() {
            loop {
                match node.poll().unwrap() {
                    Async::Ready(Some(Libp2pEvent::PeerDialed(peer_id))) => {
                        // Send an rpc message
                        node.swarm
                            .send_rpc(peer_id, RPCEvent::Request(1, rpc_request.clone()));
                    }
                    Async::Ready(Some(Libp2pEvent::RPC(_, event))) => match event {
                        // Should receive sent rpc message
                        RPCEvent::Request(id, request) => {
                            assert_eq!(id, 1);
                            assert_eq!(rpc_request.clone(), request);
                            return Ok(Async::Ready(()));
                        }
                        _ => panic!("Received incorrect rpc message"),
                    },
                    Async::Ready(Some(_)) => (),
                    Async::Ready(None) | Async::NotReady => break,
                }
            }
        }
        Ok(Async::NotReady)
    }))
}
