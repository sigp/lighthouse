#![cfg(test)]
use super::*;
use crate::NetworkConfig;
use enr::Enr;
use futures;
use slog::{o, Drain};
use slog_stdlog;
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
    config.topics.append(&mut vec!["test_topic".into()]);
    config
}

fn build_libp2p_instance(port: u16, boot_nodes: Vec<Enr>, log: slog::Logger) -> LibP2PService {
    let config = build_config(port, boot_nodes);
    let network_log = log.new(o!("Service" => "Libp2p"));
    // launch libp2p service
    let libp2p_service = LibP2PService::new(config.clone(), network_log.clone()).unwrap();
    libp2p_service
}

fn get_enr(nodes: Vec<&LibP2PService>) -> Vec<Enr> {
    nodes
        .iter()
        .map(|n| n.swarm.discovery().local_enr().clone())
        .collect::<Vec<_>>()
}

#[test]
fn test_gossipsub() {
    let log = setup_log();
    let node1 = build_libp2p_instance(9000, vec![], log.clone());
    let node2 = build_libp2p_instance(9001, get_enr(vec![&node1]), log.clone());
    let node3 = build_libp2p_instance(9002, get_enr(vec![&node1, &node2]), log.clone());
    let mut nodes = vec![node1, node2, node3];
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        for (i, node) in nodes.iter_mut().enumerate() {
            loop {
                match node.poll().unwrap() {
                    Async::Ready(Some(Libp2pEvent::PeerDialed(peer_id))) => {
                        println!(
                            "Node {} {} connected to {}\nTotal nodes connected to: {}\n",
                            i,
                            node.local_peer_id,
                            peer_id,
                            node.swarm.connected_peers()
                        );
                        let topic = vec![Topic::new("test_topic".into())];
                        node.swarm.publish(&topic, PubsubMessage::Block(vec![0; 4]));
                    }
                    Async::Ready(Some(Libp2pEvent::PubsubMessage {
                        id: _id, source, ..
                    })) => {
                        println!(
                            "{} received pubsub message from {}",
                            node.local_peer_id, source
                        );
                        return Ok(Async::Ready(()));
                    }
                    Async::Ready(_) => (),
                    Async::NotReady => break,
                }
            }
        }
        Ok(Async::NotReady)
    }))
}
