#![cfg(test)]
use super::*;
// use crate::service::Service as NetworkService;
use crate::NetworkConfig;
// use beacon_chain::{
//     lmd_ghost::ThreadSafeReducedTree, slot_clock::SystemTimeSlotClock, store::Store,
//     test_utils::generate_deterministic_keypairs, BeaconChain, BeaconChainBuilder,
// };
use eth2_libp2p::Service as LibP2PService;
// use eth2_libp2p::Topic;
// use eth2_libp2p::{Enr, Libp2pEvent, Multiaddr, PeerId, Swarm};
use eth2_libp2p::Libp2pEvent;
use slog::Drain;
use slog_stdlog;

fn setup_log() -> slog::Logger {
    slog::Logger::root(slog_stdlog::StdLog.fuse(), o!())
}

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
    let network_log = log.new(o!("Service" => "Network"));
    // launch libp2p service
    let libp2p_service = LibP2PService::new(config.clone(), network_log.clone()).unwrap();
    libp2p_service
}

#[test]
fn test_connection() {
    let log = setup_log();
    let bootnode = build_libp2p_instance(9000, Vec::new(), log.clone());
    let bootnode_enr = bootnode.swarm.discovery().local_enr().clone();
    let node1 = build_libp2p_instance(9001, vec![bootnode_enr.clone()], log.clone());
    let node2 = build_libp2p_instance(9002, vec![bootnode_enr.clone()], log.clone());
    println!("Bootnode peer id: {}", bootnode.local_peer_id);
    println!("Node1 peer id: {}", node1.local_peer_id);
    println!("Node2 peer id: {}", node2.local_peer_id);
    let mut swarms = vec![bootnode, node1, node2];
    tokio::run(futures::future::poll_fn(move || -> Result<_, ()> {
        for swarm in swarms.iter_mut() {
            loop {
                match swarm.poll().unwrap() {
                    Async::Ready(Some(Libp2pEvent::PeerDialed(peer_id))) => {
                        println!("Node {} is dialing node {}", &swarm.local_peer_id, peer_id);
                        println!(
                            "Node {} is connected to {} peers",
                            &swarm.local_peer_id,
                            swarm.swarm.discovery().connected_peers()
                        );
                    }
                    Async::Ready(_) => (),
                    Async::NotReady => break,
                }
            }
        }
        Ok(Async::NotReady)
    }))
}
