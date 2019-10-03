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
// use eth2_libp2p::{PubsubMessage, RPCEvent};
use slog_async;
use slog_term;

use slog::Drain;

fn setup_log() -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    slog::Logger::root(drain, o!())
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
fn test_network() {
    let log = setup_log();
    let bootnode = build_libp2p_instance(9000, Vec::new(), log.clone());
    let bootnode_enr = bootnode.swarm.discovery().local_enr().clone();
    let mut node1 = build_libp2p_instance(9001, vec![bootnode_enr.clone()], log.clone());
    let mut node2 = build_libp2p_instance(9002, vec![bootnode_enr.clone()], log.clone());
    dbg!(node1.swarm.connected_peers());
    dbg!(node2.swarm.connected_peers());
    dbg!(bootnode.swarm.connected_peers());
}
