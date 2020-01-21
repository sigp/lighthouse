#![cfg(test)]
use enr::Enr;
use eth2_libp2p::Multiaddr;
use eth2_libp2p::NetworkConfig;
use eth2_libp2p::Service as LibP2PService;
use slog::{debug, error, o, Drain};
use std::time::Duration;

pub fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    if enabled {
        slog::Logger::root(drain.filter_level(level).fuse(), o!())
    } else {
        slog::Logger::root(drain.filter(|_| false).fuse(), o!())
    }
}

pub fn build_config(
    port: u16,
    mut boot_nodes: Vec<Enr>,
    secret_key: Option<String>,
) -> NetworkConfig {
    let mut config = NetworkConfig::default();
    config.libp2p_port = port; // tcp port
    config.discovery_port = port; // udp port
    config.boot_nodes.append(&mut boot_nodes);
    config.secret_key_hex = secret_key;
    config.network_dir.push(port.to_string());
    // Reduce gossipsub heartbeat parameters
    config.gs_config.heartbeat_initial_delay = Duration::from_millis(500);
    config.gs_config.heartbeat_interval = Duration::from_millis(500);
    config
}

pub fn build_libp2p_instance(
    port: u16,
    boot_nodes: Vec<Enr>,
    secret_key: Option<String>,
    log: slog::Logger,
) -> LibP2PService {
    let config = build_config(port, boot_nodes, secret_key);
    // launch libp2p service
    LibP2PService::new(config, log.clone()).unwrap()
}

#[allow(dead_code)]
pub fn get_enr(node: &LibP2PService) -> Enr {
    node.swarm.discovery().local_enr().clone()
}

// Returns `n` libp2p peers in fully connected topology.
#[allow(dead_code)]
pub fn build_full_mesh(log: slog::Logger, n: usize, start_port: Option<u16>) -> Vec<LibP2PService> {
    let base_port = start_port.unwrap_or(9000);
    let mut nodes: Vec<LibP2PService> = (base_port..base_port + n as u16)
        .map(|p| build_libp2p_instance(p, vec![], None, log.clone()))
        .collect();
    let multiaddrs: Vec<Multiaddr> = nodes
        .iter()
        .map(|x| get_enr(&x).multiaddr()[1].clone())
        .collect();

    for (i, node) in nodes.iter_mut().enumerate().take(n) {
        for (j, multiaddr) in multiaddrs.iter().enumerate().skip(i) {
            if i != j {
                match libp2p::Swarm::dial_addr(&mut node.swarm, multiaddr.clone()) {
                    Ok(()) => debug!(log, "Connected"),
                    Err(_) => error!(log, "Failed to connect"),
                };
            }
        }
    }
    nodes
}

// Constructs a pair of nodes with seperate loggers. The sender dials the receiver.
// This returns a (sender, receiver) pair.
#[allow(dead_code)]
pub fn build_node_pair(log: &slog::Logger, start_port: u16) -> (LibP2PService, LibP2PService) {
    let sender_log = log.new(o!("who" => "sender"));
    let receiver_log = log.new(o!("who" => "receiver"));

    let mut sender = build_libp2p_instance(start_port, vec![], None, sender_log);
    let receiver = build_libp2p_instance(start_port + 1, vec![], None, receiver_log);

    let receiver_multiaddr = receiver.swarm.discovery().local_enr().clone().multiaddr()[1].clone();
    match libp2p::Swarm::dial_addr(&mut sender.swarm, receiver_multiaddr) {
        Ok(()) => debug!(log, "Sender dialed receiver"),
        Err(_) => error!(log, "Dialing failed"),
    };
    (sender, receiver)
}

// Returns `n` peers in a linear topology
#[allow(dead_code)]
pub fn build_linear(log: slog::Logger, n: usize, start_port: Option<u16>) -> Vec<LibP2PService> {
    let base_port = start_port.unwrap_or(9000);
    let mut nodes: Vec<LibP2PService> = (base_port..base_port + n as u16)
        .map(|p| build_libp2p_instance(p, vec![], None, log.clone()))
        .collect();
    let multiaddrs: Vec<Multiaddr> = nodes
        .iter()
        .map(|x| get_enr(&x).multiaddr()[1].clone())
        .collect();
    for i in 0..n - 1 {
        match libp2p::Swarm::dial_addr(&mut nodes[i].swarm, multiaddrs[i + 1].clone()) {
            Ok(()) => debug!(log, "Connected"),
            Err(_) => error!(log, "Failed to connect"),
        };
    }
    nodes
}
