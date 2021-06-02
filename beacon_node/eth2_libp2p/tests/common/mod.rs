#![cfg(test)]
use eth2_libp2p::Enr;
use eth2_libp2p::EnrExt;
use eth2_libp2p::Multiaddr;
use eth2_libp2p::Service as LibP2PService;
use eth2_libp2p::{Libp2pEvent, NetworkConfig};
use libp2p::gossipsub::GossipsubConfigBuilder;
use slog::{debug, error, o, Drain};
use std::net::{TcpListener, UdpSocket};
use std::sync::Weak;
use std::time::Duration;
use tokio::runtime::Runtime;
use types::{ChainSpec, EnrForkId, MinimalEthSpec};

type E = MinimalEthSpec;
use tempfile::Builder as TempBuilder;

pub struct Libp2pInstance(LibP2PService<E>, exit_future::Signal);

impl std::ops::Deref for Libp2pInstance {
    type Target = LibP2PService<E>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Libp2pInstance {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

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

// A bit of hack to find an unused port.
///
/// Does not guarantee that the given port is unused after the function exits, just that it was
/// unused before the function started (i.e., it does not reserve a port).
pub fn unused_port(transport: &str) -> Result<u16, String> {
    let local_addr = match transport {
        "tcp" => {
            let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| {
                format!("Failed to create TCP listener to find unused port: {:?}", e)
            })?;
            listener.local_addr().map_err(|e| {
                format!(
                    "Failed to read TCP listener local_addr to find unused port: {:?}",
                    e
                )
            })?
        }
        "udp" => {
            let socket = UdpSocket::bind("127.0.0.1:0")
                .map_err(|e| format!("Failed to create UDP socket to find unused port: {:?}", e))?;
            socket.local_addr().map_err(|e| {
                format!(
                    "Failed to read UDP socket local_addr to find unused port: {:?}",
                    e
                )
            })?
        }
        _ => return Err("Invalid transport to find unused port".into()),
    };
    Ok(local_addr.port())
}

pub fn build_config(port: u16, mut boot_nodes: Vec<Enr>) -> NetworkConfig {
    let mut config = NetworkConfig::default();
    let path = TempBuilder::new()
        .prefix(&format!("libp2p_test{}", port))
        .tempdir()
        .unwrap();

    config.libp2p_port = port; // tcp port
    config.discovery_port = port; // udp port
    config.enr_tcp_port = Some(port);
    config.enr_udp_port = Some(port);
    config.enr_address = Some("127.0.0.1".parse().unwrap());
    config.boot_nodes_enr.append(&mut boot_nodes);
    config.network_dir = path.into_path();
    // Reduce gossipsub heartbeat parameters
    config.gs_config = GossipsubConfigBuilder::from(config.gs_config)
        .heartbeat_initial_delay(Duration::from_millis(500))
        .heartbeat_interval(Duration::from_millis(500))
        .build()
        .unwrap();
    config
}

pub async fn build_libp2p_instance(
    rt: Weak<Runtime>,
    boot_nodes: Vec<Enr>,
    log: slog::Logger,
) -> Libp2pInstance {
    let port = unused_port("tcp").unwrap();
    let config = build_config(port, boot_nodes);
    // launch libp2p service

    let (signal, exit) = exit_future::signal();
    let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
    let executor = task_executor::TaskExecutor::new(rt, exit, log.clone(), shutdown_tx);
    Libp2pInstance(
        LibP2PService::new(
            executor,
            &config,
            EnrForkId::default(),
            &log,
            &ChainSpec::minimal(),
        )
        .await
        .expect("should build libp2p instance")
        .1,
        signal,
    )
}

#[allow(dead_code)]
pub fn get_enr(node: &LibP2PService<E>) -> Enr {
    node.swarm.local_enr()
}

// Returns `n` libp2p peers in fully connected topology.
#[allow(dead_code)]
pub async fn build_full_mesh(
    rt: Weak<Runtime>,
    log: slog::Logger,
    n: usize,
) -> Vec<Libp2pInstance> {
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n {
        nodes.push(build_libp2p_instance(rt.clone(), vec![], log.clone()).await);
    }
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

// Constructs a pair of nodes with separate loggers. The sender dials the receiver.
// This returns a (sender, receiver) pair.
#[allow(dead_code)]
pub async fn build_node_pair(
    rt: Weak<Runtime>,
    log: &slog::Logger,
) -> (Libp2pInstance, Libp2pInstance) {
    let sender_log = log.new(o!("who" => "sender"));
    let receiver_log = log.new(o!("who" => "receiver"));

    let mut sender = build_libp2p_instance(rt.clone(), vec![], sender_log).await;
    let mut receiver = build_libp2p_instance(rt, vec![], receiver_log).await;

    let receiver_multiaddr = receiver.swarm.local_enr().multiaddr()[1].clone();

    // let the two nodes set up listeners
    let sender_fut = async {
        loop {
            if let Libp2pEvent::NewListenAddr(_) = sender.next_event().await {
                return;
            }
        }
    };
    let receiver_fut = async {
        loop {
            if let Libp2pEvent::NewListenAddr(_) = receiver.next_event().await {
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

    match libp2p::Swarm::dial_addr(&mut sender.swarm, receiver_multiaddr.clone()) {
        Ok(()) => {
            debug!(log, "Sender dialed receiver"; "address" => format!("{:?}", receiver_multiaddr))
        }
        Err(_) => error!(log, "Dialing failed"),
    };
    (sender, receiver)
}

// Returns `n` peers in a linear topology
#[allow(dead_code)]
pub async fn build_linear(rt: Weak<Runtime>, log: slog::Logger, n: usize) -> Vec<Libp2pInstance> {
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n {
        nodes.push(build_libp2p_instance(rt.clone(), vec![], log.clone()).await);
    }

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
