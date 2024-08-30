#![cfg(test)]
use lighthouse_network::service::Network as LibP2PService;
use lighthouse_network::Enr;
use lighthouse_network::EnrExt;
use lighthouse_network::Multiaddr;
use lighthouse_network::{NetworkConfig, NetworkEvent};
use slog::{debug, error, o, Drain};
use std::sync::Arc;
use std::sync::Weak;
use tokio::runtime::Runtime;
use types::{
    ChainSpec, EnrForkId, Epoch, EthSpec, FixedBytesExtended, ForkContext, ForkName, Hash256,
    MinimalEthSpec, Slot,
};

type E = MinimalEthSpec;

use tempfile::Builder as TempBuilder;

/// Returns a dummy fork context
pub fn fork_context(fork_name: ForkName) -> ForkContext {
    let mut chain_spec = E::default_spec();
    let altair_fork_epoch = Epoch::new(1);
    let bellatrix_fork_epoch = Epoch::new(2);
    let capella_fork_epoch = Epoch::new(3);
    let deneb_fork_epoch = Epoch::new(4);
    let electra_fork_epoch = Epoch::new(5);
    let eip7732_fork_epoch = Epoch::new(6);

    chain_spec.altair_fork_epoch = Some(altair_fork_epoch);
    chain_spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
    chain_spec.capella_fork_epoch = Some(capella_fork_epoch);
    chain_spec.deneb_fork_epoch = Some(deneb_fork_epoch);
    chain_spec.electra_fork_epoch = Some(electra_fork_epoch);
    chain_spec.eip7732_fork_epoch = Some(eip7732_fork_epoch);

    let current_slot = match fork_name {
        ForkName::Base => Slot::new(0),
        ForkName::Altair => altair_fork_epoch.start_slot(E::slots_per_epoch()),
        ForkName::Bellatrix => bellatrix_fork_epoch.start_slot(E::slots_per_epoch()),
        ForkName::Capella => capella_fork_epoch.start_slot(E::slots_per_epoch()),
        ForkName::Deneb => deneb_fork_epoch.start_slot(E::slots_per_epoch()),
        ForkName::Electra => electra_fork_epoch.start_slot(E::slots_per_epoch()),
        ForkName::EIP7732 => eip7732_fork_epoch.start_slot(E::slots_per_epoch()),
    };
    ForkContext::new::<E>(current_slot, Hash256::zero(), &chain_spec)
}

pub struct Libp2pInstance(
    LibP2PService<E>,
    #[allow(dead_code)]
    // This field is managed for lifetime purposes may not be used directly, hence the `#[allow(dead_code)]` attribute.
    async_channel::Sender<()>,
);

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

#[allow(unused)]
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

pub fn build_config(mut boot_nodes: Vec<Enr>) -> Arc<NetworkConfig> {
    let mut config = NetworkConfig::default();

    // Find unused ports by using the 0 port.
    let port = 0;

    let random_path: u16 = rand::random();
    let path = TempBuilder::new()
        .prefix(&format!("libp2p_test_{}", random_path))
        .tempdir()
        .unwrap();

    config.set_ipv4_listening_address(std::net::Ipv4Addr::UNSPECIFIED, port, port, port);
    config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    config.boot_nodes_enr.append(&mut boot_nodes);
    config.network_dir = path.into_path();
    Arc::new(config)
}

pub async fn build_libp2p_instance(
    rt: Weak<Runtime>,
    boot_nodes: Vec<Enr>,
    log: slog::Logger,
    fork_name: ForkName,
    chain_spec: Arc<ChainSpec>,
) -> Libp2pInstance {
    let config = build_config(boot_nodes);
    // launch libp2p service

    let (signal, exit) = async_channel::bounded(1);
    let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
    let executor = task_executor::TaskExecutor::new(rt, exit, log.clone(), shutdown_tx);
    let libp2p_context = lighthouse_network::Context {
        config,
        enr_fork_id: EnrForkId::default(),
        fork_context: Arc::new(fork_context(fork_name)),
        chain_spec,
        libp2p_registry: None,
    };
    Libp2pInstance(
        LibP2PService::new(executor, libp2p_context, &log)
            .await
            .expect("should build libp2p instance")
            .0,
        signal,
    )
}

#[allow(dead_code)]
pub fn get_enr(node: &LibP2PService<E>) -> Enr {
    node.local_enr()
}

// Protocol for the node pair connection.
pub enum Protocol {
    Tcp,
    Quic,
}

// Constructs a pair of nodes with separate loggers. The sender dials the receiver.
// This returns a (sender, receiver) pair.
#[allow(dead_code)]
pub async fn build_node_pair(
    rt: Weak<Runtime>,
    log: &slog::Logger,
    fork_name: ForkName,
    spec: Arc<ChainSpec>,
    protocol: Protocol,
) -> (Libp2pInstance, Libp2pInstance) {
    let sender_log = log.new(o!("who" => "sender"));
    let receiver_log = log.new(o!("who" => "receiver"));

    let mut sender =
        build_libp2p_instance(rt.clone(), vec![], sender_log, fork_name, spec.clone()).await;
    let mut receiver =
        build_libp2p_instance(rt, vec![], receiver_log, fork_name, spec.clone()).await;

    // let the two nodes set up listeners
    let sender_fut = async {
        loop {
            if let NetworkEvent::NewListenAddr(addr) = sender.next_event().await {
                // Only end once we've listened on the protocol we care about
                match protocol {
                    Protocol::Tcp => {
                        if addr.iter().any(|multiaddr_proto| {
                            matches!(multiaddr_proto, libp2p::multiaddr::Protocol::Tcp(_))
                        }) {
                            return addr;
                        }
                    }
                    Protocol::Quic => {
                        if addr.iter().any(|multiaddr_proto| {
                            matches!(multiaddr_proto, libp2p::multiaddr::Protocol::QuicV1)
                        }) {
                            return addr;
                        }
                    }
                }
            }
        }
    };
    let receiver_fut = async {
        loop {
            if let NetworkEvent::NewListenAddr(addr) = receiver.next_event().await {
                match protocol {
                    Protocol::Tcp => {
                        if addr.iter().any(|multiaddr_proto| {
                            matches!(multiaddr_proto, libp2p::multiaddr::Protocol::Tcp(_))
                        }) {
                            return addr;
                        }
                    }
                    Protocol::Quic => {
                        if addr.iter().any(|multiaddr_proto| {
                            matches!(multiaddr_proto, libp2p::multiaddr::Protocol::QuicV1)
                        }) {
                            return addr;
                        }
                    }
                }
            }
        }
    };

    let joined = futures::future::join(sender_fut, receiver_fut);

    let receiver_multiaddr = joined.await.1;

    match sender.testing_dial(receiver_multiaddr.clone()) {
        Ok(()) => {
            debug!(log, "Sender dialed receiver"; "address" => format!("{:?}", receiver_multiaddr))
        }
        Err(_) => error!(log, "Dialing failed"),
    };
    (sender, receiver)
}

// Returns `n` peers in a linear topology
#[allow(dead_code)]
pub async fn build_linear(
    rt: Weak<Runtime>,
    log: slog::Logger,
    n: usize,
    fork_name: ForkName,
    spec: Arc<ChainSpec>,
) -> Vec<Libp2pInstance> {
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n {
        nodes.push(
            build_libp2p_instance(rt.clone(), vec![], log.clone(), fork_name, spec.clone()).await,
        );
    }

    let multiaddrs: Vec<Multiaddr> = nodes
        .iter()
        .map(|x| get_enr(x).multiaddr()[1].clone())
        .collect();
    for i in 0..n - 1 {
        match nodes[i].testing_dial(multiaddrs[i + 1].clone()) {
            Ok(()) => debug!(log, "Connected"),
            Err(_) => error!(log, "Failed to connect"),
        };
    }
    nodes
}
