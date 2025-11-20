#![cfg(test)]
use lighthouse_network::Enr;
use lighthouse_network::Multiaddr;
use lighthouse_network::service::Network as LibP2PService;
use lighthouse_network::{NetworkConfig, NetworkEvent};
use network_utils::enr_ext::EnrExt;
use std::sync::Arc;
use std::sync::Weak;
use tokio::runtime::Runtime;
use tracing::{Instrument, debug, error, info_span};
use tracing_subscriber::EnvFilter;
use types::{
    ChainSpec, EnrForkId, Epoch, EthSpec, FixedBytesExtended, ForkContext, ForkName, Hash256,
    MinimalEthSpec,
};

type E = MinimalEthSpec;

use lighthouse_network::identity::secp256k1;
use lighthouse_network::rpc::config::InboundRateLimiterConfig;
use tempfile::Builder as TempBuilder;

/// Returns a chain spec with all forks enabled.
pub fn spec_with_all_forks_enabled() -> ChainSpec {
    let mut chain_spec = E::default_spec();
    chain_spec.altair_fork_epoch = Some(Epoch::new(1));
    chain_spec.bellatrix_fork_epoch = Some(Epoch::new(2));
    chain_spec.capella_fork_epoch = Some(Epoch::new(3));
    chain_spec.deneb_fork_epoch = Some(Epoch::new(4));
    chain_spec.electra_fork_epoch = Some(Epoch::new(5));
    chain_spec.fulu_fork_epoch = Some(Epoch::new(6));
    chain_spec.gloas_fork_epoch = Some(Epoch::new(7));

    // check that we have all forks covered
    assert!(chain_spec.fork_epoch(ForkName::latest()).is_some());
    chain_spec
}

/// Returns a dummy fork context
pub fn fork_context(fork_name: ForkName, spec: &ChainSpec) -> ForkContext {
    let current_epoch = match fork_name {
        ForkName::Base => Some(Epoch::new(0)),
        ForkName::Altair => spec.altair_fork_epoch,
        ForkName::Bellatrix => spec.bellatrix_fork_epoch,
        ForkName::Capella => spec.capella_fork_epoch,
        ForkName::Deneb => spec.deneb_fork_epoch,
        ForkName::Electra => spec.electra_fork_epoch,
        ForkName::Fulu => spec.fulu_fork_epoch,
        ForkName::Gloas => spec.gloas_fork_epoch,
    };
    let current_slot = current_epoch
        .unwrap_or_else(|| panic!("expect fork {fork_name} to be scheduled"))
        .start_slot(E::slots_per_epoch());
    ForkContext::new::<E>(current_slot, Hash256::zero(), spec)
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
pub fn build_tracing_subscriber(
    level: &str,
    enabled: bool,
) -> Option<tracing::subscriber::DefaultGuard> {
    if enabled {
        Some(tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::try_new(level).unwrap())
                .finish(),
        ))
    } else {
        None
    }
}

pub fn build_config(
    mut boot_nodes: Vec<Enr>,
    disable_peer_scoring: bool,
    inbound_rate_limiter: Option<InboundRateLimiterConfig>,
) -> Arc<NetworkConfig> {
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
    config.disable_peer_scoring = disable_peer_scoring;
    config.inbound_rate_limiter_config = inbound_rate_limiter;
    Arc::new(config)
}

pub async fn build_libp2p_instance(
    rt: Weak<Runtime>,
    boot_nodes: Vec<Enr>,
    fork_name: ForkName,
    chain_spec: Arc<ChainSpec>,
    service_name: String,
    disable_peer_scoring: bool,
    inbound_rate_limiter: Option<InboundRateLimiterConfig>,
) -> Libp2pInstance {
    let config = build_config(boot_nodes, disable_peer_scoring, inbound_rate_limiter);
    // launch libp2p service

    let (signal, exit) = async_channel::bounded(1);
    let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
    let executor = task_executor::TaskExecutor::new(rt, exit, shutdown_tx, service_name);
    let custody_group_count = chain_spec.custody_requirement;
    let libp2p_context = lighthouse_network::Context {
        config,
        enr_fork_id: EnrForkId::default(),
        fork_context: Arc::new(fork_context(fork_name, &chain_spec)),
        chain_spec,
        libp2p_registry: None,
    };
    Libp2pInstance(
        LibP2PService::new(
            executor,
            libp2p_context,
            custody_group_count,
            secp256k1::Keypair::generate().into(),
        )
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
    fork_name: ForkName,
    spec: Arc<ChainSpec>,
    protocol: Protocol,
    disable_peer_scoring: bool,
    inbound_rate_limiter: Option<InboundRateLimiterConfig>,
) -> (Libp2pInstance, Libp2pInstance) {
    let mut sender = build_libp2p_instance(
        rt.clone(),
        vec![],
        fork_name,
        spec.clone(),
        "sender".to_string(),
        disable_peer_scoring,
        inbound_rate_limiter.clone(),
    )
    .await;
    let mut receiver = build_libp2p_instance(
        rt,
        vec![],
        fork_name,
        spec.clone(),
        "receiver".to_string(),
        disable_peer_scoring,
        inbound_rate_limiter,
    )
    .await;

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
    }
    .instrument(info_span!("Sender", who = "sender"));
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
    }
    .instrument(info_span!("Receiver", who = "receiver"));

    let joined = futures::future::join(sender_fut, receiver_fut);

    let receiver_multiaddr = joined.await.1;

    match sender.testing_dial(receiver_multiaddr.clone()) {
        Ok(()) => {
            debug!(address = ?receiver_multiaddr, "Sender dialed receiver")
        }
        Err(_) => error!("Dialing failed"),
    };
    (sender, receiver)
}

// Returns `n` peers in a linear topology
#[allow(dead_code)]
pub async fn build_linear(
    rt: Weak<Runtime>,
    n: usize,
    fork_name: ForkName,
    spec: Arc<ChainSpec>,
) -> Vec<Libp2pInstance> {
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n {
        nodes.push(
            build_libp2p_instance(
                rt.clone(),
                vec![],
                fork_name,
                spec.clone(),
                "linear".to_string(),
                false,
                None,
            )
            .await,
        );
    }

    let multiaddrs: Vec<Multiaddr> = nodes
        .iter()
        .map(|x| get_enr(x).multiaddr()[1].clone())
        .collect();
    for i in 0..n - 1 {
        match nodes[i].testing_dial(multiaddrs[i + 1].clone()) {
            Ok(()) => debug!("Connected"),
            Err(_) => error!("Failed to connect"),
        };
    }
    nodes
}
