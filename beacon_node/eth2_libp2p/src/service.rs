use crate::behaviour::{
    save_metadata_to_disk, Behaviour, BehaviourEvent, PeerRequestId, Request, Response,
};
use crate::discovery::enr;
use crate::multiaddr::Protocol;
use crate::rpc::{GoodbyeReason, MetaData, RPCResponseErrorCode, RequestId};
use crate::types::{error, EnrBitfield, GossipKind};
use crate::EnrExt;
use crate::{NetworkConfig, NetworkGlobals, PeerAction, ReportSource};
use futures::prelude::*;
use libp2p::core::{
    connection::ConnectionLimits, identity::Keypair, multiaddr::Multiaddr, muxing::StreamMuxerBox,
    transport::Boxed,
};
use libp2p::{
    bandwidth::{BandwidthLogging, BandwidthSinks},
    core, noise,
    swarm::{SwarmBuilder, SwarmEvent},
    PeerId, Swarm, Transport,
};
use slog::{crit, debug, info, o, trace, warn, Logger};
use ssz::Decode;
use std::fs::File;
use std::io::prelude::*;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use types::{ChainSpec, EnrForkId, EthSpec};

pub const NETWORK_KEY_FILENAME: &str = "key";
/// The maximum simultaneous libp2p connections per peer.
const MAX_CONNECTIONS_PER_PEER: u32 = 1;
/// The filename to store our local metadata.
pub const METADATA_FILENAME: &str = "metadata";

/// The types of events than can be obtained from polling the libp2p service.
///
/// This is a subset of the events that a libp2p swarm emits.
#[derive(Debug)]
pub enum Libp2pEvent<TSpec: EthSpec> {
    /// A behaviour event
    Behaviour(BehaviourEvent<TSpec>),
    /// A new listening address has been established.
    NewListenAddr(Multiaddr),
    /// We reached zero listening addresses.
    ZeroListeners,
}

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service<TSpec: EthSpec> {
    /// The libp2p Swarm handler.
    pub swarm: Swarm<Behaviour<TSpec>>,
    /// The bandwidth logger for the underlying libp2p transport.
    pub bandwidth: Arc<BandwidthSinks>,
    /// This node's PeerId.
    pub local_peer_id: PeerId,
    /// The libp2p logger handle.
    pub log: Logger,
}

impl<TSpec: EthSpec> Service<TSpec> {
    pub async fn new(
        executor: task_executor::TaskExecutor,
        config: &NetworkConfig,
        enr_fork_id: EnrForkId,
        log: &Logger,
        chain_spec: &ChainSpec,
    ) -> error::Result<(Arc<NetworkGlobals<TSpec>>, Self)> {
        let log = log.new(o!("service"=> "libp2p"));
        trace!(log, "Libp2p Service starting");

        // initialise the node's ID
        let local_keypair = load_private_key(config, &log);

        // Create an ENR or load from disk if appropriate
        let enr =
            enr::build_or_load_enr::<TSpec>(local_keypair.clone(), config, enr_fork_id, &log)?;

        let local_peer_id = enr.peer_id();

        let meta_data = load_or_build_metadata(&config.network_dir, &log);

        // set up a collection of variables accessible outside of the network crate
        let network_globals = Arc::new(NetworkGlobals::new(
            enr.clone(),
            config.libp2p_port,
            config.discovery_port,
            meta_data,
            config
                .trusted_peers
                .iter()
                .map(|x| PeerId::from(x.clone()))
                .collect(),
            &log,
        ));

        info!(log, "Libp2p Service"; "peer_id" => %enr.peer_id());
        let discovery_string = if config.disable_discovery {
            "None".into()
        } else {
            config.discovery_port.to_string()
        };
        debug!(log, "Attempting to open listening ports"; "address" => ?config.listen_address, "tcp_port" => config.libp2p_port, "udp_port" => discovery_string);

        let (mut swarm, bandwidth) = {
            // Set up the transport - tcp/ws with noise and mplex
            let (transport, bandwidth) = build_transport(local_keypair.clone())
                .map_err(|e| format!("Failed to build transport: {:?}", e))?;

            // Lighthouse network behaviour
            let behaviour = Behaviour::new(
                &local_keypair,
                config,
                network_globals.clone(),
                &log,
                chain_spec,
            )
            .await?;

            // use the executor for libp2p
            struct Executor(task_executor::TaskExecutor);
            impl libp2p::core::Executor for Executor {
                fn exec(&self, f: Pin<Box<dyn Future<Output = ()> + Send>>) {
                    self.0.spawn(f, "libp2p");
                }
            }

            // sets up the libp2p connection limits
            let limits = ConnectionLimits::default()
                .with_max_pending_incoming(Some(5))
                .with_max_pending_outgoing(Some(16))
                .with_max_established_incoming(Some((config.target_peers as f64 * 1.2) as u32))
                .with_max_established_outgoing(Some((config.target_peers as f64 * 1.2) as u32))
                .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER));

            (
                SwarmBuilder::new(transport, behaviour, local_peer_id)
                    .notify_handler_buffer_size(std::num::NonZeroUsize::new(7).expect("Not zero"))
                    .connection_event_buffer_size(64)
                    .connection_limits(limits)
                    .executor(Box::new(Executor(executor)))
                    .build(),
                bandwidth,
            )
        };

        // listen on the specified address
        let listen_multiaddr = {
            let mut m = Multiaddr::from(config.listen_address);
            m.push(Protocol::Tcp(config.libp2p_port));
            m
        };

        match Swarm::listen_on(&mut swarm, listen_multiaddr.clone()) {
            Ok(_) => {
                let mut log_address = listen_multiaddr;
                log_address.push(Protocol::P2p(local_peer_id.into()));
                info!(log, "Listening established"; "address" => %log_address);
            }
            Err(err) => {
                crit!(
                    log,
                    "Unable to listen on libp2p address";
                    "error" => ?err,
                    "listen_multiaddr" => %listen_multiaddr,
                );
                return Err("Libp2p was unable to listen on the given listen address.".into());
            }
        };

        // helper closure for dialing peers
        let mut dial_addr = |mut multiaddr: Multiaddr| {
            // strip the p2p protocol if it exists
            strip_peer_id(&mut multiaddr);
            match Swarm::dial_addr(&mut swarm, multiaddr.clone()) {
                Ok(()) => debug!(log, "Dialing libp2p peer"; "address" => %multiaddr),
                Err(err) => debug!(
                    log,
                    "Could not connect to peer"; "address" => %multiaddr, "error" => ?err
                ),
            };
        };

        // attempt to connect to user-input libp2p nodes
        for multiaddr in &config.libp2p_nodes {
            dial_addr(multiaddr.clone());
        }

        // attempt to connect to any specified boot-nodes
        let mut boot_nodes = config.boot_nodes_enr.clone();
        boot_nodes.dedup();

        for bootnode_enr in boot_nodes {
            for multiaddr in &bootnode_enr.multiaddr() {
                // ignore udp multiaddr if it exists
                let components = multiaddr.iter().collect::<Vec<_>>();
                if let Protocol::Udp(_) = components[1] {
                    continue;
                }

                if !network_globals
                    .peers
                    .read()
                    .is_connected_or_dialing(&bootnode_enr.peer_id())
                {
                    dial_addr(multiaddr.clone());
                }
            }
        }

        for multiaddr in &config.boot_nodes_multiaddr {
            // check TCP support for dialing
            if multiaddr
                .iter()
                .any(|proto| matches!(proto, Protocol::Tcp(_)))
            {
                dial_addr(multiaddr.clone());
            }
        }

        let mut subscribed_topics: Vec<GossipKind> = vec![];

        for topic_kind in &config.topics {
            if swarm.subscribe_kind(topic_kind.clone()) {
                subscribed_topics.push(topic_kind.clone());
            } else {
                warn!(log, "Could not subscribe to topic"; "topic" => %topic_kind);
            }
        }

        if !subscribed_topics.is_empty() {
            info!(log, "Subscribed to topics"; "topics" => ?subscribed_topics);
        }

        let service = Service {
            swarm,
            bandwidth,
            local_peer_id,
            log,
        };

        Ok((network_globals, service))
    }

    /// Sends a request to a peer, with a given Id.
    pub fn send_request(&mut self, peer_id: PeerId, request_id: RequestId, request: Request) {
        self.swarm.send_request(peer_id, request_id, request);
    }

    /// Informs the peer that their request failed.
    pub fn respond_with_error(
        &mut self,
        peer_id: PeerId,
        id: PeerRequestId,
        error: RPCResponseErrorCode,
        reason: String,
    ) {
        self.swarm._send_error_reponse(peer_id, id, error, reason);
    }

    /// Report a peer's action.
    pub fn report_peer(&mut self, peer_id: &PeerId, action: PeerAction, source: ReportSource) {
        self.swarm.report_peer(peer_id, action, source);
    }

    /// Disconnect and ban a peer, providing a reason.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason, source: ReportSource) {
        self.swarm.goodbye_peer(peer_id, reason, source);
    }

    /// Sends a response to a peer's request.
    pub fn send_response(&mut self, peer_id: PeerId, id: PeerRequestId, response: Response<TSpec>) {
        self.swarm.send_successful_response(peer_id, id, response);
    }

    pub async fn next_event(&mut self) -> Libp2pEvent<TSpec> {
        loop {
            match self.swarm.next_event().await {
                SwarmEvent::Behaviour(behaviour) => return Libp2pEvent::Behaviour(behaviour),
                SwarmEvent::ConnectionEstablished { .. } => {
                    // A connection could be established with a banned peer. This is
                    // handled inside the behaviour.
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    cause,
                    endpoint: _,
                    num_established,
                } => {
                    trace!(self.log, "Connection closed"; "peer_id" => %peer_id, "cause" => ?cause, "connections" => num_established);
                }
                SwarmEvent::NewListenAddr(multiaddr) => {
                    return Libp2pEvent::NewListenAddr(multiaddr)
                }
                SwarmEvent::IncomingConnection {
                    local_addr,
                    send_back_addr,
                } => {
                    trace!(self.log, "Incoming connection"; "our_addr" => %local_addr, "from" => %send_back_addr)
                }
                SwarmEvent::IncomingConnectionError {
                    local_addr,
                    send_back_addr,
                    error,
                } => {
                    debug!(self.log, "Failed incoming connection"; "our_addr" => %local_addr, "from" => %send_back_addr, "error" => %error)
                }
                SwarmEvent::BannedPeer { .. } => {
                    // We do not ban peers at the swarm layer, so this should never occur.
                }
                SwarmEvent::UnreachableAddr {
                    peer_id,
                    address,
                    error,
                    attempts_remaining,
                } => {
                    debug!(self.log, "Failed to dial address"; "peer_id" => %peer_id, "address" => %address, "error" => %error, "attempts_remaining" => attempts_remaining);
                }
                SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                    debug!(self.log, "Peer not known at dialed address"; "address" => %address, "error" => %error);
                }
                SwarmEvent::ExpiredListenAddr(multiaddr) => {
                    debug!(self.log, "Listen address expired"; "multiaddr" => %multiaddr)
                }
                SwarmEvent::ListenerClosed { addresses, reason } => {
                    crit!(self.log, "Listener closed"; "addresses" => ?addresses, "reason" => ?reason);
                    if Swarm::listeners(&self.swarm).count() == 0 {
                        return Libp2pEvent::ZeroListeners;
                    }
                }
                SwarmEvent::ListenerError { error } => {
                    // this is non fatal, but we still check
                    warn!(self.log, "Listener error"; "error" => ?error);
                    if Swarm::listeners(&self.swarm).count() == 0 {
                        return Libp2pEvent::ZeroListeners;
                    }
                }
                SwarmEvent::Dialing(peer_id) => {
                    debug!(self.log, "Dialing peer"; "peer_id" => %peer_id);
                }
            }
        }
    }
}

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

/// The implementation supports TCP/IP, WebSockets over TCP/IP, noise as the encryption layer, and
/// mplex as the multiplexing layer.
fn build_transport(
    local_private_key: Keypair,
) -> std::io::Result<(BoxedTransport, Arc<BandwidthSinks>)> {
    let transport = libp2p::tcp::TokioTcpConfig::new().nodelay(true);
    let transport = libp2p::dns::DnsConfig::new(transport)?;
    #[cfg(feature = "libp2p-websocket")]
    let transport = {
        let trans_clone = transport.clone();
        transport.or_transport(libp2p::websocket::WsConfig::new(trans_clone))
    };

    let (transport, bandwidth) = BandwidthLogging::new(transport);

    // mplex config
    let mut mplex_config = libp2p::mplex::MplexConfig::new();
    mplex_config.set_max_buffer_size(256);
    mplex_config.set_max_buffer_behaviour(libp2p::mplex::MaxBufferBehaviour::Block);

    // Authentication
    Ok((
        transport
            .upgrade(core::upgrade::Version::V1)
            .authenticate(generate_noise_config(&local_private_key))
            .multiplex(core::upgrade::SelectUpgrade::new(
                libp2p::yamux::YamuxConfig::default(),
                mplex_config,
            ))
            .timeout(Duration::from_secs(10))
            .boxed(),
        bandwidth,
    ))
}

// Useful helper functions for debugging. Currently not used in the client.
#[allow(dead_code)]
fn keypair_from_hex(hex_bytes: &str) -> error::Result<Keypair> {
    let hex_bytes = if let Some(stripped) = hex_bytes.strip_prefix("0x") {
        stripped.to_string()
    } else {
        hex_bytes.to_string()
    };

    hex::decode(&hex_bytes)
        .map_err(|e| format!("Failed to parse p2p secret key bytes: {:?}", e).into())
        .and_then(keypair_from_bytes)
}

#[allow(dead_code)]
fn keypair_from_bytes(mut bytes: Vec<u8>) -> error::Result<Keypair> {
    libp2p::core::identity::secp256k1::SecretKey::from_bytes(&mut bytes)
        .map(|secret| {
            let keypair: libp2p::core::identity::secp256k1::Keypair = secret.into();
            Keypair::Secp256k1(keypair)
        })
        .map_err(|e| format!("Unable to parse p2p secret key: {:?}", e).into())
}

/// Loads a private key from disk. If this fails, a new key is
/// generated and is then saved to disk.
///
/// Currently only secp256k1 keys are allowed, as these are the only keys supported by discv5.
pub fn load_private_key(config: &NetworkConfig, log: &slog::Logger) -> Keypair {
    // check for key from disk
    let network_key_f = config.network_dir.join(NETWORK_KEY_FILENAME);
    if let Ok(mut network_key_file) = File::open(network_key_f.clone()) {
        let mut key_bytes: Vec<u8> = Vec::with_capacity(36);
        match network_key_file.read_to_end(&mut key_bytes) {
            Err(_) => debug!(log, "Could not read network key file"),
            Ok(_) => {
                // only accept secp256k1 keys for now
                if let Ok(secret_key) =
                    libp2p::core::identity::secp256k1::SecretKey::from_bytes(&mut key_bytes)
                {
                    let kp: libp2p::core::identity::secp256k1::Keypair = secret_key.into();
                    debug!(log, "Loaded network key from disk.");
                    return Keypair::Secp256k1(kp);
                } else {
                    debug!(log, "Network key file is not a valid secp256k1 key");
                }
            }
        }
    }

    // if a key could not be loaded from disk, generate a new one and save it
    let local_private_key = Keypair::generate_secp256k1();
    if let Keypair::Secp256k1(key) = local_private_key.clone() {
        let _ = std::fs::create_dir_all(&config.network_dir);
        match File::create(network_key_f.clone())
            .and_then(|mut f| f.write_all(&key.secret().to_bytes()))
        {
            Ok(_) => {
                debug!(log, "New network key generated and written to disk");
            }
            Err(e) => {
                warn!(
                    log,
                    "Could not write node key to file: {:?}. error: {}", network_key_f, e
                );
            }
        }
    }
    local_private_key
}

/// Generate authenticated XX Noise config from identity keys
fn generate_noise_config(
    identity_keypair: &Keypair,
) -> noise::NoiseAuthenticated<noise::XX, noise::X25519Spec, ()> {
    let static_dh_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(identity_keypair)
        .expect("signing can fail only once during starting a node");
    noise::NoiseConfig::xx(static_dh_keys).into_authenticated()
}

/// For a multiaddr that ends with a peer id, this strips this suffix. Rust-libp2p
/// only supports dialing to an address without providing the peer id.
fn strip_peer_id(addr: &mut Multiaddr) {
    let last = addr.pop();
    match last {
        Some(Protocol::P2p(_)) => {}
        Some(other) => addr.push(other),
        _ => {}
    }
}

/// Load metadata from persisted file. Return default metadata if loading fails.
fn load_or_build_metadata<E: EthSpec>(
    network_dir: &std::path::Path,
    log: &slog::Logger,
) -> MetaData<E> {
    // Default metadata
    let mut meta_data = MetaData {
        seq_number: 0,
        attnets: EnrBitfield::<E>::default(),
    };
    // Read metadata from persisted file if available
    let metadata_path = network_dir.join(METADATA_FILENAME);
    if let Ok(mut metadata_file) = File::open(metadata_path) {
        let mut metadata_ssz = Vec::new();
        if metadata_file.read_to_end(&mut metadata_ssz).is_ok() {
            match MetaData::<E>::from_ssz_bytes(&metadata_ssz) {
                Ok(persisted_metadata) => {
                    meta_data.seq_number = persisted_metadata.seq_number;
                    // Increment seq number if persisted attnet is not default
                    if persisted_metadata.attnets != meta_data.attnets {
                        meta_data.seq_number += 1;
                    }
                    debug!(log, "Loaded metadata from disk");
                }
                Err(e) => {
                    debug!(
                        log,
                        "Metadata from file could not be decoded";
                        "error" => ?e,
                    );
                }
            }
        }
    };

    debug!(log, "Metadata sequence number"; "seq_num" => meta_data.seq_number);
    save_metadata_to_disk(network_dir, meta_data.clone(), &log);
    meta_data
}
