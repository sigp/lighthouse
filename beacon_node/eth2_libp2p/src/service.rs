use crate::behaviour::{Behaviour, BehaviourEvent, PeerRequestId, Request, Response};
use crate::discovery::enr;
use crate::multiaddr::Protocol;
use crate::rpc::{GoodbyeReason, RPCResponseErrorCode, RequestId};
use crate::types::{error, GossipKind};
use crate::EnrExt;
use crate::{NetworkConfig, NetworkGlobals, PeerAction};
use futures::prelude::*;
use libp2p::core::{
    identity::Keypair,
    multiaddr::Multiaddr,
    muxing::StreamMuxerBox,
    transport::boxed::Boxed,
    upgrade::{InboundUpgradeExt, OutboundUpgradeExt},
};
use libp2p::{
    core, noise, secio,
    swarm::{SwarmBuilder, SwarmEvent},
    PeerId, Swarm, Transport,
};
use slog::{crit, debug, info, o, trace, warn};
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use types::{EnrForkId, EthSpec};

pub const NETWORK_KEY_FILENAME: &str = "key";
/// The maximum simultaneous libp2p connections per peer.
const MAX_CONNECTIONS_PER_PEER: usize = 1;

/// The types of events than can be obtained from polling the libp2p service.
///
/// This is a subset of the events that a libp2p swarm emits.
#[derive(Debug)]
pub enum Libp2pEvent<TSpec: EthSpec> {
    /// A behaviour event
    Behaviour(BehaviourEvent<TSpec>),
    /// A new listening address has been established.
    NewListenAddr(Multiaddr),
}

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service<TSpec: EthSpec> {
    /// The libp2p Swarm handler.
    pub swarm: Swarm<Behaviour<TSpec>>,

    /// This node's PeerId.
    pub local_peer_id: PeerId,

    /// The libp2p logger handle.
    pub log: slog::Logger,
}

impl<TSpec: EthSpec> Service<TSpec> {
    pub fn new(
        executor: environment::TaskExecutor,
        config: &NetworkConfig,
        enr_fork_id: EnrForkId,
        log: &slog::Logger,
    ) -> error::Result<(Arc<NetworkGlobals<TSpec>>, Self)> {
        let log = log.new(o!("service"=> "libp2p"));
        trace!(log, "Libp2p Service starting");

        // initialise the node's ID
        let local_keypair = load_private_key(config, &log);

        // Create an ENR or load from disk if appropriate
        let enr =
            enr::build_or_load_enr::<TSpec>(local_keypair.clone(), config, enr_fork_id, &log)?;

        let local_peer_id = enr.peer_id();
        // set up a collection of variables accessible outside of the network crate
        let network_globals = Arc::new(NetworkGlobals::new(
            enr.clone(),
            config.libp2p_port,
            config.discovery_port,
            &log,
        ));

        info!(log, "Libp2p Service"; "peer_id" => format!("{:?}", enr.peer_id()));
        let discovery_string = if config.disable_discovery {
            "None".into()
        } else {
            config.discovery_port.to_string()
        };
        debug!(log, "Attempting to open listening ports"; "address" => format!("{}", config.listen_address), "tcp_port" => config.libp2p_port, "udp_port" => discovery_string);

        let mut swarm = {
            // Set up the transport - tcp/ws with noise and yamux/mplex
            let transport = build_transport(local_keypair.clone())
                .map_err(|e| format!("Failed to build transport: {:?}", e))?;
            // Lighthouse network behaviour
            let behaviour = Behaviour::new(&local_keypair, config, network_globals.clone(), &log)?;

            // use the executor for libp2p
            struct Executor(environment::TaskExecutor);
            impl libp2p::core::Executor for Executor {
                fn exec(&self, f: Pin<Box<dyn Future<Output = ()> + Send>>) {
                    self.0.spawn(f, "libp2p");
                }
            }
            SwarmBuilder::new(transport, behaviour, local_peer_id.clone())
                .notify_handler_buffer_size(std::num::NonZeroUsize::new(32).expect("Not zero"))
                .connection_event_buffer_size(64)
                .incoming_connection_limit(10)
                .peer_connection_limit(MAX_CONNECTIONS_PER_PEER)
                .executor(Box::new(Executor(executor)))
                .build()
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
                log_address.push(Protocol::P2p(local_peer_id.clone().into()));
                info!(log, "Listening established"; "address" => format!("{}", log_address));
            }
            Err(err) => {
                crit!(
                    log,
                    "Unable to listen on libp2p address";
                    "error" => format!("{:?}", err),
                    "listen_multiaddr" => format!("{}", listen_multiaddr),
                );
                return Err("Libp2p was unable to listen on the given listen address.".into());
            }
        };

        // helper closure for dialing peers
        let mut dial_addr = |mut multiaddr: Multiaddr| {
            // strip the p2p protocol if it exists
            strip_peer_id(&mut multiaddr);
            match Swarm::dial_addr(&mut swarm, multiaddr.clone()) {
                Ok(()) => debug!(log, "Dialing libp2p peer"; "address" => format!("{}", multiaddr)),
                Err(err) => debug!(
                    log,
                    "Could not connect to peer"; "address" => format!("{}", multiaddr), "error" => format!("{:?}", err)
                ),
            };
        };

        // attempt to connect to user-input libp2p nodes
        for multiaddr in &config.libp2p_nodes {
            dial_addr(multiaddr.clone());
        }

        // attempt to connect to any specified boot-nodes
        let mut boot_nodes = config.boot_nodes.clone();
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

        let mut subscribed_topics: Vec<GossipKind> = vec![];
        for topic_kind in &config.topics {
            if swarm.subscribe_kind(topic_kind.clone()) {
                subscribed_topics.push(topic_kind.clone());
            } else {
                warn!(log, "Could not subscribe to topic"; "topic" => format!("{}",topic_kind));
            }
        }
        info!(log, "Subscribed to topics"; "topics" => format!("{:?}", subscribed_topics));

        let service = Service {
            local_peer_id,
            swarm,
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
    pub fn report_peer(&mut self, peer_id: &PeerId, action: PeerAction) {
        self.swarm.report_peer(peer_id, action);
    }

    // Disconnect and ban a peer, providing a reason.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason) {
        self.swarm.goodbye_peer(peer_id, reason);
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
                    debug!(self.log, "Connection closed"; "peer_id"=> peer_id.to_string(), "cause" => cause.to_string(), "connections" => num_established);
                }
                SwarmEvent::NewListenAddr(multiaddr) => {
                    return Libp2pEvent::NewListenAddr(multiaddr)
                }
                SwarmEvent::IncomingConnection {
                    local_addr,
                    send_back_addr,
                } => {
                    debug!(self.log, "Incoming connection"; "our_addr" => local_addr.to_string(), "from" => send_back_addr.to_string())
                }
                SwarmEvent::IncomingConnectionError {
                    local_addr,
                    send_back_addr,
                    error,
                } => {
                    debug!(self.log, "Failed incoming connection"; "our_addr" => local_addr.to_string(), "from" => send_back_addr.to_string(), "error" => error.to_string())
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
                    debug!(self.log, "Failed to dial address"; "peer_id" => peer_id.to_string(), "address" => address.to_string(), "error" => error.to_string(), "attempts_remaining" => attempts_remaining);
                }
                SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                    debug!(self.log, "Peer not known at dialed address"; "address" => address.to_string(), "error" => error.to_string());
                }
                SwarmEvent::ExpiredListenAddr(multiaddr) => {
                    debug!(self.log, "Listen address expired"; "multiaddr" => multiaddr.to_string())
                }
                SwarmEvent::ListenerClosed { addresses, reason } => {
                    debug!(self.log, "Listener closed"; "addresses" => format!("{:?}", addresses), "reason" => format!("{:?}", reason))
                }
                SwarmEvent::ListenerError { error } => {
                    debug!(self.log, "Listener error"; "error" => format!("{:?}", error.to_string()))
                }
                SwarmEvent::Dialing(peer_id) => {
                    debug!(self.log, "Dialing peer"; "peer_id" => peer_id.to_string());
                }
            }
        }
    }
}

/// The implementation supports TCP/IP, WebSockets over TCP/IP, noise as the encryption layer, and
/// yamux or mplex as the multiplexing layer.

fn build_transport(
    local_private_key: Keypair,
) -> Result<Boxed<(PeerId, StreamMuxerBox), Error>, Error> {
    let transport = libp2p::tcp::TokioTcpConfig::new().nodelay(true);
    let transport = libp2p::dns::DnsConfig::new(transport)?;
    #[cfg(feature = "libp2p-websocket")]
    let transport = {
        let trans_clone = transport.clone();
        transport.or_transport(libp2p::websocket::WsConfig::new(trans_clone))
    };
    // Authentication
    let transport = transport
        .and_then(move |stream, endpoint| {
            let upgrade = core::upgrade::SelectUpgrade::new(
                secio::SecioConfig::new(local_private_key.clone()),
                generate_noise_config(&local_private_key),
            );
            core::upgrade::apply(stream, upgrade, endpoint, core::upgrade::Version::V1).and_then(
                |out| async move {
                    match out {
                        // Secio was negotiated
                        core::either::EitherOutput::First((remote_id, out)) => {
                            Ok((core::either::EitherOutput::First(out), remote_id))
                        }
                        // Noise was negotiated
                        core::either::EitherOutput::Second((remote_id, out)) => {
                            Ok((core::either::EitherOutput::Second(out), remote_id))
                        }
                    }
                },
            )
        })
        .timeout(Duration::from_secs(20));

    // Multiplexing
    let transport = transport
        .and_then(move |(stream, peer_id), endpoint| {
            let peer_id2 = peer_id.clone();
            let upgrade = core::upgrade::SelectUpgrade::new(
                libp2p::mplex::MplexConfig::new(),
                libp2p::yamux::Config::default(),
            )
            .map_inbound(move |muxer| (peer_id, muxer))
            .map_outbound(move |muxer| (peer_id2, muxer));

            core::upgrade::apply(stream, upgrade, endpoint, core::upgrade::Version::V1)
                .map_ok(|(id, muxer)| (id, core::muxing::StreamMuxerBox::new(muxer)))
        })
        .timeout(Duration::from_secs(20))
        .map_err(|err| Error::new(ErrorKind::Other, err))
        .boxed();
    Ok(transport)
}

// Useful helper functions for debugging. Currently not used in the client.
#[allow(dead_code)]
fn keypair_from_hex(hex_bytes: &str) -> error::Result<Keypair> {
    let hex_bytes = if hex_bytes.starts_with("0x") {
        hex_bytes[2..].to_string()
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
fn load_private_key(config: &NetworkConfig, log: &slog::Logger) -> Keypair {
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
