use crate::behaviour::{Behaviour, BehaviourEvent};
use crate::discovery::enr;
use crate::multiaddr::Protocol;
use crate::types::{error, GossipKind};
use crate::EnrExt;
use crate::{NetworkConfig, NetworkGlobals};
use futures::prelude::*;
use libp2p::core::{
    identity::Keypair,
    multiaddr::Multiaddr,
    muxing::StreamMuxerBox,
    transport::boxed::Boxed,
    upgrade::{InboundUpgradeExt, OutboundUpgradeExt},
    ConnectedPoint,
};
use libp2p::{
    core, noise, secio,
    swarm::{NetworkBehaviour, SwarmBuilder, SwarmEvent},
    PeerId, Swarm, Transport,
};
use slog::{crit, debug, info, o, trace, warn};
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::DelayQueue;
use types::{EnrForkId, EthSpec};

pub const NETWORK_KEY_FILENAME: &str = "key";
/// The time in milliseconds to wait before banning a peer. This allows for any Goodbye messages to be
/// flushed and protocols to be negotiated.
const BAN_PEER_WAIT_TIMEOUT: u64 = 200;
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
    /// A peer has established at least one connection.
    PeerConnected {
        /// The peer that connected.
        peer_id: PeerId,
        /// Whether the peer was a dialer or listener.
        endpoint: ConnectedPoint,
    },
    /// A peer no longer has any connections, i.e is disconnected.
    PeerDisconnected {
        /// The peer the disconnected.
        peer_id: PeerId,
        /// Whether the peer was a dialer or a listener.
        endpoint: ConnectedPoint,
    },
}

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service<TSpec: EthSpec> {
    /// The libp2p Swarm handler.
    //TODO: Make this private
    pub swarm: Swarm<Behaviour<TSpec>>,

    /// This node's PeerId.
    pub local_peer_id: PeerId,

    /// Used for managing the state of peers.
    network_globals: Arc<NetworkGlobals<TSpec>>,

    /// A current list of peers to ban after a given timeout.
    peers_to_ban: DelayQueue<PeerId>,

    /// A list of timeouts after which peers become unbanned.
    peer_ban_timeout: DelayQueue<PeerId>,

    /// The libp2p logger handle.
    pub log: slog::Logger,
}

impl<TSpec: EthSpec> Service<TSpec> {
    pub fn new(
        config: &NetworkConfig,
        enr_fork_id: EnrForkId,
        log: &slog::Logger,
    ) -> error::Result<(Arc<NetworkGlobals<TSpec>>, Self)> {
        let log = log.new(o!("service"=> "libp2p"));
        trace!(log, "Libp2p Service starting");

        // initialise the node's ID
        let local_keypair = if let Some(hex_bytes) = &config.secret_key_hex {
            keypair_from_hex(hex_bytes)?
        } else {
            load_private_key(config, &log)
        };

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
        debug!(log, "Attempting to open listening ports"; "address" => format!("{}", config.listen_address), "tcp_port" => config.libp2p_port, "udp_port" => config.discovery_port);

        let mut swarm = {
            // Set up the transport - tcp/ws with noise/secio and mplex/yamux
            let transport = build_transport(local_keypair.clone())
                .map_err(|e| format!("Failed to build transport: {:?}", e))?;
            // Lighthouse network behaviour
            let behaviour = Behaviour::new(&local_keypair, config, network_globals.clone(), &log)?;

            // use the executor for libp2p
            struct Executor(tokio::runtime::Handle);
            impl libp2p::core::Executor for Executor {
                fn exec(&self, f: Pin<Box<dyn Future<Output = ()> + Send>>) {
                    self.0.spawn(f);
                }
            }
            SwarmBuilder::new(transport, behaviour, local_peer_id.clone())
                .peer_connection_limit(MAX_CONNECTIONS_PER_PEER)
                .executor(Box::new(Executor(tokio::runtime::Handle::current())))
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
        let mut dial_addr = |multiaddr: &Multiaddr| {
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
            dial_addr(multiaddr);
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
                    dial_addr(multiaddr);
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
            network_globals: network_globals.clone(),
            peers_to_ban: DelayQueue::new(),
            peer_ban_timeout: DelayQueue::new(),
            log,
        };

        Ok((network_globals, service))
    }

    /// Adds a peer to be banned for a period of time, specified by a timeout.
    pub fn disconnect_and_ban_peer(&mut self, peer_id: PeerId, timeout: Duration) {
        warn!(self.log, "Disconnecting and banning peer"; "peer_id" => peer_id.to_string(), "timeout" => format!("{:?}", timeout));
        self.peers_to_ban.insert(
            peer_id.clone(),
            Duration::from_millis(BAN_PEER_WAIT_TIMEOUT),
        );
        self.peer_ban_timeout.insert(peer_id, timeout);
    }

    pub async fn next_event(&mut self) -> Libp2pEvent<TSpec> {
        loop {
            tokio::select! {
            event = self.swarm.next_event() => {
                match event {
                    SwarmEvent::Behaviour(behaviour) => {
                        return Libp2pEvent::Behaviour(behaviour)
                    }
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint,
                        num_established,
                    } => {
                        debug!(self.log, "Connection established"; "peer_id"=> peer_id.to_string(), "connections" => num_established.get());
                        // if this is the first connection inform the network layer a new connection
                        // has been established and update the db
                        if num_established.get() == 1 {
                            // update the peerdb
                            match endpoint {
                                ConnectedPoint::Listener { .. } => {
                                    self.swarm.peer_manager().connect_ingoing(&peer_id);
                                }
                                ConnectedPoint::Dialer { .. } => self
                                    .network_globals
                                    .peers
                                    .write()
                                    .connect_outgoing(&peer_id),
                            }
                            return Libp2pEvent::PeerConnected { peer_id, endpoint };
                        }
                    }
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        cause,
                        endpoint,
                        num_established,
                    } => {
                        debug!(self.log, "Connection closed"; "peer_id"=> peer_id.to_string(), "cause" => cause.to_string(), "connections" => num_established);
                        if num_established == 0 {
                            // update the peer_db
                            self.swarm.peer_manager().notify_disconnect(&peer_id);
                            // the peer has disconnected
                            return Libp2pEvent::PeerDisconnected {
                                peer_id,
                                endpoint,
                            };
                        }
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
                    SwarmEvent::BannedPeer {
                        peer_id,
                        endpoint: _,
                    } => {
                        debug!(self.log, "Attempted to dial a banned peer"; "peer_id" => peer_id.to_string())
                    }
                    SwarmEvent::UnreachableAddr {
                        peer_id,
                        address,
                        error,
                        attempts_remaining,
                    } => {
                        debug!(self.log, "Failed to dial address"; "peer_id" => peer_id.to_string(), "address" => address.to_string(), "error" => error.to_string(), "attempts_remaining" => attempts_remaining);
                        self.swarm.peer_manager().notify_disconnect(&peer_id);
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
                        debug!(self.log, "Dialing peer"; "peer" => peer_id.to_string());
                        self.swarm.peer_manager().dialing_peer(&peer_id);
                    }
                }
            }
            Some(Ok(peer_to_ban)) = self.peers_to_ban.next() => {
                let peer_id = peer_to_ban.into_inner();
                Swarm::ban_peer_id(&mut self.swarm, peer_id.clone());
                // TODO: Correctly notify protocols of the disconnect
                // TODO: Also remove peer from the DHT: https://github.com/sigp/lighthouse/issues/629
                self.swarm.inject_disconnected(&peer_id);
                // inform the behaviour that the peer has been banned
                self.swarm.peer_banned(peer_id);
            }
            Some(Ok(peer_to_unban)) = self.peer_ban_timeout.next() => {
                debug!(self.log, "Peer has been unbanned"; "peer" => format!("{:?}", peer_to_unban));
                let unban_peer = peer_to_unban.into_inner();
                self.swarm.peer_unbanned(&unban_peer);
                Swarm::unban_peer_id(&mut self.swarm, unban_peer);
            }
            }
        }
    }
}

/// The implementation supports TCP/IP, WebSockets over TCP/IP, noise/secio as the encryption layer, and
/// mplex or yamux as the multiplexing layer.
fn build_transport(
    local_private_key: Keypair,
) -> Result<Boxed<(PeerId, StreamMuxerBox), Error>, Error> {
    let transport = libp2p_tcp::TokioTcpConfig::new().nodelay(true);
    let transport = libp2p::dns::DnsConfig::new(transport)?;
    #[cfg(feature = "libp2p-websocket")]
    let transport = {
        let trans_clone = transport.clone();
        transport.or_transport(websocket::WsConfig::new(trans_clone))
    };
    // Authentication
    let transport = transport
        .and_then(move |stream, endpoint| {
            let upgrade = core::upgrade::SelectUpgrade::new(
                generate_noise_config(&local_private_key),
                secio::SecioConfig::new(local_private_key),
            );
            core::upgrade::apply(stream, upgrade, endpoint, core::upgrade::Version::V1).and_then(
                |out| async move {
                    match out {
                        // Noise was negotiated
                        core::either::EitherOutput::First((remote_id, out)) => {
                            Ok((core::either::EitherOutput::First(out), remote_id))
                        }
                        // Secio was negotiated
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
                libp2p::yamux::Config::default(),
                libp2p::mplex::MplexConfig::new(),
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
    // TODO: Currently using secp256k1 keypairs - currently required for discv5
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
