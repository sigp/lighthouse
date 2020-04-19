use crate::behaviour::{Behaviour, BehaviourEvent};
use crate::discovery::enr;
use crate::multiaddr::Protocol;
use crate::types::{error, GossipKind};
use crate::{NetworkConfig, NetworkGlobals};
use futures::prelude::*;
use futures::Stream;
use libp2p::core::{
    identity::Keypair,
    multiaddr::Multiaddr,
    muxing::StreamMuxerBox,
    nodes::Substream,
    transport::boxed::Boxed,
    upgrade::{InboundUpgradeExt, OutboundUpgradeExt},
    ConnectedPoint,
};
use libp2p::{core, noise, secio, swarm::NetworkBehaviour, PeerId, Swarm, Transport};
use slog::{crit, debug, error, info, trace, warn};
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::Duration;
use tokio::timer::DelayQueue;
use types::{EnrForkId, EthSpec};

type Libp2pStream = Boxed<(PeerId, StreamMuxerBox), Error>;
type Libp2pBehaviour<TSpec> = Behaviour<Substream<StreamMuxerBox>, TSpec>;

pub const NETWORK_KEY_FILENAME: &str = "key";
/// The time in milliseconds to wait before banning a peer. This allows for any Goodbye messages to be
/// flushed and protocols to be negotiated.
const BAN_PEER_WAIT_TIMEOUT: u64 = 200;

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service<TSpec: EthSpec> {
    /// The libp2p Swarm handler.
    //TODO: Make this private
    pub swarm: Swarm<Libp2pStream, Libp2pBehaviour<TSpec>>,

    /// This node's PeerId.
    pub local_peer_id: PeerId,

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
        log: slog::Logger,
    ) -> error::Result<(Arc<NetworkGlobals<TSpec>>, Self)> {
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
            let transport = build_transport(local_keypair.clone());
            // Lighthouse network behaviour
            let behaviour = Behaviour::new(&local_keypair, config, network_globals.clone(), &log)?;
            Swarm::new(transport, behaviour, local_peer_id.clone())
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
        for bootnode_enr in &config.boot_nodes {
            for multiaddr in &bootnode_enr.multiaddr() {
                // ignore udp multiaddr if it exists
                let components = multiaddr.iter().collect::<Vec<_>>();
                if let Protocol::Udp(_) = components[1] {
                    continue;
                }
                dial_addr(multiaddr);
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
            peers_to_ban: DelayQueue::new(),
            peer_ban_timeout: DelayQueue::new(),
            log,
        };

        Ok((network_globals, service))
    }

    /// Adds a peer to be banned for a period of time, specified by a timeout.
    pub fn disconnect_and_ban_peer(&mut self, peer_id: PeerId, timeout: Duration) {
        error!(self.log, "Disconnecting and banning peer"; "peer_id" => format!("{:?}", peer_id), "timeout" => format!("{:?}", timeout));
        self.peers_to_ban.insert(
            peer_id.clone(),
            Duration::from_millis(BAN_PEER_WAIT_TIMEOUT),
        );
        self.peer_ban_timeout.insert(peer_id, timeout);
    }
}

impl<TSpec: EthSpec> Stream for Service<TSpec> {
    type Item = BehaviourEvent<TSpec>;
    type Error = error::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match self.swarm.poll() {
                Ok(Async::Ready(Some(event))) => {
                    return Ok(Async::Ready(Some(event)));
                }
                Ok(Async::Ready(None)) => unreachable!("Swarm stream shouldn't end"),
                Ok(Async::NotReady) => break,
                _ => break,
            }
        }

        // check if peers need to be banned
        loop {
            match self.peers_to_ban.poll() {
                Ok(Async::Ready(Some(peer_id))) => {
                    let peer_id = peer_id.into_inner();
                    Swarm::ban_peer_id(&mut self.swarm, peer_id.clone());
                    // TODO: Correctly notify protocols of the disconnect
                    // TODO: Also remove peer from the DHT: https://github.com/sigp/lighthouse/issues/629
                    let dummy_connected_point = ConnectedPoint::Dialer {
                        address: "/ip4/0.0.0.0"
                            .parse::<Multiaddr>()
                            .expect("valid multiaddr"),
                    };
                    self.swarm
                        .inject_disconnected(&peer_id, dummy_connected_point);
                    // inform the behaviour that the peer has been banned
                    self.swarm.peer_banned(peer_id);
                }
                Ok(Async::NotReady) | Ok(Async::Ready(None)) => break,
                Err(e) => {
                    warn!(self.log, "Peer banning queue failed"; "error" => format!("{:?}", e));
                }
            }
        }

        // un-ban peer if it's timeout has expired
        loop {
            match self.peer_ban_timeout.poll() {
                Ok(Async::Ready(Some(peer_id))) => {
                    let peer_id = peer_id.into_inner();
                    debug!(self.log, "Peer has been unbanned"; "peer" => format!("{:?}", peer_id));
                    self.swarm.peer_unbanned(&peer_id);
                    Swarm::unban_peer_id(&mut self.swarm, peer_id);
                }
                Ok(Async::NotReady) | Ok(Async::Ready(None)) => break,
                Err(e) => {
                    warn!(self.log, "Peer banning timeout queue failed"; "error" => format!("{:?}", e));
                }
            }
        }

        Ok(Async::NotReady)
    }
}

/// The implementation supports TCP/IP, WebSockets over TCP/IP, noise/secio as the encryption layer, and
/// mplex or yamux as the multiplexing layer.
fn build_transport(local_private_key: Keypair) -> Boxed<(PeerId, StreamMuxerBox), Error> {
    // TODO: The Wire protocol currently doesn't specify encryption and this will need to be customised
    // in the future.
    let transport = libp2p::tcp::TcpConfig::new().nodelay(true);
    let transport = libp2p::dns::DnsConfig::new(transport);
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
                move |out| {
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
                .map(|(id, muxer)| (id, core::muxing::StreamMuxerBox::new(muxer)))
        })
        .timeout(Duration::from_secs(20))
        .map_err(|err| Error::new(ErrorKind::Other, err))
        .boxed();
    transport
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
) -> noise::NoiseAuthenticated<noise::XX, noise::X25519, ()> {
    let static_dh_keys = noise::Keypair::<noise::X25519>::new()
        .into_authentic(identity_keypair)
        .expect("signing can fail only once during starting a node");
    noise::NoiseConfig::xx(static_dh_keys).into_authenticated()
}
