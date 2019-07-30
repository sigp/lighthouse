use crate::behaviour::{Behaviour, BehaviourEvent, PubsubMessage};
use crate::error;
use crate::multiaddr::Protocol;
use crate::rpc::RPCEvent;
use crate::NetworkConfig;
use crate::{TopicBuilder, TopicHash};
use crate::{BEACON_ATTESTATION_TOPIC, BEACON_PUBSUB_TOPIC};
use futures::prelude::*;
use futures::Stream;
use libp2p::core::{
    identity::Keypair,
    multiaddr::Multiaddr,
    muxing::StreamMuxerBox,
    nodes::Substream,
    transport::boxed::Boxed,
    upgrade::{InboundUpgradeExt, OutboundUpgradeExt},
};
use libp2p::{core, secio, PeerId, Swarm, Transport};
use slog::{debug, info, trace, warn};
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::time::Duration;
use types::EthSpec;

type Libp2pStream = Boxed<(PeerId, StreamMuxerBox), Error>;
type Libp2pBehaviour<E> = Behaviour<Substream<StreamMuxerBox>, E>;

const NETWORK_KEY_FILENAME: &str = "key";

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service<E: EthSpec> {
    /// The libp2p Swarm handler.
    //TODO: Make this private
    pub swarm: Swarm<Libp2pStream, Libp2pBehaviour<E>>,
    /// This node's PeerId.
    _local_peer_id: PeerId,
    /// The libp2p logger handle.
    pub log: slog::Logger,
}

impl<E: EthSpec> Service<E> {
    pub fn new(config: NetworkConfig, log: slog::Logger) -> error::Result<Self> {
        debug!(log, "Network-libp2p Service starting");

        // load the private key from CLI flag, disk or generate a new one
        let local_private_key = load_private_key(&config, &log);

        let local_peer_id = PeerId::from(local_private_key.public());
        info!(log, "Local peer id: {:?}", local_peer_id);

        let mut swarm = {
            // Set up the transport - tcp/ws with secio and mplex/yamux
            let transport = build_transport(local_private_key.clone());
            // Lighthouse network behaviour
            let behaviour = Behaviour::new(&local_private_key, &config, &log)?;
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
                info!(log, "Listening on: {}", log_address);
            }
            Err(err) => warn!(
                log,
                "Cannot listen on: {} because: {:?}", listen_multiaddr, err
            ),
        };

        // subscribe to default gossipsub topics
        let mut topics = vec![];
        //TODO: Handle multiple shard attestations. For now we simply use a separate topic for
        //attestations
        topics.push(BEACON_ATTESTATION_TOPIC.to_string());
        topics.push(BEACON_PUBSUB_TOPIC.to_string());
        topics.append(&mut config.topics.clone());

        let mut subscribed_topics = vec![];
        for topic in topics {
            let t = TopicBuilder::new(topic.clone()).build();
            if swarm.subscribe(t) {
                trace!(log, "Subscribed to topic: {:?}", topic);
                subscribed_topics.push(topic);
            } else {
                warn!(log, "Could not subscribe to topic: {:?}", topic)
            }
        }
        info!(log, "Subscribed to topics: {:?}", subscribed_topics);

        Ok(Service {
            _local_peer_id: local_peer_id,
            swarm,
            log,
        })
    }
}

impl<E: EthSpec> Stream for Service<E> {
    type Item = Libp2pEvent<E>;
    type Error = crate::error::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match self.swarm.poll() {
                //Behaviour events
                Ok(Async::Ready(Some(event))) => match event {
                    // TODO: Stub here for debugging
                    BehaviourEvent::GossipMessage {
                        source,
                        topics,
                        message,
                    } => {
                        trace!(self.log, "Pubsub message received: {:?}", message);
                        return Ok(Async::Ready(Some(Libp2pEvent::PubsubMessage {
                            source,
                            topics,
                            message,
                        })));
                    }
                    BehaviourEvent::RPC(peer_id, event) => {
                        return Ok(Async::Ready(Some(Libp2pEvent::RPC(peer_id, event))));
                    }
                    BehaviourEvent::PeerDialed(peer_id) => {
                        return Ok(Async::Ready(Some(Libp2pEvent::PeerDialed(peer_id))));
                    }
                    BehaviourEvent::PeerDisconnected(peer_id) => {
                        return Ok(Async::Ready(Some(Libp2pEvent::PeerDisconnected(peer_id))));
                    }
                },
                Ok(Async::Ready(None)) => unreachable!("Swarm stream shouldn't end"),
                Ok(Async::NotReady) => break,
                _ => break,
            }
        }
        Ok(Async::NotReady)
    }
}

/// The implementation supports TCP/IP, WebSockets over TCP/IP, secio as the encryption layer, and
/// mplex or yamux as the multiplexing layer.
fn build_transport(local_private_key: Keypair) -> Boxed<(PeerId, StreamMuxerBox), Error> {
    // TODO: The Wire protocol currently doesn't specify encryption and this will need to be customised
    // in the future.
    let transport = libp2p::tcp::TcpConfig::new();
    let transport = libp2p::dns::DnsConfig::new(transport);
    #[cfg(feature = "libp2p-websocket")]
    let transport = {
        let trans_clone = transport.clone();
        transport.or_transport(websocket::WsConfig::new(trans_clone))
    };
    transport
        .with_upgrade(secio::SecioConfig::new(local_private_key))
        .and_then(move |out, endpoint| {
            let peer_id = out.remote_key.into_peer_id();
            let peer_id2 = peer_id.clone();
            let upgrade = core::upgrade::SelectUpgrade::new(
                libp2p::yamux::Config::default(),
                libp2p::mplex::MplexConfig::new(),
            )
            // TODO: use a single `.map` instead of two maps
            .map_inbound(move |muxer| (peer_id, muxer))
            .map_outbound(move |muxer| (peer_id2, muxer));

            core::upgrade::apply(out.stream, upgrade, endpoint)
                .map(|(id, muxer)| (id, core::muxing::StreamMuxerBox::new(muxer)))
        })
        .with_timeout(Duration::from_secs(20))
        .map_err(|err| Error::new(ErrorKind::Other, err))
        .boxed()
}

/// Events that can be obtained from polling the Libp2p Service.
pub enum Libp2pEvent<E: EthSpec> {
    /// An RPC response request has been received on the swarm.
    RPC(PeerId, RPCEvent),
    /// Initiated the connection to a new peer.
    PeerDialed(PeerId),
    /// A peer has disconnected.
    PeerDisconnected(PeerId),
    /// Received pubsub message.
    PubsubMessage {
        source: PeerId,
        topics: Vec<TopicHash>,
        message: Box<PubsubMessage<E>>,
    },
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
                    "Could not write node key to file: {:?}. Error: {}", network_key_f, e
                );
            }
        }
    }
    local_private_key
}
