use crate::behaviour::{Behaviour, BehaviourEvent, PubsubMessage};
use crate::error;
use crate::multiaddr::Protocol;
use crate::rpc::RPCEvent;
use crate::NetworkConfig;
use crate::{TopicBuilder, TopicHash};
use futures::prelude::*;
use futures::Stream;
use libp2p::core::{
    identity,
    muxing::StreamMuxerBox,
    nodes::Substream,
    transport::boxed::Boxed,
    upgrade::{InboundUpgradeExt, OutboundUpgradeExt},
};
use libp2p::identify::protocol::IdentifyInfo;
use libp2p::{core, secio, PeerId, Swarm, Transport};
use slog::{debug, info, trace, warn};
use std::io::{Error, ErrorKind};
use std::time::Duration;

type Libp2pStream = Boxed<(PeerId, StreamMuxerBox), Error>;
type Libp2pBehaviour = Behaviour<Substream<StreamMuxerBox>>;

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service {
    /// The libp2p Swarm handler.
    //TODO: Make this private
    pub swarm: Swarm<Libp2pStream, Libp2pBehaviour>,
    /// This node's PeerId.
    _local_peer_id: PeerId,
    /// The libp2p logger handle.
    pub log: slog::Logger,
}

impl Service {
    pub fn new(config: NetworkConfig, log: slog::Logger) -> error::Result<Self> {
        debug!(log, "Libp2p Service starting");

        // TODO: Currently using secp256k1 key pairs. Wire protocol specifies RSA. Waiting for this
        // PR to be merged to generate RSA keys: https://github.com/briansmith/ring/pull/733
        // TODO: Save and recover node key from disk
        let local_private_key = identity::Keypair::generate_secp256k1();

        let local_public_key = local_private_key.public();
        let local_peer_id = PeerId::from(local_private_key.public());
        info!(log, "Local peer id: {:?}", local_peer_id);

        let mut swarm = {
            // Set up the transport
            let transport = build_transport(local_private_key);
            // Set up gossipsub routing
            let behaviour = Behaviour::new(local_public_key.clone(), &config, &log);
            // Set up Topology
            let topology = local_peer_id.clone();
            Swarm::new(transport, behaviour, topology)
        };

        // listen on all addresses
        for address in config
            .listen_addresses()
            .map_err(|e| format!("Invalid listen multiaddr: {}", e))?
        {
            match Swarm::listen_on(&mut swarm, address.clone()) {
                Ok(mut listen_addr) => {
                    listen_addr.append(Protocol::P2p(local_peer_id.clone().into()));
                    info!(log, "Listening on: {}", listen_addr);
                }
                Err(err) => warn!(log, "Cannot listen on: {} : {:?}", address, err),
            };
        }
        // connect to boot nodes - these are currently stored as multiaddrs
        // Once we have discovery, can set to peerId
        for bootnode in config
            .boot_nodes()
            .map_err(|e| format!("Invalid boot node multiaddr: {:?}", e))?
        {
            match Swarm::dial_addr(&mut swarm, bootnode.clone()) {
                Ok(()) => debug!(log, "Dialing bootnode: {}", bootnode),
                Err(err) => debug!(
                    log,
                    "Could not connect to bootnode: {} error: {:?}", bootnode, err
                ),
            };
        }

        // subscribe to default gossipsub topics
        let mut topics = vec![];
        //TODO: Handle multiple shard attestations. For now we simply use a separate topic for
        //attestations
        topics.push(config.shard_prefix);
        topics.push(config.beacon_chain_topic);

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

impl Stream for Service {
    type Item = Libp2pEvent;
    type Error = crate::error::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            // TODO: Currently only gossipsub events passed here.
            // Build a type for more generic events
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
                    BehaviourEvent::Identified(peer_id, info) => {
                        return Ok(Async::Ready(Some(Libp2pEvent::Identified(peer_id, info))));
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
fn build_transport(local_private_key: identity::Keypair) -> Boxed<(PeerId, StreamMuxerBox), Error> {
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
pub enum Libp2pEvent {
    /// An RPC response request has been received on the swarm.
    RPC(PeerId, RPCEvent),
    /// Initiated the connection to a new peer.
    PeerDialed(PeerId),
    /// Received information about a peer on the network.
    Identified(PeerId, Box<IdentifyInfo>),
    /// Received pubsub message.
    PubsubMessage {
        source: PeerId,
        topics: Vec<TopicHash>,
        message: Box<PubsubMessage>,
    },
}
