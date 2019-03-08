use crate::behaviour::Behaviour;
use crate::multiaddr::Protocol;
use crate::NetworkConfig;
use futures::prelude::*;
use libp2p::core::{
    muxing::StreamMuxerBox,
    nodes::Substream,
    transport::boxed::Boxed,
    upgrade::{InboundUpgradeExt, OutboundUpgradeExt},
};
use libp2p::{core, secio, Transport};
use libp2p::{PeerId, Swarm};
use slog::{debug, info, warn};
use std::io::{Error, ErrorKind};
use std::time::Duration;

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service {
    /// The libp2p Swarm handler.
    swarm: Swarm<Boxed<(PeerId, StreamMuxerBox), Error>, Behaviour<Substream<StreamMuxerBox>>>,
    /// This node's PeerId.
    local_peer_id: PeerId,
}

impl Service {
    pub fn new(config: NetworkConfig, log: slog::Logger) -> Self {
        debug!(log, "Libp2p Service starting");

        let local_private_key = config.local_private_key;
        let local_peer_id = local_private_key.to_peer_id();
        debug!(log, "Local peer id: {:?}", local_peer_id);

        let mut swarm = {
            // Set up the transport
            let transport = build_transport(local_private_key);
            // Set up gossipsub routing
            let behaviour = Behaviour::new(local_peer_id.clone(), config.gs_config);
            // Set up Topology
            let topology = local_peer_id.clone();
            Swarm::new(transport, behaviour, topology)
        };

        // listen on all addresses
        for address in &config.listen_addresses {
            match Swarm::listen_on(&mut swarm, address.clone()) {
                Ok(mut listen_addr) => {
                    listen_addr.append(Protocol::P2p(local_peer_id.clone().into()));
                    info!(log, "Listening on: {}", listen_addr);
                }
                Err(err) => warn!(log, "Cannot listen on: {} : {:?}", address, err),
            };
        }
        // connect to boot nodes - these are currently stored as multiadders
        // Once we have discovery, can set to peerId
        for bootnode in config.boot_nodes {
            match Swarm::dial_addr(&mut swarm, bootnode.clone()) {
                Ok(()) => debug!(log, "Dialing bootnode: {}", bootnode),
                Err(err) => debug!(
                    log,
                    "Could not connect to bootnode: {} error: {:?}", bootnode, err
                ),
            };
        }

        Service {
            local_peer_id,
            swarm,
        }
    }
}

/// The implementation supports TCP/IP, WebSockets over TCP/IP, secio as the encryption layer, and
/// mplex or yamux as the multiplexing layer.
fn build_transport(
    local_private_key: secio::SecioKeyPair,
) -> Boxed<(PeerId, StreamMuxerBox), Error> {
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
