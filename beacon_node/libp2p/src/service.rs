use crate::behaviour::Behaviour;
use crate::NetworkConfig;
use futures::prelude::*;
use libp2p::core::{
    muxing::StreamMuxerBox,
    nodes::Substream,
    transport::boxed::Boxed,
    upgrade::{InboundUpgrade, InboundUpgradeExt, OutboundUpgrade, OutboundUpgradeExt},
};
use libp2p::{build_tcp_ws_secio_mplex_yamux, core, secio, Transport};
use libp2p::{PeerId, Swarm};
use slog::debug;
use std::error;
use std::io::{Error, ErrorKind};
use std::time::Duration;

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service {
    /// The libp2p Swarm handler.
    swarm: Swarm<Boxed<(PeerId, StreamMuxerBox), Error>, Behaviour<Substream<StreamMuxerBox>>>,
    /// This node's PeerId.
    local_peer_id: PeerId,
}
//Swarm<impl std::clone::Clone+libp2p_core::transport::Transport, behaviour::Behaviour<libp2p_core::muxing::SubstreamRef<std::sync::Arc<impl std::marker::Send+std::marker::Sync+libp2p_core::muxing::StreamMuxer>>>>

//swarm: Swarm<Boxed<(PeerId, StreamMuxerBox), IoError>, Behaviour<TMessage, Substream<StreamMuxerBox>>>,

impl Service {
    pub fn new(config: NetworkConfig, log: slog::Logger) -> Self {
        debug!(log, "Libp2p Service starting");

        let local_private_key = config.local_private_key;
        let local_peer_id = local_private_key.to_peer_id();
        debug!(log, "Local peer id: {:?}", local_peer_id);

        // Set up the transport
        let transport = build_transport(local_private_key);
        // Set up gossipsub routing
        let behaviour = Behaviour::new(local_peer_id.clone(), config.gs_config);
        // Set up Topology
        let topology = local_peer_id.clone();

        let swarm = Swarm::new(transport, behaviour, topology);

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
