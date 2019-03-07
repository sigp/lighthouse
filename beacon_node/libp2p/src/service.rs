use crate::NetworkConfig;
use libp2p::core::{muxing::StreamMuxer, nodes::Substream};
use libp2p::gossipsub::{Gossipsub, GossipsubConfig, GossipsubEvent};
use libp2p::{build_tcp_ws_secio_mplex_yamux, core, secio, Transport};
use libp2p::{core::swarm::NetworkBehaviour, PeerId, Swarm};
use slog::debug;
use std::error;

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service {
    /// The libp2p Swarm handler.
    swarm: String,
    /// This node's PeerId.
    local_peer_id: PeerId,
}

impl Service {
    pub fn new(config: NetworkConfig, log: slog::Logger) -> Self {
        debug!(log, "Libp2p Service starting");

        let local_private_key = config.local_private_key;
        let local_peer_id = local_private_key.to_peer_id();
        debug!(log, "Local peer id: {:?}", local_peer_id);

        // Set up the transport
        let transport = build_transport(local_private_key);
        // Set up gossipsub routing
        let behaviour = build_behaviour(local_peer_id, config.gs_config);
        // Set up Topology
        let topology = local_peer_id;

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
) -> impl Transport<
    Output = (
        PeerId,
        impl core::muxing::StreamMuxer<OutboundSubstream = impl Send, Substream = impl Send>
            + Send
            + Sync,
    ),
    Error = impl error::Error + Send,
    Listener = impl Send,
    Dial = impl Send,
    ListenerUpgrade = impl Send,
> + Clone {
    // TODO: The Wire protocol currently doesn't specify encryption and this will need to be customised
    // in the future.
    build_tcp_ws_secio_mplex_yamux(local_private_key)
}

/// Builds the network behaviour for the libp2p Swarm.
fn build_behaviour<TSubstream>(
    local_peer_id: PeerId,
    config: GossipsubConfig,
) -> impl NetworkBehaviour {
    // TODO: Add Kademlia/Peer discovery
    Gossipsub::new(local_peer_id, config)
}
