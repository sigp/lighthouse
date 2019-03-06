use crate::NetworkConfig;
use libp2p::gossipsub::GossipsubEvent;
use libp2p::PeerId;
use libp2p::{build_tcp_ws_secio_mplex_yamux, core, secio, Transport};
use slog::debug;
use std::error;

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service {
    /// This node's PeerId.
    peer_id: PeerId,
}

impl Service {
    pub fn new(config: NetworkConfig, log: slog::Logger) -> Self {
        debug!(log, "Libp2p Service starting");

        let local_private_key = config.local_private_key;
        let peer_id = local_private_key.to_peer_id();
        debug!(log, "Local peer id: {:?}", peer_id);

        // Set up the transport
        let transport = build_transport(local_private_key);

        //let transport = libp2p::

        Service { peer_id }
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
