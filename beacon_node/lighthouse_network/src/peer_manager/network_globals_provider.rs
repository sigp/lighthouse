use crate::{NetworkGlobals, PeerId};
use std::sync::Arc;
use std::time::Instant;
use types::EthSpec;

pub trait NetworkGlobalsProvider {
    /// Returns the number of libp2p connected peers with outbound-only connections.
    fn connected_outbound_only_peers(&self) -> usize;

    /// Returns the number of libp2p peers that are either connected or being dialed.
    fn connected_or_dialing_peers(&self) -> usize;

    /// Update min ttl of a peer.
    fn update_min_ttl(&self, peer_id: &PeerId, min_ttl: Instant);

    /// Returns true if the peer should be dialed. This checks the connection state and the
    /// score state and determines if the peer manager should dial this peer.
    fn should_dial(&self, peer_id: &PeerId) -> bool;
}

impl<E: EthSpec> NetworkGlobalsProvider for Arc<NetworkGlobals<E>> {
    fn connected_outbound_only_peers(&self) -> usize {
        self.as_ref().connected_outbound_only_peers()
    }

    fn connected_or_dialing_peers(&self) -> usize {
        self.as_ref().connected_or_dialing_peers()
    }

    fn update_min_ttl(&self, peer_id: &PeerId, min_ttl: Instant) {
        self.peers.write().update_min_ttl(peer_id, min_ttl)
    }

    fn should_dial(&self, peer_id: &PeerId) -> bool {
        self.peers.read().should_dial(peer_id)
    }
}
