use crate::{NetworkGlobals, PeerId};
use std::sync::Arc;
use std::time::Instant;
use types::EthSpec;

pub trait NetworkGlobalsWrapper {
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

pub struct LHNetworkGlobalsWrapper<E: EthSpec> {
    /// Storage of network globals to access the `PeerDB`.
    network_globals: Arc<NetworkGlobals<E>>,
}

impl<E: EthSpec> LHNetworkGlobalsWrapper<E> {
    pub fn new(network_globals: Arc<NetworkGlobals<E>>) -> Self {
        Self { network_globals }
    }

    /// Returns the number of libp2p connected peers with outbound-only connections.
    fn connected_outbound_only_peers(&self) -> usize {
        self.network_globals.connected_outbound_only_peers()
    }

    /// Returns the number of libp2p peers that are either connected or being dialed.
    fn connected_or_dialing_peers(&self) -> usize {
        self.network_globals.connected_or_dialing_peers()
    }

    /// Update min ttl of a peer.
    fn update_min_ttl(&self, peer_id: &PeerId, min_ttl: Instant) {
        self.network_globals
            .peers
            .write()
            .update_min_ttl(peer_id, min_ttl);
    }

    /// Returns true if the peer should be dialed. This checks the connection state and the
    /// score state and determines if the peer manager should dial this peer.
    fn should_dial(&self, peer_id: &PeerId) -> bool {
        self.network_globals.peers.read().should_dial(peer_id)
    }
}

impl<E: EthSpec> NetworkGlobalsWrapper for LHNetworkGlobalsWrapper<E> {
    /// Returns the number of libp2p connected peers with outbound-only connections.
    fn connected_outbound_only_peers(&self) -> usize {
        self.connected_outbound_only_peers()
    }

    /// Returns the number of libp2p peers that are either connected or being dialed.
    fn connected_or_dialing_peers(&self) -> usize {
        self.connected_or_dialing_peers()
    }

    /// Update min ttl of a peer.
    fn update_min_ttl(&self, peer_id: &PeerId, min_ttl: Instant) {
        self.update_min_ttl(peer_id, min_ttl)
    }

    /// Returns true if the peer should be dialed. This checks the connection state and the
    /// score state and determines if the peer manager should dial this peer.
    fn should_dial(&self, peer_id: &PeerId) -> bool {
        self.should_dial(peer_id)
    }
}
