//! A collection of variables that are accessible outside of the network thread itself.
use eth2_libp2p::{Enr, Multiaddr, PeerId};

pub struct NetworkGlobals {
    /// The current local ENR.
    pub local_enr: Option<Enr>,
    /// The local peer_id.
    pub peer_id: Option<PeerId>,
    /// Listening multiaddrs.
    pub listen_multiaddrs: Vec<Multiaddr>,
    /// Current number of connected libp2p peers.
    pub connected_peers: usize,
    /// The collection of currently connected peers.
    pub connected_peer_set: Vec<PeerId>,
}

impl NetworkGlobals {
    pub fn new() -> Self {
        NetworkGlobals {
            local_enr: None,
            peer_id: None,
            listen_multiaddrs: Vec::new(),
            connected_peers: 0,
            connected_peer_set: Vec::new(),
        }
    }
}
