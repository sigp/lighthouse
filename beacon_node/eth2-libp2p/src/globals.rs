//! A collection of variables that are accessible outside of the network thread itself.
use crate::{Enr, Multiaddr, PeerId};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::atomic::AtomicUsize;

pub struct NetworkGlobals {
    /// The current local ENR.
    pub local_enr: RwLock<Option<Enr>>,
    /// The local peer_id.
    pub peer_id: RwLock<PeerId>,
    /// Listening multiaddrs.
    pub listen_multiaddrs: RwLock<Vec<Multiaddr>>,
    /// Current number of connected libp2p peers.
    pub connected_peers: AtomicUsize,
    /// The collection of currently connected peers.
    pub connected_peer_set: RwLock<HashSet<PeerId>>,
}

impl NetworkGlobals {
    pub fn new(peer_id: PeerId) -> Self {
        NetworkGlobals {
            local_enr: RwLock::new(None),
            peer_id: RwLock::new(peer_id),
            listen_multiaddrs: RwLock::new(Vec::new()),
            connected_peers: AtomicUsize::new(0),
            connected_peer_set: RwLock::new(HashSet::new()),
        }
    }
}
