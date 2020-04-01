//! A collection of variables that are accessible outside of the network thread itself.
use crate::{Enr, GossipTopic, Multiaddr, PeerId, PeerInfo};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU16, Ordering};
use types::EthSpec;

pub struct NetworkGlobals<TSpec: EthSpec> {
    /// The current local ENR.
    pub local_enr: RwLock<Option<Enr>>,
    /// The local peer_id.
    pub peer_id: RwLock<PeerId>,
    /// Listening multiaddrs.
    pub listen_multiaddrs: RwLock<Vec<Multiaddr>>,
    /// The tcp port that the libp2p service is listening on
    pub listen_port_tcp: AtomicU16,
    /// The udp port that the discovery service is listening on
    pub listen_port_udp: AtomicU16,
    /// The collection of currently connected peers.
    pub connected_peer_set: RwLock<HashMap<PeerId, PeerInfo<TSpec>>>,
    /// The current gossipsub topic subscriptions.
    pub gossipsub_subscriptions: RwLock<HashSet<GossipTopic>>,
}

impl<TSpec: EthSpec> NetworkGlobals<TSpec> {
    pub fn new(peer_id: PeerId, tcp_port: u16, udp_port: u16) -> Self {
        NetworkGlobals {
            local_enr: RwLock::new(None),
            peer_id: RwLock::new(peer_id),
            listen_multiaddrs: RwLock::new(Vec::new()),
            listen_port_tcp: AtomicU16::new(tcp_port),
            listen_port_udp: AtomicU16::new(udp_port),
            connected_peer_set: RwLock::new(HashMap::new()),
            gossipsub_subscriptions: RwLock::new(HashSet::new()),
        }
    }

    /// Returns the local ENR from the underlying Discv5 behaviour that external peers may connect
    /// to.
    pub fn local_enr(&self) -> Option<Enr> {
        self.local_enr.read().clone()
    }

    /// Returns the local libp2p PeerID.
    pub fn local_peer_id(&self) -> PeerId {
        self.peer_id.read().clone()
    }

    /// Returns the list of `Multiaddr` that the underlying libp2p instance is listening on.
    pub fn listen_multiaddrs(&self) -> Vec<Multiaddr> {
        self.listen_multiaddrs.read().clone()
    }

    /// Returns the libp2p TCP port that this node has been configured to listen on.
    pub fn listen_port_tcp(&self) -> u16 {
        self.listen_port_tcp.load(Ordering::Relaxed)
    }

    /// Returns the UDP discovery port that this node has been configured to listen on.
    pub fn listen_port_udp(&self) -> u16 {
        self.listen_port_udp.load(Ordering::Relaxed)
    }

    /// Returns the number of libp2p connected peers.
    pub fn connected_peers(&self) -> usize {
        self.connected_peer_set.read().len()
    }
}
