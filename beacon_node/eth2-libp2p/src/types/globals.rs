//! A collection of variables that are accessible outside of the network thread itself.
use crate::peer_manager::PeerDB;
use crate::rpc::methods::MetaData;
use crate::types::SyncState;
use crate::Client;
use crate::EnrExt;
use crate::{discovery::enr::Eth2Enr, Enr, GossipTopic, Multiaddr, PeerId};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU16, Ordering};
use types::EthSpec;

pub struct NetworkGlobals<TSpec: EthSpec> {
    /// The current local ENR.
    pub local_enr: RwLock<Enr>,
    /// The current node's meta-data.
    pub meta_data: RwLock<MetaData<TSpec>>,
    /// The local peer_id.
    pub peer_id: RwLock<PeerId>,
    /// Listening multiaddrs.
    pub listen_multiaddrs: RwLock<Vec<Multiaddr>>,
    /// The TCP port that the libp2p service is listening on
    pub listen_port_tcp: AtomicU16,
    /// The UDP port that the discovery service is listening on
    pub listen_port_udp: AtomicU16,
    /// The collection of known peers.
    pub peers: RwLock<PeerDB<TSpec>>,
    /// The current gossipsub topic subscriptions.
    pub gossipsub_subscriptions: RwLock<HashSet<GossipTopic>>,
    /// The current sync status of the node.
    pub sync_state: RwLock<SyncState>,
}

impl<TSpec: EthSpec> NetworkGlobals<TSpec> {
    pub fn new(enr: Enr, tcp_port: u16, udp_port: u16, log: &slog::Logger) -> Self {
        // set up the local meta data of the node
        let meta_data = RwLock::new(MetaData {
            seq_number: 0,
            attnets: enr
                .bitfield::<TSpec>()
                .expect("Local ENR must have a bitfield specified"),
        });

        NetworkGlobals {
            local_enr: RwLock::new(enr.clone()),
            meta_data,
            peer_id: RwLock::new(enr.peer_id()),
            listen_multiaddrs: RwLock::new(Vec::new()),
            listen_port_tcp: AtomicU16::new(tcp_port),
            listen_port_udp: AtomicU16::new(udp_port),
            peers: RwLock::new(PeerDB::new(log)),
            gossipsub_subscriptions: RwLock::new(HashSet::new()),
            sync_state: RwLock::new(SyncState::Stalled),
        }
    }

    /// Returns the local ENR from the underlying Discv5 behaviour that external peers may connect
    /// to.
    pub fn local_enr(&self) -> Enr {
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
        self.peers.read().connected_peer_ids().count()
    }

    /// Returns the number of libp2p peers that are either connected or being dialed.
    pub fn connected_or_dialing_peers(&self) -> usize {
        self.peers.read().connected_or_dialing_peers().count()
    }

    /// Returns in the node is syncing.
    pub fn is_syncing(&self) -> bool {
        self.sync_state.read().is_syncing()
    }

    /// Returns the current sync state of the peer.
    pub fn sync_state(&self) -> SyncState {
        self.sync_state.read().clone()
    }

    /// Returns a `Client` type if one is known for the `PeerId`.
    pub fn client(&self, peer_id: &PeerId) -> Client {
        self.peers
            .read()
            .peer_info(peer_id)
            .map(|info| info.client.clone())
            .unwrap_or_default()
    }

    /// Updates the syncing state of the node.
    ///
    /// If there is a new state, the old state and the new states are returned.
    pub fn update_sync_state(&self) -> Option<(SyncState, SyncState)> {
        let mut result = None;
        // if we are in a range sync, nothing changes. Range sync will update this.
        if !self.is_syncing() {
            let new_state = self
                .peers
                .read()
                .synced_peers()
                .next()
                .map(|_| SyncState::Synced)
                .unwrap_or_else(|| SyncState::Stalled);

            let mut peer_state = self.sync_state.write();
            if new_state != *peer_state {
                result = Some((peer_state.clone(), new_state.clone()));
            }
            *peer_state = new_state;
        }
        result
    }
}
