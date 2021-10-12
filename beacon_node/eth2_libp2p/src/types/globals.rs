//! A collection of variables that are accessible outside of the network thread itself.
use crate::peer_manager::PeerDB;
use crate::rpc::MetaData;
use crate::types::{BackFillState, SyncState};
use crate::Client;
use crate::EnrExt;
use crate::{Enr, GossipTopic, Multiaddr, PeerId};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use types::EthSpec;

/// Simple struct to maintain the synchronization mechanism of a RwLock but defining a non-clonable
/// data owner with write access.
pub struct Owner<T> {
    data: Arc<RwLock<T>>,
}

impl<T: Default> Default for Owner<T> {
    fn default() -> Self {
        Owner::new(T::default())
    }
}

/// Simple struct that uses the synchronization mechanisms of a RwLock but provides only read
/// access to the underlying data.
pub struct ReadOnly<T> {
    data: Arc<RwLock<T>>,
}

impl<T> Clone for ReadOnly<T> {
    fn clone(&self) -> Self {
        ReadOnly {
            data: self.data.clone(),
        }
    }
}

impl<T> Owner<T> {
    pub fn new(data: T) -> Owner<T> {
        Owner {
            data: Arc::new(RwLock::new(data)),
        }
    }

    pub fn read_access(&self) -> ReadOnly<T> {
        ReadOnly {
            data: self.data.clone(),
        }
    }

    pub fn read<'a>(&'a self) -> impl std::ops::Deref<Target = T> + 'a {
        self.data.read()
    }

    pub fn write<'a>(&'a self) -> impl std::ops::DerefMut<Target = T> + 'a {
        self.data.write()
    }
}

impl<T> ReadOnly<T> {
    pub fn read<'a>(&'a self) -> impl std::ops::Deref<Target = T> + 'a {
        self.data.read()
    }
}

/// Relevant information about the network.
// NOTE: this is intented to be read only.
pub struct NetworkGlobals<TSpec: EthSpec> {
    /// The current local ENR.
    pub(crate) local_enr: ReadOnly<Enr>,
    /// The local peer_id.
    /// TODO: remove?
    // pub peer_id: ReadOnly<PeerId>,
    /// Listening multiaddrs.
    pub(crate) listen_multiaddrs: ReadOnly<Vec<Multiaddr>>,
    /// The TCP port that the libp2p service is listening on
    pub(crate) listen_port_tcp: Arc<AtomicU16>,
    /// The UDP port that the discovery service is listening on
    pub(crate) listen_port_udp: Arc<AtomicU16>,
    /// The collection of known peers.
    pub(crate) peers: ReadOnly<PeerDB<TSpec>>,
    // The local meta data of our node.
    pub(crate) local_metadata: ReadOnly<MetaData<TSpec>>,
    /// The current gossipsub topic subscriptions.
    pub(crate) gossipsub_subscriptions: ReadOnly<HashSet<GossipTopic>>,
    /// The current sync status of the node.
    pub(crate) sync_state: ReadOnly<SyncState>,
    /// The current state of the backfill sync.
    pub(crate) backfill_state: ReadOnly<BackFillState>,
}

impl<TSpec: EthSpec> NetworkGlobals<TSpec> {
    /// Returns the local ENR from the underlying Discv5 behaviour that external peers may connect
    /// to.
    pub fn local_enr(&self) -> Enr {
        self.local_enr.read().clone()
    }

    /// Returns the local libp2p PeerID.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_enr.read().peer_id()
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

    /// Returns the number of libp2p connected peers with outbound-only connections.
    pub fn connected_outbound_only_peers(&self) -> usize {
        self.peers.read().connected_outbound_only_peers().count()
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

    /// Returns the current backfill state.
    pub fn backfill_state(&self) -> BackFillState {
        self.backfill_state.read().clone()
    }

    /// Returns a `Client` type if one is known for the `PeerId`.
    pub fn client(&self, peer_id: &PeerId) -> Client {
        self.peers
            .read()
            .peer_info(peer_id)
            .map(|info| info.client.clone())
            .unwrap_or_default()
    }
}
