//NOTE: This should be removed in favour of the PeerManager PeerInfo, once built.
use crate::rpc::MetaData;
use types::{EthSpec, SubnetId};

/// Information about a given connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo<T: EthSpec> {
    /// The current syncing state of the peer. The state may be determined after it's initial
    /// connection.
    pub syncing_state: Option<PeerSyncingState>,
    /// The ENR subnet bitfield of the peer. This may be determined after it's initial
    /// connection.
    pub meta_data: Option<MetaData<T>>,
}

#[derive(Debug, Clone)]
pub enum PeerSyncingState {
    /// At the current state as our node.
    Synced,
    /// The peer is further ahead than our node and useful for block downloads.
    Ahead,
    /// Is behind our current head and not useful for block downloads.
    Behind,
}

impl<T: EthSpec> PeerInfo<T> {
    /// Creates a new PeerInfo, specifying it's
    pub fn new() -> Self {
        PeerInfo {
            syncing_state: None,
            meta_data: None,
        }
    }

    /// Returns if the peer is subscribed to a given `SubnetId`
    pub fn on_subnet(&self, subnet_id: SubnetId) -> bool {
        if let Some(meta_data) = &self.meta_data {
            return meta_data
                .attnets
                .get(*subnet_id as usize)
                .unwrap_or_else(|_| false);
        }
        false
    }
}
