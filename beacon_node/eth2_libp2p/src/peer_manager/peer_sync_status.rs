//! Handles individual sync status for peers.

use serde::Serialize;
use types::{Epoch, Hash256, Slot};

#[derive(Clone, Debug, Serialize)]
/// The current sync status of the peer.
pub enum PeerSyncStatus {
    /// At the current state as our node or ahead of us.
    Synced { info: SyncInfo },
    /// The peer has greater knowledge about the canonical chain than we do.
    Advanced { info: SyncInfo },
    /// Is behind our current head and not useful for block downloads.
    Behind { info: SyncInfo },
    /// Not currently known as a STATUS handshake has not occurred.
    Unknown,
}

/// This is stored inside the PeerSyncStatus and is very similar to `PeerSyncInfo` in the
/// `Network` crate.
#[derive(Clone, Debug, Serialize)]
pub struct SyncInfo {
    pub status_head_slot: Slot,
    pub status_head_root: Hash256,
    pub status_finalized_epoch: Epoch,
    pub status_finalized_root: Hash256,
}

impl PeerSyncStatus {
    /// Returns true if the peer has advanced knowledge of the chain.
    pub fn is_advanced(&self) -> bool {
        match self {
            PeerSyncStatus::Advanced { .. } => true,
            _ => false,
        }
    }

    /// Returns true if the peer is up to date with the current chain.
    pub fn is_synced(&self) -> bool {
        match self {
            PeerSyncStatus::Synced { .. } => true,
            _ => false,
        }
    }

    /// Returns true if the peer is behind the current chain.
    pub fn is_behind(&self) -> bool {
        match self {
            PeerSyncStatus::Behind { .. } => true,
            _ => false,
        }
    }

    /// Updates the sync state given a fully synced peer.
    /// Returns true if the state has changed.
    pub fn update_synced(&mut self, info: SyncInfo) -> bool {
        let new_state = PeerSyncStatus::Synced { info };

        match self {
            PeerSyncStatus::Synced { .. } | PeerSyncStatus::Unknown => {
                *self = new_state;
                false // state was not updated
            }
            _ => {
                *self = new_state;
                true
            }
        }
    }

    /// Updates the sync state given a peer that is further ahead in the chain than us.
    /// Returns true if the state has changed.
    pub fn update_advanced(&mut self, info: SyncInfo) -> bool {
        let new_state = PeerSyncStatus::Advanced { info };

        match self {
            PeerSyncStatus::Advanced { .. } | PeerSyncStatus::Unknown => {
                *self = new_state;
                false // state was not updated
            }
            _ => {
                *self = new_state;
                true
            }
        }
    }

    /// Updates the sync state given a peer that is behind us in the chain.
    /// Returns true if the state has changed.
    pub fn update_behind(&mut self, info: SyncInfo) -> bool {
        let new_state = PeerSyncStatus::Behind { info };

        match self {
            PeerSyncStatus::Behind { .. } | PeerSyncStatus::Unknown => {
                *self = new_state;
                false // state was not updated
            }
            _ => {
                *self = new_state;
                true
            }
        }
    }
}
