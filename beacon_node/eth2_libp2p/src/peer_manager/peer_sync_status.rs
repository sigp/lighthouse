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
    /// This peer is in an incompatible network.
    IrrelevantPeer,
    /// Not currently known as a STATUS handshake has not occurred.
    Unknown,
}

/// A relevant peer's sync information.
#[derive(Clone, Debug, Serialize)]
pub struct SyncInfo {
    pub head_slot: Slot,
    pub head_root: Hash256,
    pub finalized_epoch: Epoch,
    pub finalized_root: Hash256,
}

impl std::cmp::PartialEq for PeerSyncStatus {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (PeerSyncStatus::Synced { .. }, PeerSyncStatus::Synced { .. })
                | (
                    PeerSyncStatus::Advanced { .. },
                    PeerSyncStatus::Advanced { .. }
                )
                | (PeerSyncStatus::Behind { .. }, PeerSyncStatus::Behind { .. })
                | (
                    PeerSyncStatus::IrrelevantPeer,
                    PeerSyncStatus::IrrelevantPeer
                )
                | (PeerSyncStatus::Unknown, PeerSyncStatus::Unknown)
        )
    }
}

impl PeerSyncStatus {
    /// Returns true if the peer has advanced knowledge of the chain.
    pub fn is_advanced(&self) -> bool {
        matches!(self, PeerSyncStatus::Advanced { .. })
    }

    /// Returns true if the peer is up to date with the current chain.
    pub fn is_synced(&self) -> bool {
        matches!(self, PeerSyncStatus::Synced { .. })
    }

    /// Returns true if the peer is behind the current chain.
    pub fn is_behind(&self) -> bool {
        matches!(self, PeerSyncStatus::Behind { .. })
    }

    pub fn update(&mut self, new_state: PeerSyncStatus) -> bool {
        if *self == new_state {
            *self = new_state;
            false // state was not updated
        } else {
            *self = new_state;
            true
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PeerSyncStatus::Advanced { .. } => "Advanced",
            PeerSyncStatus::Behind { .. } => "Behind",
            PeerSyncStatus::Synced { .. } => "Synced",
            PeerSyncStatus::Unknown => "Unknown",
            PeerSyncStatus::IrrelevantPeer => "Irrelevant",
        }
    }
}

impl std::fmt::Display for PeerSyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
