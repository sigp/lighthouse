//! Handles individual sync status for peers.

use serde::Serialize;
use types::{Epoch, Hash256, Slot};

#[derive(Clone, Debug, Serialize)]
/// The current sync status of the peer.
pub enum SyncStatus {
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

impl std::cmp::PartialEq for SyncStatus {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (SyncStatus::Synced { .. }, SyncStatus::Synced { .. })
                | (SyncStatus::Advanced { .. }, SyncStatus::Advanced { .. })
                | (SyncStatus::Behind { .. }, SyncStatus::Behind { .. })
                | (SyncStatus::IrrelevantPeer, SyncStatus::IrrelevantPeer)
                | (SyncStatus::Unknown, SyncStatus::Unknown)
        )
    }
}

impl SyncStatus {
    /// Returns true if the peer has advanced knowledge of the chain.
    pub fn is_advanced(&self) -> bool {
        matches!(self, SyncStatus::Advanced { .. })
    }

    /// Returns true if the peer is up to date with the current chain.
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncStatus::Synced { .. })
    }

    /// Returns true if the peer is behind the current chain.
    pub fn is_behind(&self) -> bool {
        matches!(self, SyncStatus::Behind { .. })
    }

    /// Updates the peer's sync status, returning whether the status transitioned.
    ///
    /// E.g. returns `true` if the state changed from `Synced` to `Advanced`, but not if
    /// the status remained `Synced` with different `SyncInfo` within.
    pub fn update(&mut self, new_state: SyncStatus) -> bool {
        let changed_status = *self != new_state;
        *self = new_state;
        changed_status
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SyncStatus::Advanced { .. } => "Advanced",
            SyncStatus::Behind { .. } => "Behind",
            SyncStatus::Synced { .. } => "Synced",
            SyncStatus::Unknown => "Unknown",
            SyncStatus::IrrelevantPeer => "Irrelevant",
        }
    }
}

impl std::fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
