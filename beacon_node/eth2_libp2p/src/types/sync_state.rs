use serde::{Deserialize, Serialize};
use types::{Hash256, Slot};

/// The current state of the node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncState {
    /// The node is performing a long-range (batch) sync over a finalized chain.
    /// In this state, parent lookups are disabled.
    SyncingFinalized {
        start_slot: Slot,
        head_slot: Slot,
        head_root: Hash256,
    },
    /// The node is performing a long-range (batch) sync over one or many head chains.
    /// In this state parent lookups are disabled.
    SyncingHead { start_slot: Slot, head_slot: Slot },
    /// The node is up to date with all known peers and is connected to at least one
    /// fully synced peer. In this state, parent lookups are enabled.
    Synced,
    /// No useful peers are connected. Long-range sync's cannot proceed and we have no useful
    /// peers to download parents for. More peers need to be connected before we can proceed.
    Stalled,
}

impl PartialEq for SyncState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SyncState::SyncingFinalized { .. }, SyncState::SyncingFinalized { .. }) => true,
            (SyncState::SyncingHead { .. }, SyncState::SyncingHead { .. }) => true,
            (SyncState::Synced, SyncState::Synced) => true,
            (SyncState::Stalled, SyncState::Stalled) => true,
            _ => false,
        }
    }
}

impl SyncState {
    /// Returns a boolean indicating the node is currently performing a long-range sync.
    pub fn is_syncing(&self) -> bool {
        match self {
            SyncState::SyncingFinalized { .. } => true,
            SyncState::SyncingHead { .. } => true,
            SyncState::Synced => false,
            SyncState::Stalled => false,
        }
    }

    /// Returns true if the node is synced.
    pub fn is_synced(&self) -> bool {
        match self {
            SyncState::Synced => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncState::SyncingFinalized { .. } => write!(f, "Syncing Finalized Chain"),
            SyncState::SyncingHead { .. } => write!(f, "Syncing Head Chain"),
            SyncState::Synced { .. } => write!(f, "Synced"),
            SyncState::Stalled { .. } => write!(f, "Stalled"),
        }
    }
}
