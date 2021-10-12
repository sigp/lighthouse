use serde::{Deserialize, Serialize};
use types::Slot;

/// The current state of the node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncState {
    /// The node is performing a long-range (batch) sync over a finalized chain.
    /// In this state, parent lookups are disabled.
    SyncingFinalized { start_slot: Slot, target_slot: Slot },
    /// The node is performing a long-range (batch) sync over one or many head chains.
    /// In this state parent lookups are disabled.
    SyncingHead { start_slot: Slot, target_slot: Slot },
    /// The node is undertaking a backfill sync. This occurs when a user has specified a trusted
    /// state. The node first syncs "forward" by downloading blocks up to the current head as
    /// specified by its peers. Once completed, the node enters this sync state and attempts to
    /// download all required historical blocks to complete its chain.
    BackFillSyncing { completed: usize, remaining: usize },
    /// The node has completed syncing a finalized chain and is in the process of re-evaluating
    /// which sync state to progress to.
    SyncTransition,
    /// The node is up to date with all known peers and is connected to at least one
    /// fully synced peer. In this state, parent lookups are enabled.
    Synced,
    /// No useful peers are connected. Long-range sync's cannot proceed and we have no useful
    /// peers to download parents for. More peers need to be connected before we can proceed.
    Stalled,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
/// The state of the backfill sync.
pub enum BackFillState {
    /// The sync is partially completed and currently paused.
    Paused,
    /// We are currently backfilling.
    Syncing,
    /// A backfill sync has completed.
    Completed,
    /// A backfill sync is not required.
    NotRequired,
    /// Too many failed attempts at backfilling. Consider it failed.
    Failed,
}

impl PartialEq for SyncState {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (
                SyncState::SyncingFinalized { .. },
                SyncState::SyncingFinalized { .. }
            ) | (SyncState::SyncingHead { .. }, SyncState::SyncingHead { .. })
                | (SyncState::Synced, SyncState::Synced)
                | (SyncState::Stalled, SyncState::Stalled)
                | (SyncState::SyncTransition, SyncState::SyncTransition)
                | (
                    SyncState::BackFillSyncing { .. },
                    SyncState::BackFillSyncing { .. }
                )
        )
    }
}

impl SyncState {
    /// Returns a boolean indicating the node is currently performing a long-range sync.
    pub fn is_syncing(&self) -> bool {
        match self {
            SyncState::SyncingFinalized { .. } => true,
            SyncState::SyncingHead { .. } => true,
            SyncState::SyncTransition => true,
            // Backfill doesn't effect any logic, we consider this state, not syncing.
            SyncState::BackFillSyncing { .. } => false,
            SyncState::Synced => false,
            SyncState::Stalled => false,
        }
    }

    /// Returns true if the node is synced.
    ///
    /// NOTE: We consider the node synced if it is fetching old historical blocks.
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncState::Synced | SyncState::BackFillSyncing { .. })
    }
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncState::SyncingFinalized { .. } => write!(f, "Syncing Finalized Chain"),
            SyncState::SyncingHead { .. } => write!(f, "Syncing Head Chain"),
            SyncState::Synced { .. } => write!(f, "Synced"),
            SyncState::Stalled { .. } => write!(f, "Stalled"),
            SyncState::SyncTransition => write!(f, "Evaluating known peers"),
            SyncState::BackFillSyncing { .. } => write!(f, "Syncing Historical Blocks"),
        }
    }
}
