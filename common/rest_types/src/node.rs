//! Collection of types for the /node HTTP
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use types::Slot;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
/// The current syncing status of the node.
pub struct SyncingStatus {
    /// The starting slot of sync.
    ///
    /// For a finalized sync, this is the start slot of the current finalized syncing
    /// chain.
    ///
    /// For head sync this is the last finalized slot.
    pub starting_slot: Slot,
    /// The current slot.
    pub current_slot: Slot,
    /// The highest known slot. For the current syncing chain.
    ///
    /// For a finalized sync, the target finalized slot.
    /// For head sync, this is the highest known slot of all head chains.
    pub highest_slot: Slot,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
/// The response for the /node/syncing HTTP GET.
pub struct SyncingResponse {
    /// Is the node syncing.
    pub is_syncing: bool,
    /// The current sync status.
    pub sync_status: SyncingStatus,
}
