use std::collections::HashMap;
use types::{Slot, H256};

/// Keeps track of syncing information for known connected peers.
pub struct PeerSyncInfo {
    best_slot: Slot,
    best_slot_hash: H256,
}

/// The current syncing state.
pub enum SyncState {
    Idle,
    Downloading,
    Stopped,
}

/// Simple Syncing protocol.
pub struct SimpleSync {
    genesis_hash: H256,
    known_peers: HashMap<PeerId, PeerSyncInfo>,
    state: SyncState,
}
