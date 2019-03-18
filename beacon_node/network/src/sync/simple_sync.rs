use crate::beacon_chain::BeaconChain;
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use types::{Epoch, Hash256, Slot};

/// Keeps track of syncing information for known connected peers.
pub struct PeerSyncInfo {
    latest_finalized_root: Hash256,
    latest_finalized_epoch: Epoch,
    best_root: Hash256,
    best_slot: Slot,
}

/// The current syncing state.
pub enum SyncState {
    Idle,
    Downloading,
    Stopped,
}

/// Simple Syncing protocol.
//TODO: Decide for HELLO messages whether its better to keep current in RAM or build on the fly
//when asked.
pub struct SimpleSync {
    known_peers: HashMap<PeerId, PeerSyncInfo>,
    state: SyncState,
    network_id: u8,
}

impl SimpleSync {
    pub fn new(beacon_chain: Arc<BeaconChain>) -> Self {
        SimpleSync {
            known_peers: HashMap::new(),
            state: SyncState::Idle,
            network_id: beacon_chain.get_spec().network_id,
        }
    }
}
