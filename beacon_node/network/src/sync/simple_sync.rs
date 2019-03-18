use crate::beacon_chain::BeaconChain;
use libp2p::rpc::HelloMessage;
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
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain>,
    /// A mapping of Peers to their respective PeerSyncInfo.
    known_peers: HashMap<PeerId, PeerSyncInfo>,
    /// The current state of the syncing protocol.
    state: SyncState,
    /// The network id, for quick HELLO RPC message lookup.
    network_id: u8,
}

impl SimpleSync {
    pub fn new(beacon_chain: Arc<BeaconChain>) -> Self {
        SimpleSync {
            known_peers: HashMap::new(),
            state: SyncState::Idle,
            network_id: beacon_chain.get_spec().network_id,
            chain: beacon_chain,
        }
    }

    /// Generates our current state in the form of a HELLO RPC message.
    pub fn generate_hello(&self) -> HelloMessage {
        let state = &self.chain.get_state();
        //TODO: Paul to verify the logic of these fields.
        HelloMessage {
            network_id: self.network_id,
            latest_finalized_root: state.finalized_root.clone(),
            latest_finalized_epoch: state.finalized_epoch,
            best_root: state.latest_block_roots[0], // 0 or len of vec?
            best_slot: state.slot,
        }
    }
}
