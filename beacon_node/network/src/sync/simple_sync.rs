use crate::beacon_chain::BeaconChain;
use crate::message_handler::NetworkContext;
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCRequest, RPCResponse};
use eth2_libp2p::PeerId;
use slog::{debug, o};
use std::collections::HashMap;
use std::sync::Arc;
use types::{Epoch, Hash256, Slot};

/// The number of slots that we can import blocks ahead of us, before going into full Sync mode.
const SLOT_IMPORT_TOLERANCE: u64 = 100;

/// Keeps track of syncing information for known connected peers.
#[derive(Clone, Copy, Debug)]
pub struct PeerSyncInfo {
    network_id: u8,
    latest_finalized_root: Hash256,
    latest_finalized_epoch: Epoch,
    best_root: Hash256,
    best_slot: Slot,
}

impl PeerSyncInfo {
    fn is_on_same_chain(&self, other: Self) -> bool {
        self.network_id == other.network_id
    }

    fn has_higher_finalized_epoch_than(&self, other: Self) -> bool {
        self.latest_finalized_epoch > other.latest_finalized_epoch
    }

    fn has_higher_best_slot_than(&self, other: Self) -> bool {
        self.best_slot > other.best_slot
    }

    pub fn status_compared_to(&self, other: Self) -> PeerStatus {
        if self.has_higher_finalized_epoch_than(other) {
            PeerStatus::HigherFinalizedEpoch
        } else if !self.is_on_same_chain(other) {
            PeerStatus::OnDifferentChain
        } else if self.has_higher_best_slot_than(other) {
            PeerStatus::HigherBestSlot
        } else {
            PeerStatus::NotInteresting
        }
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum PeerStatus {
    OnDifferentChain,
    HigherFinalizedEpoch,
    HigherBestSlot,
    NotInteresting,
}

impl From<HelloMessage> for PeerSyncInfo {
    fn from(hello: HelloMessage) -> PeerSyncInfo {
        PeerSyncInfo {
            network_id: hello.network_id,
            latest_finalized_root: hello.latest_finalized_root,
            latest_finalized_epoch: hello.latest_finalized_epoch,
            best_root: hello.best_root,
            best_slot: hello.best_slot,
        }
    }
}

impl From<&Arc<BeaconChain>> for PeerSyncInfo {
    fn from(chain: &Arc<BeaconChain>) -> PeerSyncInfo {
        Self::from(chain.hello_message())
    }
}

/// The current syncing state.
#[derive(PartialEq)]
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
    /// Sync logger.
    log: slog::Logger,
}

impl SimpleSync {
    pub fn new(beacon_chain: Arc<BeaconChain>, log: &slog::Logger) -> Self {
        let state = beacon_chain.get_state();
        let sync_logger = log.new(o!("Service"=> "Sync"));
        SimpleSync {
            chain: beacon_chain.clone(),
            known_peers: HashMap::new(),
            state: SyncState::Idle,
            log: sync_logger,
        }
    }

    pub fn on_connect(&self, peer_id: PeerId, network: &mut NetworkContext) {
        network.send_rpc_request(peer_id, RPCRequest::Hello(self.chain.hello_message()));
    }

    pub fn on_hello_request(
        &mut self,
        peer_id: PeerId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        network.send_rpc_response(
            peer_id.clone(),
            RPCResponse::Hello(self.chain.hello_message()),
        );
        self.on_hello(peer_id, hello, network);
    }

    pub fn on_hello(&mut self, peer_id: PeerId, hello: HelloMessage, network: &mut NetworkContext) {
        let spec = self.chain.get_spec();

        let remote = PeerSyncInfo::from(hello);
        let local = PeerSyncInfo::from(&self.chain);
        let remote_status = remote.status_compared_to(local);

        // network id must match
        if remote_status != PeerStatus::OnDifferentChain {
            debug!(self.log, "Handshake successful. Peer: {:?}", peer_id);
            self.known_peers.insert(peer_id.clone(), remote);
        }

        match remote_status {
            PeerStatus::OnDifferentChain => {
                debug!(self.log, "Peer is on different chain. Peer: {:?}", peer_id);

                network.disconnect(peer_id);
            }
            PeerStatus::HigherFinalizedEpoch => {
                let start_slot = remote
                    .latest_finalized_epoch
                    .start_slot(spec.slots_per_epoch);
                let required_slots = start_slot - local.best_slot;

                self.request_block_roots(peer_id, start_slot, required_slots.as_u64(), network);
            }
            PeerStatus::HigherBestSlot => {
                let required_slots = remote.best_slot - local.best_slot;

                self.request_block_roots(
                    peer_id,
                    local.best_slot,
                    required_slots.as_u64(),
                    network,
                );
            }
            PeerStatus::NotInteresting => {}
        }
    }

    pub fn on_beacon_block_roots_response(
        &mut self,
        peer_id: PeerId,
        reponse: BeaconBlockRootsResponse,
        network: &mut NetworkContext,
    ) {
        //
    }

    fn request_block_roots(
        &mut self,
        peer_id: PeerId,
        start_slot: Slot,
        count: u64,
        network: &mut NetworkContext,
    ) {
        // Potentially set state to sync.
        if self.state == SyncState::Idle && count > SLOT_IMPORT_TOLERANCE {
            debug!(self.log, "Entering downloading sync state.");
            self.state = SyncState::Downloading;
        }

        debug!(self.log, "Requesting {} blocks from {:?}.", count, &peer_id);

        // TODO: handle count > max count.
        network.send_rpc_request(
            peer_id.clone(),
            RPCRequest::BeaconBlockRoots(BeaconBlockRootsRequest { start_slot, count }),
        );
    }

    /// Generates our current state in the form of a HELLO RPC message.
    pub fn generate_hello(&self) -> HelloMessage {
        self.chain.hello_message()
    }
}
