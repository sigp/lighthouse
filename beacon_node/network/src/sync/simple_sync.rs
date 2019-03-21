use crate::beacon_chain::BeaconChain;
use crate::message_handler::NetworkContext;
use crate::service::NetworkMessage;
use crossbeam_channel::Sender;
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCRequest, RPCResponse};
use eth2_libp2p::PeerId;
use slog::{debug, o};
use std::collections::HashMap;
use std::sync::Arc;
use types::{Epoch, Hash256, Slot};

type NetworkSender = Sender<NetworkMessage>;

/// The number of slots that we can import blocks ahead of us, before going into full Sync mode.
const SLOT_IMPORT_TOLERANCE: u64 = 100;

/// Keeps track of syncing information for known connected peers.
#[derive(Clone, Copy)]
pub struct PeerSyncInfo {
    latest_finalized_root: Hash256,
    latest_finalized_epoch: Epoch,
    best_root: Hash256,
    best_slot: Slot,
}

impl PeerSyncInfo {
    fn is_on_chain(&self, chain: &Arc<BeaconChain>) -> bool {
        // TODO: make useful.
        true
    }

    fn has_higher_finalized_epoch(&self, chain: &Arc<BeaconChain>) -> bool {
        self.latest_finalized_epoch > chain.get_state().finalized_epoch
    }

    fn has_higher_best_slot(&self, chain: &Arc<BeaconChain>) -> bool {
        self.latest_finalized_epoch > chain.get_state().finalized_epoch
    }

    pub fn status(&self, chain: &Arc<BeaconChain>) -> PeerStatus {
        if self.has_higher_finalized_epoch(chain) {
            PeerStatus::HigherFinalizedEpoch
        } else if !self.is_on_chain(chain) {
            PeerStatus::HigherFinalizedEpoch
        } else if self.has_higher_best_slot(chain) {
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
            latest_finalized_root: hello.latest_finalized_root,
            latest_finalized_epoch: hello.latest_finalized_epoch,
            best_root: hello.best_root,
            best_slot: hello.best_slot,
        }
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
    /// The network id, for quick HELLO RPC message lookup.
    network_id: u8,
    /// The latest epoch of the syncing chain.
    latest_finalized_epoch: Epoch,
    /// The latest block of the syncing chain.
    latest_slot: Slot,
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
            network_id: beacon_chain.get_spec().network_id,
            latest_finalized_epoch: state.finalized_epoch,
            latest_slot: state.slot - 1, //TODO: Build latest block function into Beacon chain and correct this
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

        // network id must match
        if hello.network_id != self.network_id {
            debug!(self.log, "Bad network id. Peer: {:?}", peer_id);
            network.disconnect(peer_id);
            return;
        }

        let peer = PeerSyncInfo::from(hello);
        debug!(self.log, "Handshake successful. Peer: {:?}", peer_id);
        self.known_peers.insert(peer_id.clone(), peer);

        debug!(
            self.log,
            "Peer hello. Status: {:?}",
            peer.status(&self.chain)
        );

        match peer.status(&self.chain) {
            PeerStatus::OnDifferentChain => {
                debug!(self.log, "Peer is on different chain. Peer: {:?}", peer_id);

                network.disconnect(peer_id);
            }
            PeerStatus::HigherFinalizedEpoch => {
                let start_slot = peer.latest_finalized_epoch.start_slot(spec.slots_per_epoch);
                let required_slots = start_slot - self.chain.slot();

                self.request_block_roots(peer_id, start_slot, required_slots.as_u64(), network);
            }
            PeerStatus::HigherBestSlot => {
                let start_slot = peer.best_slot;
                let required_slots = start_slot - self.chain.slot();

                self.request_block_roots(peer_id, start_slot, required_slots.as_u64(), network);
            }
            PeerStatus::NotInteresting => {}
        }
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
            self.state = SyncState::Downloading;
        }

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
