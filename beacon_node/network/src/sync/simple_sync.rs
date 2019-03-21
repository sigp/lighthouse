use crate::beacon_chain::BeaconChain;
use crate::message_handler::{MessageHandler, NetworkContext};
use crate::service::NetworkMessage;
use crossbeam_channel::Sender;
use libp2p::rpc::{HelloMessage, RPCMethod, RPCRequest, RPCResponse};
use libp2p::PeerId;
use slog::{debug, o};
use std::collections::HashMap;
use std::sync::Arc;
use types::{Epoch, Hash256, Slot};

type NetworkSender = Sender<NetworkMessage>;

/// The number of slots that we can import blocks ahead of us, before going into full Sync mode.
const SLOT_IMPORT_TOLERANCE: u64 = 100;

/// Keeps track of syncing information for known connected peers.
pub struct PeerSyncInfo {
    latest_finalized_root: Hash256,
    latest_finalized_epoch: Epoch,
    best_root: Hash256,
    best_slot: Slot,
}

impl PeerSyncInfo {
    pub fn is_on_chain(&self, chain: &Arc<BeaconChain>) -> bool {
        // TODO: make useful.
        true
    }

    pub fn has_higher_finalized_epoch(&self, chain: &Arc<BeaconChain>) -> bool {
        self.latest_finalized_epoch > chain.get_state().finalized_epoch
    }

    pub fn has_higher_best_slot(&self, chain: &Arc<BeaconChain>) -> bool {
        self.latest_finalized_epoch > chain.get_state().finalized_epoch
    }
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

    pub fn on_connect(&self, peer_id: &PeerId, network: &mut NetworkContext) {
        network.send_rpc_request(
            peer_id.clone(),
            RPCRequest::Hello(self.chain.hello_message()),
        );
    }

    pub fn on_hello_request(
        &self,
        peer_id: &PeerId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        network.send_rpc_response(
            peer_id.clone(),
            RPCResponse::Hello(self.chain.hello_message()),
        );
        self.on_hello(peer_id, hello, network);
    }

    pub fn on_hello(&self, peer_id: &PeerId, hello: HelloMessage, network: &mut NetworkContext) {
        // network id must match
        if hello.network_id != self.network_id {
            debug!(self.log, "Bad network id. Peer: {:?}", peer_id);
            return;
        }

        let peer = PeerSyncInfo::from(hello);

        /*
        if peer.has_higher_finalized_epoch(&self.chain) {
            // we need blocks
            let peer_slot = peer.latest_finalized_epoch.start_slot(spec.slots_per_epoch);
            let our_slot = self.chain.finalized_epoch();
            let required_slots = peer_slot - our_slot;
        } else {
            if !peer.is_on_chain(&self.chain) {
                return (true, responses);
            }
            //
        }
        */

        /*
        // compare latest epoch and finalized root to see if they exist in our chain
        if peer_info.latest_finalized_epoch <= self.latest_finalized_epoch {
            // ensure their finalized root is in our chain
            // TODO: Get the finalized root at hello_message.latest_epoch and ensure they match
            //if (hello_message.latest_finalized_root == self.chain.get_state() {
            //    return false;
            //    }
        }

        // the client is valid, add it to our list of known_peers and request sync if required
        // update peer list if peer already exists
        let peer_info = PeerSyncInfo::from(hello);

        debug!(self.log, "Handshake successful. Peer: {:?}", peer_id);
        self.known_peers.insert(peer_id, peer_info);

        // set state to sync
        if self.state == SyncState::Idle
            && hello_message.best_slot > self.latest_slot + SLOT_IMPORT_TOLERANCE
        {
            self.state = SyncState::Downloading;
            //TODO: Start requesting blocks from known peers. Ideally in batches
        }

        true
        */
    }

    /// Generates our current state in the form of a HELLO RPC message.
    pub fn generate_hello(&self) -> HelloMessage {
        self.chain.hello_message()
    }

    pub fn validate_peer(&mut self, peer_id: PeerId, hello_message: HelloMessage) -> bool {
        // network id must match
        if hello_message.network_id != self.network_id {
            return false;
        }
        // compare latest epoch and finalized root to see if they exist in our chain
        if hello_message.latest_finalized_epoch <= self.latest_finalized_epoch {
            // ensure their finalized root is in our chain
            // TODO: Get the finalized root at hello_message.latest_epoch and ensure they match
            //if (hello_message.latest_finalized_root == self.chain.get_state() {
            //    return false;
            //    }
        }

        // the client is valid, add it to our list of known_peers and request sync if required
        // update peer list if peer already exists
        let peer_info = PeerSyncInfo {
            latest_finalized_root: hello_message.latest_finalized_root,
            latest_finalized_epoch: hello_message.latest_finalized_epoch,
            best_root: hello_message.best_root,
            best_slot: hello_message.best_slot,
        };

        debug!(self.log, "Handshake successful. Peer: {:?}", peer_id);
        self.known_peers.insert(peer_id, peer_info);

        // set state to sync
        if self.state == SyncState::Idle
            && hello_message.best_slot > self.latest_slot + SLOT_IMPORT_TOLERANCE
        {
            self.state = SyncState::Downloading;
            //TODO: Start requesting blocks from known peers. Ideally in batches
        }

        true
    }
}
