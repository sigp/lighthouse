use crate::beacon_chain::BeaconChain;
use crate::message_handler::NetworkContext;
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCRequest, RPCResponse};
use eth2_libp2p::PeerId;
use slog::{debug, error, o, warn};
use ssz::TreeHash;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use types::{BeaconBlockHeader, Epoch, Hash256, Slot};

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
    _Stopped,
}

/// Simple Syncing protocol.
//TODO: Decide for HELLO messages whether its better to keep current in RAM or build on the fly
//when asked.
pub struct SimpleSync {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain>,
    /// A mapping of Peers to their respective PeerSyncInfo.
    known_peers: HashMap<PeerId, PeerSyncInfo>,
    /// A queue to allow importing of blocks
    import_queue: ImportQueue,
    /// The current state of the syncing protocol.
    state: SyncState,
    /// Sync logger.
    log: slog::Logger,
}

impl SimpleSync {
    pub fn new(beacon_chain: Arc<BeaconChain>, log: &slog::Logger) -> Self {
        let sync_logger = log.new(o!("Service"=> "Sync"));
        let import_queue = ImportQueue::new(beacon_chain.clone(), log.clone());
        SimpleSync {
            chain: beacon_chain.clone(),
            known_peers: HashMap::new(),
            import_queue,
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

                self.request_block_roots(
                    peer_id,
                    BeaconBlockRootsRequest {
                        start_slot,
                        count: required_slots.into(),
                    },
                    network,
                );
            }
            PeerStatus::HigherBestSlot => {
                let required_slots = remote.best_slot - local.best_slot;

                self.request_block_roots(
                    peer_id,
                    BeaconBlockRootsRequest {
                        start_slot: local.best_slot + 1,
                        count: required_slots.into(),
                    },
                    network,
                );
            }
            PeerStatus::NotInteresting => {}
        }
    }

    pub fn on_beacon_block_roots_response(
        &mut self,
        peer_id: PeerId,
        response: BeaconBlockRootsResponse,
        network: &mut NetworkContext,
    ) {
        if response.roots.is_empty() {
            warn!(
                self.log,
                "Peer returned empty block roots response. PeerId: {:?}", peer_id
            );
            return;
        }

        let new_root_index = self.import_queue.first_new_root(&response.roots);

        // If a new block root is found, request it and all the headers following it.
        //
        // We make an assumption here that if we don't know a block then we don't know of all
        // it's parents. This might not be the case if syncing becomes more sophisticated.
        if let Some(i) = new_root_index {
            let new = &response.roots[i];

            self.request_block_headers(
                peer_id,
                BeaconBlockHeadersRequest {
                    start_root: new.block_root,
                    start_slot: new.slot,
                    max_headers: (response.roots.len() - i) as u64,
                    skip_slots: 0,
                },
                network,
            )
        }
    }

    pub fn on_beacon_block_headers_response(
        &mut self,
        peer_id: PeerId,
        response: BeaconBlockHeadersResponse,
        network: &mut NetworkContext,
    ) {
        if response.headers.is_empty() {
            warn!(
                self.log,
                "Peer returned empty block headers response. PeerId: {:?}", peer_id
            );
            return;
        }

        let block_roots = self.import_queue.enqueue_headers(response.headers);

        if !block_roots.is_empty() {
            self.request_block_bodies(peer_id, BeaconBlockBodiesRequest { block_roots }, network);
        }
    }

    fn request_block_roots(
        &mut self,
        peer_id: PeerId,
        request: BeaconBlockRootsRequest,
        network: &mut NetworkContext,
    ) {
        // Potentially set state to sync.
        if self.state == SyncState::Idle && request.count > SLOT_IMPORT_TOLERANCE {
            debug!(self.log, "Entering downloading sync state.");
            self.state = SyncState::Downloading;
        }

        debug!(
            self.log,
            "Requesting {} block roots from {:?}.", request.count, &peer_id
        );

        // TODO: handle count > max count.
        network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlockRoots(request));
    }

    fn request_block_headers(
        &mut self,
        peer_id: PeerId,
        request: BeaconBlockHeadersRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "Requesting {} headers from {:?}.", request.max_headers, &peer_id
        );

        network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlockHeaders(request));
    }

    fn request_block_bodies(
        &mut self,
        peer_id: PeerId,
        request: BeaconBlockBodiesRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "Requesting {} bodies from {:?}.",
            request.block_roots.len(),
            &peer_id
        );

        network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlockBodies(request));
    }

    /// Generates our current state in the form of a HELLO RPC message.
    pub fn generate_hello(&self) -> HelloMessage {
        self.chain.hello_message()
    }
}

pub struct ImportQueue {
    /// BeaconChain
    pub chain: Arc<BeaconChain>,
    /// Partially imported blocks, keyed by the root of `BeaconBlockBody`.
    pub partials: HashMap<Hash256, PartialBeaconBlock>,
    /// Logging
    log: slog::Logger,
}

impl ImportQueue {
    pub fn new(chain: Arc<BeaconChain>, log: slog::Logger) -> Self {
        Self {
            chain,
            partials: HashMap::new(),
            log,
        }
    }

    fn is_new_block(&self, block_root: &Hash256) -> bool {
        self.chain
            .is_new_block_root(&block_root)
            .unwrap_or_else(|_| {
                error!(self.log, "Unable to determine if block is new.");
                true
            })
    }

    /// Returns the index of the first new root in the list of block roots.
    pub fn first_new_root(&mut self, roots: &[BlockRootSlot]) -> Option<usize> {
        for root in roots {
            println!("root {}", root.block_root);
        }
        roots
            .iter()
            .position(|brs| self.is_new_block(&brs.block_root))
    }

    /// Adds the `headers` to the `partials` queue. Returns a list of `Hash256` block roots for
    /// which we should use to request `BeaconBlockBodies`.
    ///
    /// If a `header` is not in the queue and has not been processed by the chain it is added to
    /// the queue and it's block root is included in the output.
    ///
    /// If a `header` is already in the queue, but not yet processed by the chain the block root is
    /// included in the output and the `inserted` time for the partial record is set to
    /// `Instant::now()`. Updating the `inserted` time stops the partial from becoming stale.
    pub fn enqueue_headers(&mut self, headers: Vec<BeaconBlockHeader>) -> Vec<Hash256> {
        let mut required_bodies: Vec<Hash256> = vec![];

        for header in headers {
            let block_root = Hash256::from_slice(&header.hash_tree_root()[..]);

            if self.is_new_block(&block_root) {
                self.insert_partial(block_root, header);
                required_bodies.push(block_root)
            }
        }

        required_bodies
    }

    fn insert_partial(&mut self, block_root: Hash256, header: BeaconBlockHeader) {
        self.partials.insert(
            header.block_body_root,
            PartialBeaconBlock {
                block_root,
                header,
                inserted: Instant::now(),
            },
        );
    }
}

pub struct PartialBeaconBlock {
    pub block_root: Hash256,
    pub header: BeaconBlockHeader,
    pub inserted: Instant,
}
