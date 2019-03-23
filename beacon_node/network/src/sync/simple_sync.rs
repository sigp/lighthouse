use crate::beacon_chain::BeaconChain;
use crate::message_handler::NetworkContext;
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCRequest, RPCResponse};
use eth2_libp2p::PeerId;
use slog::{debug, error, info, o, warn};
use ssz::TreeHash;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use types::{BeaconBlock, BeaconBlockBody, BeaconBlockHeader, Epoch, Hash256, Slot};

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

        let queue_item_stale_time = Duration::from_secs(600);

        let import_queue =
            ImportQueue::new(beacon_chain.clone(), queue_item_stale_time, log.clone());
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

        let block_roots = self
            .import_queue
            .enqueue_headers(response.headers, peer_id.clone());

        if !block_roots.is_empty() {
            self.request_block_bodies(peer_id, BeaconBlockBodiesRequest { block_roots }, network);
        }
    }

    pub fn on_beacon_block_bodies_response(
        &mut self,
        peer_id: PeerId,
        response: BeaconBlockBodiesResponse,
        network: &mut NetworkContext,
    ) {
        self.import_queue
            .enqueue_bodies(response.block_bodies, peer_id.clone());
        self.process_import_queue(network);
    }

    pub fn process_import_queue(&mut self, network: &mut NetworkContext) {
        let mut blocks: Vec<(Hash256, BeaconBlock, PeerId)> = self
            .import_queue
            .partials
            .iter()
            .filter_map(|(key, partial)| {
                if let Some(_) = partial.body {
                    let (block, _root) = partial.clone().complete().expect("Body must be Some");
                    Some((*key, block, partial.sender.clone()))
                } else {
                    None
                }
            })
            .collect();

        // Sort the blocks to be in ascending slot order.
        blocks.sort_unstable_by(|a, b| a.1.slot.partial_cmp(&b.1.slot).unwrap());

        let mut imported_keys = vec![];

        for (key, block, sender) in blocks {
            match self.chain.process_block(block) {
                Ok(outcome) => {
                    if outcome.is_invalid() {
                        warn!(self.log, "Invalid block: {:?}", outcome);
                        network.disconnect(sender);
                    } else {
                        imported_keys.push(key)
                    }
                }
                Err(e) => {
                    error!(self.log, "Error during block processing"; "error" => format!("{:?}", e))
                }
            }
        }

        println!("imported_keys.len: {:?}", imported_keys.len());

        if !imported_keys.is_empty() {
            info!(self.log, "Imported {} blocks", imported_keys.len());
            for key in imported_keys {
                self.import_queue.partials.remove(&key);
            }
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
    /// Time before a queue entry is consider state.
    pub stale_time: Duration,
    /// Logging
    log: slog::Logger,
}

impl ImportQueue {
    pub fn new(chain: Arc<BeaconChain>, stale_time: Duration, log: slog::Logger) -> Self {
        Self {
            chain,
            partials: HashMap::new(),
            stale_time,
            log,
        }
    }

    pub fn remove_stale(&mut self) {
        let keys: Vec<Hash256> = self
            .partials
            .iter()
            .filter_map(|(key, partial)| {
                if partial.inserted + self.stale_time >= Instant::now() {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect();

        keys.iter().for_each(|key| {
            self.partials.remove(&key);
        });
    }

    /// Returns `true` if `self.chain` has not yet processed this block.
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
    pub fn enqueue_headers(
        &mut self,
        headers: Vec<BeaconBlockHeader>,
        sender: PeerId,
    ) -> Vec<Hash256> {
        let mut required_bodies: Vec<Hash256> = vec![];

        for header in headers {
            let block_root = Hash256::from_slice(&header.hash_tree_root()[..]);

            if self.is_new_block(&block_root) {
                self.insert_header(block_root, header, sender.clone());
                required_bodies.push(block_root)
            }
        }

        required_bodies
    }

    /// If there is a matching `header` for this `body`, adds it to the queue.
    ///
    /// If there is no `header` for the `body`, the body is simply discarded.
    pub fn enqueue_bodies(&mut self, bodies: Vec<BeaconBlockBody>, sender: PeerId) {
        for body in bodies {
            self.insert_body(body, sender.clone());
        }
    }

    /// Inserts a header to the queue.
    ///
    /// If the header already exists, the `inserted` time is set to `now` and not other
    /// modifications are made.
    fn insert_header(&mut self, block_root: Hash256, header: BeaconBlockHeader, sender: PeerId) {
        self.partials
            .entry(header.block_body_root)
            .and_modify(|p| p.inserted = Instant::now())
            .or_insert(PartialBeaconBlock {
                block_root,
                header,
                body: None,
                inserted: Instant::now(),
                sender,
            });
    }

    /// Updates an existing partial with the `body`.
    ///
    /// If there is no header for the `body`, the body is simply discarded.
    fn insert_body(&mut self, body: BeaconBlockBody, sender: PeerId) {
        let body_root = Hash256::from_slice(&body.hash_tree_root()[..]);

        self.partials.entry(body_root).and_modify(|p| {
            if body_root == p.header.block_body_root {
                p.body = Some(body);
                p.inserted = Instant::now();
                p.sender = sender;
            }
        });
    }
}

#[derive(Clone, Debug)]
pub struct PartialBeaconBlock {
    pub block_root: Hash256,
    pub header: BeaconBlockHeader,
    pub body: Option<BeaconBlockBody>,
    pub inserted: Instant,
    pub sender: PeerId,
}

impl PartialBeaconBlock {
    /// Given a `body`, consumes `self` and returns a complete `BeaconBlock` along with its root.
    pub fn complete(self) -> Option<(BeaconBlock, Hash256)> {
        Some((self.header.into_block(self.body?), self.block_root))
    }
}
