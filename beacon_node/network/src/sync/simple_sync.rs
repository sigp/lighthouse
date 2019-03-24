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

/// The amount of seconds a block (or partial block) may exist in the import queue.
const QUEUE_STALE_SECS: u64 = 60;

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

        let queue_item_stale_time = Duration::from_secs(QUEUE_STALE_SECS);

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
        info!(self.log, "PeerConnect"; "peer" => format!("{:?}", peer_id));

        network.send_rpc_request(peer_id, RPCRequest::Hello(self.chain.hello_message()));
    }

    pub fn on_hello_request(
        &mut self,
        peer_id: PeerId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        debug!(self.log, "HelloRequest"; "peer" => format!("{:?}", peer_id));

        // Say hello back.
        network.send_rpc_response(
            peer_id.clone(),
            RPCResponse::Hello(self.chain.hello_message()),
        );

        self.process_hello(peer_id, hello, network);
    }

    pub fn on_hello_response(
        &mut self,
        peer_id: PeerId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        debug!(self.log, "HelloResponse"; "peer" => format!("{:?}", peer_id));

        // Process the hello message, without sending back another hello.
        self.process_hello(peer_id, hello, network);
    }

    fn process_hello(
        &mut self,
        peer_id: PeerId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        let spec = self.chain.get_spec();

        let remote = PeerSyncInfo::from(hello);
        let local = PeerSyncInfo::from(&self.chain);
        let remote_status = remote.status_compared_to(local);

        // network id must match
        if remote_status != PeerStatus::OnDifferentChain {
            info!(self.log, "HandshakeSuccess"; "peer" => format!("{:?}", peer_id));
            self.known_peers.insert(peer_id.clone(), remote);
        }

        match remote_status {
            PeerStatus::OnDifferentChain => {
                info!(
                    self.log, "Failure";
                    "peer" => format!("{:?}", peer_id),
                    "reason" => "network_id"
                );

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

    pub fn on_beacon_block_roots_request(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockRootsRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockRootsRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.count,
        );

        let roots = match self
            .chain
            .get_block_roots(req.start_slot, req.count as usize, 0)
        {
            Ok(roots) => roots,
            Err(e) => {
                // TODO: return RPC error.
                warn!(
                    self.log,
                    "RPCRequest"; "peer" => format!("{:?}", peer_id),
                    "req" => "BeaconBlockRoots",
                    "error" => format!("{:?}", e)
                );
                return;
            }
        };

        let roots = roots
            .iter()
            .enumerate()
            .map(|(i, &block_root)| BlockRootSlot {
                slot: req.start_slot + Slot::from(i),
                block_root,
            })
            .collect();

        network.send_rpc_response(
            peer_id,
            RPCResponse::BeaconBlockRoots(BeaconBlockRootsResponse { roots }),
        )
    }

    pub fn on_beacon_block_roots_response(
        &mut self,
        peer_id: PeerId,
        res: BeaconBlockRootsResponse,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockRootsResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => res.roots.len(),
        );

        if res.roots.is_empty() {
            warn!(
                self.log,
                "Peer returned empty block roots response. PeerId: {:?}", peer_id
            );
            return;
        }

        let new_root_index = self.import_queue.first_new_root(&res.roots);

        // If a new block root is found, request it and all the headers following it.
        //
        // We make an assumption here that if we don't know a block then we don't know of all
        // it's parents. This might not be the case if syncing becomes more sophisticated.
        if let Some(i) = new_root_index {
            let new = &res.roots[i];

            self.request_block_headers(
                peer_id,
                BeaconBlockHeadersRequest {
                    start_root: new.block_root,
                    start_slot: new.slot,
                    max_headers: (res.roots.len() - i) as u64,
                    skip_slots: 0,
                },
                network,
            )
        }
    }

    pub fn on_beacon_block_headers_request(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockHeadersRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockHeadersRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.max_headers,
        );

        let headers = match self.chain.get_block_headers(
            req.start_slot,
            req.max_headers as usize,
            req.skip_slots as usize,
        ) {
            Ok(headers) => headers,
            Err(e) => {
                // TODO: return RPC error.
                warn!(
                    self.log,
                    "RPCRequest"; "peer" => format!("{:?}", peer_id),
                    "req" => "BeaconBlockHeaders",
                    "error" => format!("{:?}", e)
                );
                return;
            }
        };

        network.send_rpc_response(
            peer_id,
            RPCResponse::BeaconBlockHeaders(BeaconBlockHeadersResponse { headers }),
        )
    }

    pub fn on_beacon_block_headers_response(
        &mut self,
        peer_id: PeerId,
        res: BeaconBlockHeadersResponse,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockHeadersResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => res.headers.len(),
        );

        if res.headers.is_empty() {
            warn!(
                self.log,
                "Peer returned empty block headers response. PeerId: {:?}", peer_id
            );
            return;
        }

        // Enqueue the headers, obtaining a list of the roots of the headers which were newly added
        // to the queue.
        let block_roots = self
            .import_queue
            .enqueue_headers(res.headers, peer_id.clone());

        self.request_block_bodies(peer_id, BeaconBlockBodiesRequest { block_roots }, network);
    }

    pub fn on_beacon_block_bodies_request(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockBodiesRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockBodiesRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.block_roots.len(),
        );

        let block_bodies = match self.chain.get_block_bodies(&req.block_roots) {
            Ok(bodies) => bodies,
            Err(e) => {
                // TODO: return RPC error.
                warn!(
                    self.log,
                    "RPCRequest"; "peer" => format!("{:?}", peer_id),
                    "req" => "BeaconBlockBodies",
                    "error" => format!("{:?}", e)
                );
                return;
            }
        };

        network.send_rpc_response(
            peer_id,
            RPCResponse::BeaconBlockBodies(BeaconBlockBodiesResponse { block_bodies }),
        )
    }

    pub fn on_beacon_block_bodies_response(
        &mut self,
        peer_id: PeerId,
        res: BeaconBlockBodiesResponse,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockBodiesResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => res.block_bodies.len(),
        );

        self.import_queue
            .enqueue_bodies(res.block_bodies, peer_id.clone());

        // Clear out old entries
        self.import_queue.remove_stale();

        // Import blocks, if possible.
        self.process_import_queue(network);
    }

    pub fn process_import_queue(&mut self, network: &mut NetworkContext) {
        let mut successful = 0;
        let mut invalid = 0;
        let mut errored = 0;

        // Loop through all of the complete blocks in the queue.
        for (block_root, block, sender) in self.import_queue.complete_blocks() {
            match self.chain.process_block(block) {
                Ok(outcome) => {
                    if outcome.is_invalid() {
                        invalid += 1;
                        warn!(
                            self.log,
                            "InvalidBlock";
                            "sender_peer_id" => format!("{:?}", sender),
                            "reason" => format!("{:?}", outcome),
                        );
                        network.disconnect(sender);
                    }

                    // If this results to true, the item will be removed from the queue.
                    if outcome.sucessfully_processed() {
                        successful += 1;
                        self.import_queue.remove(block_root);
                    }
                }
                Err(e) => {
                    errored += 1;
                    error!(self.log, "BlockProcessingError"; "error" => format!("{:?}", e));
                }
            }
        }

        if successful > 0 {
            info!(self.log, "Imported {} blocks", successful)
        }
        if invalid > 0 {
            warn!(self.log, "Rejected {} invalid blocks", invalid)
        }
        if errored > 0 {
            warn!(self.log, "Failed to process {} blocks", errored)
        }
    }

    fn request_block_roots(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockRootsRequest,
        network: &mut NetworkContext,
    ) {
        // Potentially set state to sync.
        if self.state == SyncState::Idle && req.count > SLOT_IMPORT_TOLERANCE {
            debug!(self.log, "Entering downloading sync state.");
            self.state = SyncState::Downloading;
        }

        debug!(
            self.log,
            "RPCRequest(BeaconBlockRoots)";
            "count" => req.count,
            "peer" => format!("{:?}", peer_id)
        );

        // TODO: handle count > max count.
        network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlockRoots(req));
    }

    fn request_block_headers(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockHeadersRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "RPCRequest(BeaconBlockHeaders)";
            "max_headers" => req.max_headers,
            "peer" => format!("{:?}", peer_id)
        );

        network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlockHeaders(req));
    }

    fn request_block_bodies(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockBodiesRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "RPCRequest(BeaconBlockBodies)";
            "count" => req.block_roots.len(),
            "peer" => format!("{:?}", peer_id)
        );

        network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlockBodies(req));
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
    pub partials: Vec<PartialBeaconBlock>,
    /// Time before a queue entry is consider state.
    pub stale_time: Duration,
    /// Logging
    log: slog::Logger,
}

impl ImportQueue {
    pub fn new(chain: Arc<BeaconChain>, stale_time: Duration, log: slog::Logger) -> Self {
        Self {
            chain,
            partials: vec![],
            stale_time,
            log,
        }
    }

    /// Completes all possible partials into `BeaconBlock` and returns them, sorted by increasing
    /// slot number.  Does not delete the partials from the queue, this must be done manually.
    ///
    /// Returns `(queue_index, block, sender)`:
    ///
    /// - `block_root`: may be used to remove the entry if it is successfully processed.
    /// - `block`: the completed block.
    /// - `sender`: the `PeerId` the provided the `BeaconBlockBody` which completed the partial.
    pub fn complete_blocks(&self) -> Vec<(Hash256, BeaconBlock, PeerId)> {
        let mut complete: Vec<(Hash256, BeaconBlock, PeerId)> = self
            .partials
            .iter()
            .filter_map(|partial| partial.clone().complete())
            .collect();

        // Sort the completable partials to be in ascending slot order.
        complete.sort_unstable_by(|a, b| a.1.slot.partial_cmp(&b.1.slot).unwrap());

        complete
    }

    /// Removes the first `PartialBeaconBlock` with a matching `block_root`, returning the partial
    /// if it exists.
    pub fn remove(&mut self, block_root: Hash256) -> Option<PartialBeaconBlock> {
        let position = self
            .partials
            .iter()
            .position(|p| p.block_root == block_root)?;
        Some(self.partials.remove(position))
    }

    /// Flushes all stale entries from the queue.
    ///
    /// An entry is stale if it has as a `inserted` time that is more than `self.stale_time` in the
    /// past.
    pub fn remove_stale(&mut self) {
        let stale_indices: Vec<usize> = self
            .partials
            .iter()
            .enumerate()
            .filter_map(|(i, partial)| {
                if partial.inserted + self.stale_time <= Instant::now() {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        if !stale_indices.is_empty() {
            debug!(
                self.log,
                "ImportQueue removing stale entries";
                "stale_items" => stale_indices.len(),
                "stale_time_seconds" => self.stale_time.as_secs()
            );
        }

        stale_indices.iter().for_each(|&i| {
            self.partials.remove(i);
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
        if let Some(i) = self
            .partials
            .iter()
            .position(|p| p.block_root == block_root)
        {
            self.partials[i].inserted = Instant::now();
        } else {
            self.partials.push(PartialBeaconBlock {
                block_root,
                header,
                body: None,
                inserted: Instant::now(),
                sender,
            })
        }
    }

    /// Updates an existing partial with the `body`.
    ///
    /// If there is no header for the `body`, the body is simply discarded.
    ///
    /// If the body already existed, the `inserted` time is set to `now`.
    fn insert_body(&mut self, body: BeaconBlockBody, sender: PeerId) {
        let body_root = Hash256::from_slice(&body.hash_tree_root()[..]);

        self.partials.iter_mut().for_each(|mut p| {
            if body_root == p.header.block_body_root {
                p.inserted = Instant::now();

                if p.body.is_none() {
                    p.body = Some(body.clone());
                    p.sender = sender.clone();
                }
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
    pub fn complete(self) -> Option<(Hash256, BeaconBlock, PeerId)> {
        Some((
            self.block_root,
            self.header.into_block(self.body?),
            self.sender,
        ))
    }
}
