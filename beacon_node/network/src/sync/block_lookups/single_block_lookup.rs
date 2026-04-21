use super::{BlockComponent, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS};
use crate::sync::manager::BlockProcessType;
use crate::sync::network_context::{
    LookupRequestResult, PeerGroup, ReqId, RpcRequestSendError, SendErrorProcessor,
    SyncNetworkContext,
};
use beacon_chain::BeaconChainTypes;
use beacon_chain::BlockProcessStatus;
use beacon_chain::block_verification_types::AsBlock;
use educe::Educe;
use lighthouse_network::service::api_types::Id;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Hash256;
use strum::IntoStaticStr;
use tracing::{Span, debug, debug_span};
use types::data::FixedBlobSidecarList;
use types::{
    DataColumnSidecarList, EthSpec, ExecutionBlockHash, ForkName, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope, Slot,
};

// === AwaitingParent — tracks what a child lookup waits for ===

/// What a child lookup is waiting for its parent to resolve.
///
/// `parent_hash` is `Some` only post-Gloas: the child's bid references the
/// parent's payload execution hash, which lets us determine whether the parent
/// is full (payload envelope was published) or empty. Pre-Gloas lookups never
/// need to distinguish — they always wait for the full block+data set.
#[derive(Debug, Clone, Copy)]
pub struct AwaitingParent {
    parent_root: Hash256,
    parent_hash: Option<ExecutionBlockHash>,
}

impl AwaitingParent {
    pub fn pre_gloas(parent_root: Hash256) -> Self {
        Self {
            parent_root,
            parent_hash: None,
        }
    }

    pub fn post_gloas(parent_root: Hash256, parent_hash: ExecutionBlockHash) -> Self {
        Self {
            parent_root,
            parent_hash: Some(parent_hash),
        }
    }

    pub fn parent_root(&self) -> Hash256 {
        self.parent_root
    }

    pub fn parent_hash(&self) -> Option<ExecutionBlockHash> {
        self.parent_hash
    }

    pub fn is_post_gloas(&self) -> bool {
        self.parent_hash.is_some()
    }
}

// === Public types re-exported by mod.rs ===

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DownloadResult<T: Clone> {
    pub value: T,
    pub block_root: Hash256,
    pub seen_timestamp: Duration,
    pub peer_group: PeerGroup,
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupRequestError {
    /// Too many failed attempts
    TooManyAttempts {
        /// The failed attempts were primarily due to processing failures.
        cannot_process: bool,
    },
    /// Error sending event to network
    SendFailedNetwork(RpcRequestSendError),
    /// Error sending event to processor
    SendFailedProcessor(SendErrorProcessor),
    /// Inconsistent lookup request state
    BadState(String),
    /// Lookup failed for some other reason and should be dropped
    Failed(/* reason: */ String),
    /// Attempted to retrieve a not known lookup id
    UnknownLookup,
    /// Received a download result for a different request id than the in-flight request.
    /// There should only exist a single request at a time. Having multiple requests is a bug and
    /// can result in undefined state, so it's treated as a hard error and the lookup is dropped.
    UnexpectedRequestId {
        expected_req_id: ReqId,
        req_id: ReqId,
    },
    InternalError(String),
}

// Dedicated enum for LookupResult to force its usage
#[must_use = "LookupResult must be handled with on_lookup_result"]
pub enum LookupResult {
    /// Lookup completed successfully
    Completed,
    /// Lookup is expecting some future event from the network
    Pending,
    /// Block's parent is not known to fork-choice, a parent lookup is needed
    ParentUnknown {
        awaiting_parent: AwaitingParent,
        block_root: Hash256,
        peers: Vec<PeerId>,
    },
}

// === Block request: Downloading → Downloaded → Processing → Complete ===

#[derive(Educe)]
#[educe(Debug)]
enum BlockRequest<E: EthSpec> {
    /// Block downloading or awaiting download
    Downloading {
        block_root: Hash256,
        state: SingleLookupRequestState<Arc<SignedBeaconBlock<E>>>,
    },
    /// Block downloaded, waiting for parent check + send for processing
    Downloaded {
        #[educe(Debug(ignore))]
        block: Arc<SignedBeaconBlock<E>>,
        peer: PeerId,
    },
    /// Block sent for processing, awaiting result
    Processing {
        #[educe(Debug(ignore))]
        block: Arc<SignedBeaconBlock<E>>,
        peer: PeerId,
    },
    /// Block processing complete. `peer` is retained so data/payload processing failures
    /// after the block has been imported can still be attributed back to the peer that
    /// served the block (they are typically the same peer for blobs). `None` when the
    /// block bypassed the download path (cache hit in the availability checker).
    Complete {
        #[educe(Debug(ignore))]
        block: Arc<SignedBeaconBlock<E>>,
        peer: Option<PeerId>,
    },
}

impl<E: EthSpec> BlockRequest<E> {
    fn new(block_root: Hash256) -> Self {
        BlockRequest::Downloading {
            block_root,
            state: SingleLookupRequestState::new(),
        }
    }

    fn new_with_processing_failures(block_root: Hash256, failed_processing: u8) -> Self {
        BlockRequest::Downloading {
            block_root,
            state: SingleLookupRequestState::new_with_processing_failures(failed_processing),
        }
    }

    fn peek_block(&self) -> Option<&Arc<SignedBeaconBlock<E>>> {
        match self {
            BlockRequest::Downloading { state, .. } => state.peek_downloaded_data(),
            BlockRequest::Downloaded { block, .. }
            | BlockRequest::Processing { block, .. }
            | BlockRequest::Complete { block, .. } => Some(block),
        }
    }

    fn peek_slot(&self) -> Option<Slot> {
        self.peek_block().map(|b| b.slot())
    }

    /// Returns the block peer for error attribution. Available in Downloaded/Processing states.
    fn peer(&self) -> Option<PeerId> {
        match self {
            BlockRequest::Downloaded { peer, .. } | BlockRequest::Processing { peer, .. } => {
                Some(*peer)
            }
            BlockRequest::Downloading { state, .. } => state
                .peek_downloaded_peer_group()
                .and_then(|pg| pg.all().next().copied()),
            BlockRequest::Complete { peer, .. } => *peer,
        }
    }

    fn is_awaiting_event(&self) -> bool {
        match self {
            BlockRequest::Downloading { state, .. } => state.is_awaiting_event(),
            BlockRequest::Processing { .. } => true,
            _ => false,
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self, BlockRequest::Complete { .. })
    }

    fn insert_verified_response(
        &mut self,
        result: DownloadResult<Arc<SignedBeaconBlock<E>>>,
    ) -> bool {
        if let BlockRequest::Downloading { state, .. } = self {
            state.insert_verified_response(result)
        } else {
            // The block already transitioned past Downloading (e.g. a child arrived while the
            // block was already being processed). Silently dropping would be hard to debug if
            // we ever reach this path unexpectedly — log it.
            debug!(
                state = ?self,
                "insert_verified_response called outside Downloading state, dropping"
            );
            false
        }
    }
}

// === Data request: WaitingForBlock → Downloading → Downloaded → Processing → Complete ===

#[derive(Debug)]
enum DataRequest<E: EthSpec> {
    /// Waiting for block to be downloaded to determine what data is needed
    WaitingForBlock,
    /// Data downloading or awaiting download
    Downloading(DataDownload<E>),
    /// Data downloaded, waiting for block processing to complete before import
    Downloaded {
        data: DownloadedData<E>,
        peer_group: PeerGroup,
    },
    /// Data sent for processing, awaiting result
    Processing {
        kind: DataDownloadKind,
        peer_group: PeerGroup,
    },
    /// Data processing complete (or no data needed)
    Complete,
}

impl<E: EthSpec> DataRequest<E> {
    fn is_awaiting_event(&self) -> bool {
        match self {
            DataRequest::Downloading(dl) => dl.is_awaiting_event(),
            DataRequest::Processing { .. } => true,
            _ => false,
        }
    }

    fn peer_group(&self) -> Option<&PeerGroup> {
        match self {
            DataRequest::Downloading(dl) => dl.peek_downloaded_peer_group(),
            DataRequest::Downloaded { peer_group, .. }
            | DataRequest::Processing { peer_group, .. } => Some(peer_group),
            DataRequest::WaitingForBlock | DataRequest::Complete => None,
        }
    }
}

/// Fork-dependent data download state
#[derive(Debug)]
enum DataDownload<E: EthSpec> {
    Blobs {
        block_root: Hash256,
        expected_blobs: usize,
        state: SingleLookupRequestState<FixedBlobSidecarList<E>>,
    },
    Columns {
        block_root: Hash256,
        state: SingleLookupRequestState<DataColumnSidecarList<E>>,
    },
}

impl<E: EthSpec> DataDownload<E> {
    fn continue_requests<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        id: Id,
        peers: Arc<RwLock<HashSet<PeerId>>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        match self {
            DataDownload::Blobs {
                block_root,
                expected_blobs,
                state,
            } => {
                let br = *block_root;
                let eb = *expected_blobs;
                state.make_request(|| cx.blob_lookup_request(id, peers, br, eb))?;
            }
            DataDownload::Columns {
                block_root, state, ..
            } => {
                let br = *block_root;
                state.make_request(|| cx.custody_lookup_request(id, br, peers))?;
            }
        }
        Ok(())
    }

    fn is_completed(&self) -> bool {
        match self {
            DataDownload::Blobs { state, .. } => state.is_completed(),
            DataDownload::Columns { state, .. } => state.is_completed(),
        }
    }

    fn take_download_result(&mut self) -> Option<(DownloadedData<E>, PeerGroup)> {
        match self {
            DataDownload::Blobs {
                expected_blobs,
                state,
                ..
            } => state.take_download_result().map(|r| {
                (
                    DownloadedData::Blobs {
                        blobs: r.value,
                        expected_blobs: *expected_blobs,
                    },
                    r.peer_group,
                )
            }),
            DataDownload::Columns { state, .. } => state
                .take_download_result()
                .map(|r| (DownloadedData::Columns(r.value), r.peer_group)),
        }
    }

    fn is_awaiting_event(&self) -> bool {
        match self {
            DataDownload::Blobs { state, .. } => state.is_awaiting_event(),
            DataDownload::Columns { state, .. } => state.is_awaiting_event(),
        }
    }

    fn peek_downloaded_peer_group(&self) -> Option<&PeerGroup> {
        match self {
            DataDownload::Blobs { state, .. } => state.peek_downloaded_peer_group(),
            DataDownload::Columns { state, .. } => state.peek_downloaded_peer_group(),
        }
    }
}

/// Downloaded data, waiting to be sent for processing
#[derive(Debug)]
enum DownloadedData<E: EthSpec> {
    Blobs {
        blobs: FixedBlobSidecarList<E>,
        expected_blobs: usize,
    },
    Columns(DataColumnSidecarList<E>),
}

impl<E: EthSpec> DownloadedData<E> {
    fn kind(&self) -> DataDownloadKind {
        match self {
            DownloadedData::Blobs { expected_blobs, .. } => DataDownloadKind::Blobs {
                expected_blobs: *expected_blobs,
            },
            DownloadedData::Columns(_) => DataDownloadKind::Columns,
        }
    }
}

/// Enough info to reconstruct a fresh `DataDownload` when we need to retry data download
/// after a processing failure. We can't call `create_data_request` again from here because
/// we're past the `WaitingForBlock` state and don't have the `SyncNetworkContext` (and
/// therefore no `ChainSpec`) — so the request kind (blobs vs columns, plus the expected
/// blob count) is cached alongside the in-flight request instead.
#[derive(Debug, Clone, Copy)]
enum DataDownloadKind {
    Blobs { expected_blobs: usize },
    Columns,
}

impl DataDownloadKind {
    fn into_fresh_download<E: EthSpec>(
        self,
        block_root: Hash256,
        failed_processing: u8,
    ) -> DataDownload<E> {
        match self {
            DataDownloadKind::Blobs { expected_blobs } => DataDownload::Blobs {
                block_root,
                expected_blobs,
                state: SingleLookupRequestState::new_with_processing_failures(failed_processing),
            },
            DataDownloadKind::Columns => DataDownload::Columns {
                block_root,
                state: SingleLookupRequestState::new_with_processing_failures(failed_processing),
            },
        }
    }
}

// === Payload request: WaitingForBlock → Downloading → Downloaded → Processing → Complete ===

#[derive(Educe)]
#[educe(Debug)]
enum PayloadRequest<E: EthSpec> {
    /// Waiting for block to be downloaded to determine if payload is needed
    WaitingForBlock,
    Downloading {
        block_root: Hash256,
        state: SingleLookupRequestState<Arc<SignedExecutionPayloadEnvelope<E>>>,
    },
    Downloaded {
        peer_group: PeerGroup,
    },
    Processing {
        peer_group: PeerGroup,
    },
    /// Payload processed, or no payload needed.
    Complete,
}

impl<E: EthSpec> PayloadRequest<E> {
    fn is_awaiting_event(&self) -> bool {
        match self {
            PayloadRequest::Downloading { state, .. } => state.is_awaiting_event(),
            PayloadRequest::Processing { .. } => true,
            _ => false,
        }
    }
}

// === SingleBlockLookup — three independent requests ===

#[derive(Educe)]
#[educe(Debug(bound(T: BeaconChainTypes)))]
pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    block_root: Hash256,

    // Block request — always present
    block_request: BlockRequest<T::EthSpec>,

    // Data request — starts as WaitingForBlock, set after block downloaded
    data_request: DataRequest<T::EthSpec>,

    // Payload request — starts as WaitingForBlock, set after block downloaded
    payload_request: PayloadRequest<T::EthSpec>,

    // Peer sets.
    //
    // `Arc<RwLock<..>>` is required by `ActiveCustodyRequest` (columns only), which lives
    // in `SyncNetworkContext` and needs to observe peers being added/removed at runtime
    // while it's in flight. `data_peers` and `payload_peers` use the same shape purely for
    // consistency so all three sets plug into the same `add_peer` / `remove_peer` surface.
    /// Peers for block download (also used for data in pre-Gloas forks).
    #[educe(Debug(method(fmt_peer_set_as_len)))]
    peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Peers for data download (0 initially for Gloas, shared with block for pre-Gloas).
    #[educe(Debug(method(fmt_peer_set_as_len)))]
    data_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Peers for payload download (0 initially, Gloas only).
    #[educe(Debug(method(fmt_peer_set_as_len)))]
    payload_peers: Arc<RwLock<HashSet<PeerId>>>,

    // Parent tracking
    awaiting_parent: Option<AwaitingParent>,
    created: Instant,
    pub(crate) span: Span,

    // Retry tracking
    failed_processing: u8,
}

impl<T: BeaconChainTypes> SingleBlockLookup<T> {
    pub fn new(
        requested_block_root: Hash256,
        peers: &[PeerId],
        peer_type: &PeerType,
        id: Id,
        awaiting_parent: Option<AwaitingParent>,
    ) -> Self {
        let lookup_span = debug_span!(
            "lh_single_block_lookup",
            block_root = %requested_block_root,
            id = id,
        );

        let peer_set: HashSet<PeerId> = peers.iter().copied().collect();
        let data_peers = if peer_type.data {
            peer_set.clone()
        } else {
            HashSet::new()
        };
        let payload_peers = if peer_type.payload {
            peer_set.clone()
        } else {
            HashSet::new()
        };

        Self {
            id,
            block_root: requested_block_root,
            block_request: BlockRequest::new(requested_block_root),
            data_request: DataRequest::WaitingForBlock,
            payload_request: PayloadRequest::WaitingForBlock,
            data_peers: Arc::new(RwLock::new(data_peers)),
            payload_peers: Arc::new(RwLock::new(payload_peers)),
            peers: Arc::new(RwLock::new(peer_set)),
            awaiting_parent,
            created: Instant::now(),
            failed_processing: 0,
            span: lookup_span,
        }
    }

    /// Returns whether this lookup's block was produced with a published payload envelope
    /// ("full") as seen by the given child's bid reference. Always `false` pre-Gloas: the
    /// empty/full distinction only exists post-Gloas. The child's bid carries the parent
    /// execution hash, which we match against this block's bid `block_hash`.
    pub fn is_full_payload(&self, awaiting_parent: &AwaitingParent) -> bool {
        let Some(parent_hash) = awaiting_parent.parent_hash() else {
            return false;
        };
        let Some(block) = self.block_request.peek_block() else {
            // Block not yet downloaded — we don't know what peers can serve the
            // parent envelope/data yet. Treat conservatively as "not full".
            // TODO(gloas): cache peers in a deferred set instead of dropping them
            // so we can assign them to data/payload streams once the block arrives.
            debug!(
                block_root = ?self.block_root,
                "is_full_payload called before block downloaded, returning false"
            );
            return false;
        };
        match block.message().body().signed_execution_payload_bid() {
            Ok(payload) => payload.message.block_hash == parent_hash,
            Err(_) => false,
        }
    }

    /// Reset the status of all requests (used on block processing failure)
    pub fn reset_requests(&mut self) {
        // Increment processing failure counter (we're resetting due to processing error)
        self.failed_processing = self.failed_processing.saturating_add(1);
        // Reset to fresh Downloading state with the updated counter
        self.block_request =
            BlockRequest::new_with_processing_failures(self.block_root, self.failed_processing);
        self.data_request = DataRequest::WaitingForBlock;
        self.payload_request = PayloadRequest::WaitingForBlock;
    }

    /// Return the slot of this lookup's block if it's currently cached
    pub fn peek_downloaded_block_slot(&self) -> Option<Slot> {
        self.block_request.peek_slot()
    }

    /// Get the block root that is being requested.
    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn awaiting_parent(&self) -> Option<AwaitingParent> {
        self.awaiting_parent
    }

    /// Mark this lookup as no longer awaiting a parent lookup. Components can be sent for
    /// processing.
    pub fn resolve_awaiting_parent(&mut self) {
        self.awaiting_parent = None;
    }

    /// Returns the time elapsed since this lookup was created
    pub fn elapsed_since_created(&self) -> Duration {
        self.created.elapsed()
    }

    /// Maybe insert a verified response into this lookup. Returns true if imported
    pub fn add_child_components(&mut self, block_component: BlockComponent<T::EthSpec>) -> bool {
        match block_component {
            BlockComponent::Block(block) => self.block_request.insert_verified_response(block),
            BlockComponent::Blob(_) | BlockComponent::DataColumn(_) => {
                // For now ignore single blobs and columns, as the blob request state assumes all
                // blobs are attributed to the same peer = the peer serving the remaining blobs.
                false
            }
        }
    }

    /// Check the block root matches the requested block root.
    pub fn is_for_block(&self, block_root: Hash256) -> bool {
        self.block_root() == block_root
    }

    /// Returns true if this request is expecting some event to make progress
    pub fn is_awaiting_event(&self) -> bool {
        self.awaiting_parent.is_some()
            || self.block_request.is_awaiting_event()
            || self.data_request.is_awaiting_event()
            || self.payload_request.is_awaiting_event()
    }

    /// Returns the block peer if block has been downloaded. Used for peer penalization.
    pub fn block_peer(&self) -> Option<PeerId> {
        self.block_request.peer()
    }

    /// Returns custody column peer group if data has been downloaded. Used for peer penalization.
    pub fn data_peer_group(&self) -> Option<&PeerGroup> {
        self.data_request.peer_group()
    }

    /// Returns `Some(true)` if the current data request is for custody columns (Fulu/Gloas),
    /// `Some(false)` for blobs (Deneb/Electra), `None` when no active data request. Used to
    /// pick the right penalty string on processing failure.
    pub fn data_is_columns(&self) -> Option<bool> {
        match &self.data_request {
            DataRequest::Downloading(DataDownload::Columns { .. }) => Some(true),
            DataRequest::Downloading(DataDownload::Blobs { .. }) => Some(false),
            DataRequest::Downloaded { data, .. } => {
                Some(matches!(data, DownloadedData::Columns(_)))
            }
            DataRequest::Processing { kind, .. } => Some(matches!(kind, DataDownloadKind::Columns)),
            DataRequest::WaitingForBlock | DataRequest::Complete => None,
        }
    }

    // -- Main state machine driver --

    /// Makes progress on all requests of this lookup. Any error is not recoverable and must result
    /// in dropping the lookup. May mark the lookup as completed.
    ///
    /// Each of the block / data / payload sub-state-machines is driven inside its own `loop`
    /// so that synchronous state transitions (e.g. Downloading → Downloaded → Processing) run
    /// without returning. Each loop `break`s when further progress requires an external event
    /// (download response, processing result, or a parent lookup to resolve).
    pub fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let _guard = self.span.clone().entered();
        let id = self.id;
        let block_root = self.block_root;

        // === Block request ===
        loop {
            match &mut self.block_request {
                BlockRequest::Downloading { state, .. } => {
                    let peers = self.peers.clone();
                    state.make_request(|| cx.block_lookup_request(id, peers, block_root))?;

                    if state.is_completed() {
                        // Block is fully execution-validated and cached in the availability
                        // checker (NoRequestNeeded). Pull it from the processing-status cache
                        // so the data/payload streams can continue, and mark the block stream
                        // complete without re-processing.
                        match cx.chain.get_block_process_status(&block_root) {
                            BlockProcessStatus::NotValidated(block, _)
                            | BlockProcessStatus::ExecutionValidated(block) => {
                                // No peer to attribute against on a cache hit.
                                self.block_request = BlockRequest::Complete { block, peer: None };
                                continue;
                            }
                            BlockProcessStatus::Unknown => {
                                // Race: the block was imported into fork-choice between
                                // `block_lookup_request` and this check. All components must
                                // have landed with it, so the lookup has nothing left to do.
                                return Ok(LookupResult::Completed);
                            }
                        }
                    } else if let Some(result) = state.take_download_result() {
                        // Block download requests are sent to a single peer, so the returned
                        // PeerGroup contains exactly one entry. Take the first and only.
                        let peer = result.peer_group.all().next().copied().ok_or_else(|| {
                            LookupRequestError::BadState("block download has no peer".into())
                        })?;
                        self.block_request = BlockRequest::Downloaded {
                            block: result.value,
                            peer,
                        };
                    } else {
                        // Awaiting download
                        break;
                    }
                }
                BlockRequest::Downloaded { block, peer } => {
                    if self.awaiting_parent.is_some() {
                        break;
                    }

                    let parent_root = block.parent_root();
                    // Zero hash is the parent of the genesis block — not a real block.
                    if parent_root != Hash256::ZERO {
                        let parent_in_fork_choice = cx
                            .chain
                            .canonical_head
                            .fork_choice_read_lock()
                            .get_block(&parent_root)
                            .is_some();
                        if !parent_in_fork_choice {
                            let awaiting_parent = if let Ok(bid) =
                                block.message().body().signed_execution_payload_bid()
                            {
                                AwaitingParent::post_gloas(
                                    parent_root,
                                    bid.message.parent_block_hash,
                                )
                            } else {
                                AwaitingParent::pre_gloas(parent_root)
                            };
                            self.awaiting_parent = Some(awaiting_parent);
                            return Ok(LookupResult::ParentUnknown {
                                awaiting_parent,
                                block_root: self.block_root,
                                peers: self.all_peers(),
                            });
                        }
                        // post-gloas we need to also check if the envelope is known to fork choice
                        if let Ok(child_bid) = block.message().body().signed_execution_payload_bid()
                        {
                            // TODO(gloas): after fork-choice: use parent_proto_block.execution_payload_block_hash here
                            let parent_is_full = cx
                                .chain
                                .get_blinded_block(&parent_root)
                                .map(|maybe_parent_block| {
                                    if let Some(parent_block) = maybe_parent_block {
                                        parent_block
                                            .message()
                                            .body()
                                            .signed_execution_payload_bid()
                                            .map(|parent_bid| {
                                                parent_bid.message.block_hash
                                                    == child_bid.message.parent_block_hash
                                            })
                                            .unwrap_or(false)
                                    } else {
                                        false
                                    }
                                })
                                .unwrap_or(false);

                            if parent_is_full
                                && !cx.chain.envelope_is_known_to_fork_choice(&parent_root)
                            {
                                let awaiting_parent = AwaitingParent::post_gloas(
                                    parent_root,
                                    child_bid.message.parent_block_hash,
                                );
                                self.awaiting_parent = Some(awaiting_parent);
                                return Ok(LookupResult::ParentUnknown {
                                    awaiting_parent,
                                    block_root: self.block_root,
                                    peers: self.all_peers(),
                                });
                            }
                        }
                    }

                    let block = block.clone();
                    let peer = *peer;
                    cx.send_block_for_processing(
                        id,
                        self.block_root,
                        block.clone(),
                        Duration::ZERO,
                    )
                    .map_err(LookupRequestError::SendFailedProcessor)?;
                    self.block_request = BlockRequest::Processing { block, peer };
                    // Processing needs an async trigger (block processing result) before we
                    // can make progress.
                    break;
                }
                BlockRequest::Processing { .. } | BlockRequest::Complete { .. } => break,
            }
        }

        // === Data request ===
        loop {
            match &mut self.data_request {
                DataRequest::WaitingForBlock => {
                    // Prefer a block downloaded by this lookup. Otherwise fall back to the
                    // chain's processing-status cache: the block may already be in the
                    // availability checker via gossip/HTTP API before this lookup downloads
                    // it, and we can still drive the data request in parallel.
                    let block_metadata = self
                        .block_request
                        .peek_block()
                        .map(|b| (b.slot(), b.num_expected_blobs()))
                        .or_else(|| match cx.chain.get_block_process_status(&block_root) {
                            BlockProcessStatus::NotValidated(block, _)
                            | BlockProcessStatus::ExecutionValidated(block) => {
                                Some((block.slot(), block.num_expected_blobs()))
                            }
                            BlockProcessStatus::Unknown => None,
                        });
                    if let Some((slot, expected_blobs)) = block_metadata {
                        self.create_data_request(slot, expected_blobs, cx);
                    } else {
                        // Wait for block to be downloaded
                        break;
                    }
                }
                DataRequest::Downloading(dl) => {
                    // Custody column downloads dispatch against the global synced peer pool
                    // inside `ActiveCustodyRequest`, not against `data_peers`. Only gate on
                    // `data_peers` for post-Gloas, where peer sets are strictly partitioned
                    // and no fallback pool exists.
                    let has_peers = !self.data_peers.read().is_empty();
                    let is_gloas = matches!(dl, DataDownload::Columns { .. })
                        && self.awaiting_parent.is_some_and(|a| a.is_post_gloas());
                    if has_peers || !is_gloas {
                        dl.continue_requests(id, self.data_peers.clone(), cx)?;
                    }
                    if dl.is_completed() {
                        // All data already imported (e.g. received via gossip)
                        self.data_request = DataRequest::Complete;
                    } else if let Some((data, peer_group)) = dl.take_download_result() {
                        self.data_request = DataRequest::Downloaded { data, peer_group };
                    } else {
                        // Wait for data to be downloaded
                        break;
                    }
                }
                DataRequest::Downloaded { data, peer_group } => {
                    match data {
                        DownloadedData::Blobs { blobs, .. } => {
                            cx.send_blobs_for_processing(
                                id,
                                self.block_root,
                                blobs.clone(),
                                Duration::ZERO,
                            )
                            .map_err(LookupRequestError::SendFailedProcessor)?;
                        }
                        DownloadedData::Columns(columns) => {
                            cx.send_custody_columns_for_processing(
                                id,
                                self.block_root,
                                columns.clone(),
                                Duration::ZERO,
                                BlockProcessType::SingleCustodyColumn(id),
                            )
                            .map_err(LookupRequestError::SendFailedProcessor)?;
                        }
                    }
                    let kind = data.kind();
                    let peer_group = peer_group.clone();
                    self.data_request = DataRequest::Processing { kind, peer_group };
                    // Processing needs an async trigger.
                    break;
                }
                DataRequest::Processing { .. } | DataRequest::Complete => break,
            }
        }

        // === Payload request ===
        loop {
            match &mut self.payload_request {
                PayloadRequest::WaitingForBlock => {
                    // Same fallback as the data stream: the block may be in the availability
                    // checker via gossip before this lookup downloads it.
                    let block_metadata = self
                        .block_request
                        .peek_block()
                        .map(|b| (b.slot(), b.num_expected_blobs()))
                        .or_else(|| match cx.chain.get_block_process_status(&block_root) {
                            BlockProcessStatus::NotValidated(block, _)
                            | BlockProcessStatus::ExecutionValidated(block) => {
                                Some((block.slot(), block.num_expected_blobs()))
                            }
                            BlockProcessStatus::Unknown => None,
                        });
                    if let Some((slot, expected_blobs)) = block_metadata {
                        self.create_payload_request(slot, expected_blobs, cx);
                    } else {
                        break;
                    }
                }
                PayloadRequest::Downloading { state, .. } => {
                    if !self.payload_peers.read().is_empty() {
                        let peers = self.payload_peers.clone();
                        match cx.payload_lookup_request(id, peers, block_root) {
                            Ok(LookupRequestResult::RequestSent(req_id)) => {
                                state.on_download_start(req_id)?;
                            }
                            Ok(LookupRequestResult::NoRequestNeeded(_reason)) => {
                                // Envelope is already known (e.g. imported by gossip). Skip
                                // download and mark payload stream complete.
                                self.payload_request = PayloadRequest::Complete;
                                continue;
                            }
                            Ok(LookupRequestResult::Pending(reason)) => {
                                state.update_awaiting_download_status(reason);
                            }
                            Err(e) => {
                                return Err(LookupRequestError::SendFailedNetwork(e));
                            }
                        }
                    }
                    if let Some(result) = state.take_download_result() {
                        self.payload_request = PayloadRequest::Downloaded {
                            peer_group: result.peer_group,
                        };
                    } else {
                        break;
                    }
                }
                PayloadRequest::Downloaded { peer_group } => {
                    if !self.block_request.is_complete() {
                        break;
                    }
                    // TODO(gloas): send payload for processing
                    // cx.send_payload_for_processing(...)
                    let peer_group = peer_group.clone();
                    self.payload_request = PayloadRequest::Processing { peer_group };
                    // Processing needs an async trigger.
                    break;
                }
                PayloadRequest::Processing { .. } | PayloadRequest::Complete => break,
            }
        }

        // === Check completion ===
        if self.block_request.is_complete()
            && matches!(self.data_request, DataRequest::Complete)
            && matches!(self.payload_request, PayloadRequest::Complete)
        {
            return Ok(LookupResult::Completed);
        }

        Ok(LookupResult::Pending)
    }

    /// Create data request based on the downloaded block's content and fork.
    fn create_data_request(
        &mut self,
        slot: Slot,
        expected_blobs: usize,
        cx: &SyncNetworkContext<T>,
    ) {
        let block_fork = cx.chain.spec.fork_name_at_slot::<T::EthSpec>(slot);

        match block_fork {
            ForkName::Base | ForkName::Altair | ForkName::Bellatrix | ForkName::Capella => {
                self.data_request = DataRequest::Complete;
            }
            ForkName::Deneb | ForkName::Electra => {
                if expected_blobs > 0 {
                    self.data_request = DataRequest::Downloading(DataDownload::Blobs {
                        block_root: self.block_root,
                        expected_blobs,
                        state: SingleLookupRequestState::new(),
                    });
                    // Pre-Gloas: data peers = block peers (always need data with block)
                    self.data_peers = self.peers.clone();
                } else {
                    self.data_request = DataRequest::Complete;
                }
            }
            ForkName::Fulu => {
                if expected_blobs > 0 {
                    self.data_request = DataRequest::Downloading(DataDownload::Columns {
                        block_root: self.block_root,
                        state: SingleLookupRequestState::new(),
                    });
                    // Pre-Gloas: data peers = block peers
                    self.data_peers = self.peers.clone();
                } else {
                    self.data_request = DataRequest::Complete;
                }
            }
            ForkName::Gloas => {
                if expected_blobs > 0 {
                    self.data_request = DataRequest::Downloading(DataDownload::Columns {
                        block_root: self.block_root,
                        state: SingleLookupRequestState::new(),
                    });
                    // Gloas: data peers start at 0, populated when children arrive
                } else {
                    self.data_request = DataRequest::Complete;
                }
            }
        }
    }

    /// Create payload request based on the downloaded block's content and fork.
    fn create_payload_request(
        &mut self,
        slot: Slot,
        expected_blobs: usize,
        cx: &SyncNetworkContext<T>,
    ) {
        let block_fork = cx.chain.spec.fork_name_at_slot::<T::EthSpec>(slot);

        match block_fork {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => {
                self.payload_request = PayloadRequest::Complete;
            }
            ForkName::Gloas => {
                if expected_blobs > 0 {
                    self.payload_request = PayloadRequest::Downloading {
                        block_root: self.block_root,
                        state: SingleLookupRequestState::new(),
                    };
                    // Payload peers start at 0, download gated until children provide peers
                } else {
                    // Empty blocks have no payload and no data — both are Done
                    self.payload_request = PayloadRequest::Complete;
                }
            }
        }
    }

    // -- Processing result handlers --

    /// Handle block processing result. Advances the lookup state machine.
    pub fn on_block_processing_result(
        &mut self,
        result_is_ok: bool,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let BlockRequest::Processing { block, peer } = &self.block_request else {
            return Err(LookupRequestError::BadState(
                "block processing result but not in Processing state".to_owned(),
            ));
        };
        if result_is_ok {
            let block = block.clone();
            let peer = Some(*peer);
            self.block_request = BlockRequest::Complete { block, peer };
            self.continue_requests(cx)
        } else {
            // Block processing failed — reset everything and retry from scratch
            self.reset_requests();
            self.continue_requests(cx)
        }
    }

    /// Handle data processing result (blobs or custody columns imported).
    pub fn on_data_processing_result(
        &mut self,
        result_is_ok: bool,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        if !matches!(self.data_request, DataRequest::Processing { .. }) {
            return Err(LookupRequestError::BadState(
                "data processing result but not in Processing state".to_owned(),
            ));
        }
        if result_is_ok {
            self.data_request = DataRequest::Complete;
            self.continue_requests(cx)
        } else {
            // Data processing failed — bump the shared processing-failure counter so the
            // retry is bounded against `SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS`, then reset.
            self.failed_processing = self.failed_processing.saturating_add(1);
            self.reset_data_request();
            self.continue_requests(cx)
        }
    }

    /// Handle payload processing result.
    #[allow(dead_code)]
    pub fn on_payload_processing_result(
        &mut self,
        result_is_ok: bool,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        if !matches!(self.payload_request, PayloadRequest::Processing { .. }) {
            return Err(LookupRequestError::BadState(
                "payload processing result but not in Processing state".to_owned(),
            ));
        }
        if result_is_ok {
            self.payload_request = PayloadRequest::Complete;
            self.continue_requests(cx)
        } else {
            // Bump the shared processing-failure counter to bound retries.
            self.failed_processing = self.failed_processing.saturating_add(1);
            self.payload_request = PayloadRequest::Downloading {
                block_root: self.block_root,
                state: SingleLookupRequestState::new_with_processing_failures(
                    self.failed_processing,
                ),
            };
            self.continue_requests(cx)
        }
    }

    /// Reset data request to a fresh download, preserving the download kind.
    fn reset_data_request(&mut self) {
        let kind = match &self.data_request {
            DataRequest::Downloading(dl) => match dl {
                DataDownload::Blobs { expected_blobs, .. } => Some(DataDownloadKind::Blobs {
                    expected_blobs: *expected_blobs,
                }),
                DataDownload::Columns { .. } => Some(DataDownloadKind::Columns),
            },
            DataRequest::Downloaded { data, .. } => Some(data.kind()),
            DataRequest::Processing { kind, .. } => Some(*kind),
            DataRequest::WaitingForBlock | DataRequest::Complete => None,
        };
        if let Some(kind) = kind {
            self.data_request = DataRequest::Downloading(
                kind.into_fresh_download(self.block_root, self.failed_processing),
            );
        }
    }

    // -- Download response handlers --

    /// Handle a block download response. Updates download state and advances the lookup.
    #[allow(clippy::type_complexity)]
    pub fn on_block_download_response(
        &mut self,
        req_id: ReqId,
        result: Result<(Arc<SignedBeaconBlock<T::EthSpec>>, PeerGroup, Duration), ()>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let BlockRequest::Downloading { state, .. } = &mut self.block_request else {
            return Err(LookupRequestError::BadState(
                "block response but not downloading".to_owned(),
            ));
        };
        state.on_download_response(req_id, self.block_root, result)?;
        self.continue_requests(cx)
    }

    /// Handle a blob download response. Updates download state and advances the lookup.
    pub fn on_blob_download_response(
        &mut self,
        req_id: ReqId,
        result: Result<(FixedBlobSidecarList<T::EthSpec>, PeerGroup, Duration), ()>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let DataRequest::Downloading(DataDownload::Blobs { state, .. }) = &mut self.data_request
        else {
            return Err(LookupRequestError::BadState(
                "blob response but not downloading blobs".to_owned(),
            ));
        };
        state.on_download_response(req_id, self.block_root, result)?;
        self.continue_requests(cx)
    }

    /// Handle a custody columns download response. Updates download state and advances the lookup.
    pub fn on_custody_download_response(
        &mut self,
        req_id: ReqId,
        result: Result<(DataColumnSidecarList<T::EthSpec>, PeerGroup, Duration), ()>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let DataRequest::Downloading(DataDownload::Columns { state, .. }) = &mut self.data_request
        else {
            return Err(LookupRequestError::BadState(
                "custody response but not downloading columns".to_owned(),
            ));
        };
        state.on_download_response(req_id, self.block_root, result)?;
        self.continue_requests(cx)
    }

    /// Handle a payload envelope download response. Updates download state and advances the lookup.
    #[allow(clippy::type_complexity)]
    pub fn on_payload_download_response(
        &mut self,
        req_id: ReqId,
        result: Result<
            (
                Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
                PeerGroup,
                Duration,
            ),
            (),
        >,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let PayloadRequest::Downloading { state, .. } = &mut self.payload_request else {
            return Err(LookupRequestError::BadState(
                "payload envelope response but not downloading payload".to_owned(),
            ));
        };
        state.on_download_response(req_id, self.block_root, result)?;
        self.continue_requests(cx)
    }

    /// Get all unique peers that claim to have imported this set of block components
    pub fn all_peers(&self) -> Vec<PeerId> {
        self.peers.read().iter().copied().collect()
    }

    /// Add peer to all request states. The peer must be able to serve this request.
    /// Returns true if the peer was newly inserted into any peer set.
    pub fn add_peer(&mut self, peer_id: PeerId, peer_type: &PeerType) -> bool {
        let mut added = false;
        if peer_type.payload {
            added |= self.payload_peers.write().insert(peer_id);
        }
        if peer_type.data {
            added |= self.data_peers.write().insert(peer_id);
        }
        added |= self.peers.write().insert(peer_id);
        added
    }

    /// Remove peer from available peers.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
        self.data_peers.write().remove(peer_id);
        self.payload_peers.write().remove(peer_id);
    }

    /// Returns true if this lookup has zero peers
    pub fn has_no_peers(&self) -> bool {
        self.peers.read().is_empty()
    }
}

pub struct PeerType {
    pub data: bool,
    pub payload: bool,
}

// === Generic download state machine ===

#[derive(IntoStaticStr)]
enum DownloadState<T: Clone> {
    AwaitingDownload(/* reason */ &'static str),
    Downloading(ReqId),
    Downloaded(DownloadResult<T>),
    /// Download completed with no request needed (e.g. all components already imported)
    Completed(/* reason */ &'static str),
}

/// Object representing the state of a single block or blob lookup request.
#[derive(Debug)]
struct SingleLookupRequestState<T: Clone> {
    state: DownloadState<T>,
    failed_processing: u8,
    failed_downloading: u8,
}

impl<T: Clone> SingleLookupRequestState<T> {
    fn new() -> Self {
        Self {
            state: DownloadState::AwaitingDownload("not started"),
            failed_processing: 0,
            failed_downloading: 0,
        }
    }

    fn new_with_processing_failures(failed_processing: u8) -> Self {
        Self {
            state: DownloadState::AwaitingDownload("reset after processing failure"),
            failed_processing,
            failed_downloading: 0,
        }
    }

    fn is_awaiting_download(&self) -> bool {
        matches!(self.state, DownloadState::AwaitingDownload { .. })
    }

    fn is_completed(&self) -> bool {
        matches!(self.state, DownloadState::Completed { .. })
    }

    /// Drive download: check max attempts, issue request, handle result.
    fn make_request(
        &mut self,
        request_fn: impl FnOnce() -> Result<LookupRequestResult, RpcRequestSendError>,
    ) -> Result<(), LookupRequestError> {
        if !self.is_awaiting_download() {
            return Ok(());
        }
        if self.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
            let cannot_process = self.more_failed_processing_attempts();
            return Err(LookupRequestError::TooManyAttempts { cannot_process });
        }
        match request_fn().map_err(LookupRequestError::SendFailedNetwork)? {
            LookupRequestResult::RequestSent(req_id) => self.on_download_start(req_id)?,
            LookupRequestResult::NoRequestNeeded(reason) => self.on_completed_request(reason)?,
            LookupRequestResult::Pending(reason) => self.update_awaiting_download_status(reason),
        }
        Ok(())
    }

    fn is_awaiting_event(&self) -> bool {
        matches!(self.state, DownloadState::Downloading { .. })
    }

    fn peek_downloaded_data(&self) -> Option<&T> {
        match &self.state {
            DownloadState::Downloaded(data) => Some(&data.value),
            _ => None,
        }
    }

    fn peek_downloaded_peer_group(&self) -> Option<&PeerGroup> {
        match &self.state {
            DownloadState::Downloaded(data) => Some(&data.peer_group),
            _ => None,
        }
    }

    /// Take the download result out, transitioning back to AwaitingDownload.
    /// Returns None if not in Downloaded state.
    fn take_download_result(&mut self) -> Option<DownloadResult<T>> {
        let old = std::mem::replace(&mut self.state, DownloadState::AwaitingDownload("taken"));
        if let DownloadState::Downloaded(result) = old {
            Some(result)
        } else {
            self.state = old;
            None
        }
    }

    fn insert_verified_response(&mut self, result: DownloadResult<T>) -> bool {
        if let DownloadState::AwaitingDownload { .. } = &self.state {
            self.state = DownloadState::Downloaded(result);
            true
        } else {
            false
        }
    }

    fn update_awaiting_download_status(&mut self, new_status: &'static str) {
        if let DownloadState::AwaitingDownload(status) = &mut self.state {
            *status = new_status;
        }
    }

    fn on_download_start(&mut self, req_id: ReqId) -> Result<(), LookupRequestError> {
        match &self.state {
            DownloadState::AwaitingDownload { .. } => {
                self.state = DownloadState::Downloading(req_id);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_start expected AwaitingDownload got {other}"
            ))),
        }
    }

    /// Handle a download response: dispatch success or failure based on result.
    fn on_download_response(
        &mut self,
        req_id: ReqId,
        block_root: Hash256,
        result: Result<(T, PeerGroup, Duration), ()>,
    ) -> Result<(), LookupRequestError> {
        match result {
            Ok((value, peer_group, seen_timestamp)) => self.on_download_success(
                req_id,
                DownloadResult {
                    value,
                    block_root,
                    seen_timestamp,
                    peer_group,
                },
            ),
            Err(()) => self.on_download_failure(req_id),
        }
    }

    fn on_download_failure(&mut self, req_id: ReqId) -> Result<(), LookupRequestError> {
        match &self.state {
            DownloadState::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(LookupRequestError::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.failed_downloading = self.failed_downloading.saturating_add(1);
                self.state = DownloadState::AwaitingDownload("not started");
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_failure expected Downloading got {other}"
            ))),
        }
    }

    fn on_download_success(
        &mut self,
        req_id: ReqId,
        result: DownloadResult<T>,
    ) -> Result<(), LookupRequestError> {
        match &self.state {
            DownloadState::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(LookupRequestError::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.state = DownloadState::Downloaded(result);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_success expected Downloading got {other}"
            ))),
        }
    }

    fn on_completed_request(&mut self, reason: &'static str) -> Result<(), LookupRequestError> {
        match &self.state {
            DownloadState::AwaitingDownload { .. } => {
                self.state = DownloadState::Completed(reason);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_completed_request expected AwaitingDownload got {other}"
            ))),
        }
    }

    fn failed_attempts(&self) -> u8 {
        self.failed_processing + self.failed_downloading
    }

    fn more_failed_processing_attempts(&self) -> bool {
        self.failed_processing >= self.failed_downloading
    }
}

impl<T: Clone> std::fmt::Display for DownloadState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(self))
    }
}

impl<T: Clone> std::fmt::Debug for DownloadState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwaitingDownload(reason) => write!(f, "AwaitingDownload({})", reason),
            Self::Downloading(req_id) => write!(f, "Downloading({:?})", req_id),
            Self::Downloaded(_) => write!(f, "Downloaded()"),
            Self::Completed(reason) => write!(f, "Completed({})", reason),
        }
    }
}

fn fmt_peer_set_as_len(
    peer_set: &Arc<RwLock<HashSet<PeerId>>>,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{}", peer_set.read().len())
}
