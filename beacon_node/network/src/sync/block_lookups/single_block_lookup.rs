use super::{BlockComponent, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS};
use crate::sync::block_lookups::{
    BlobDownloadResponse, BlockDownloadResponse, CustodyDownloadResponse, PayloadDownloadResponse,
};
use crate::sync::manager::{BlockProcessType, BlockProcessingResult};
use crate::sync::network_context::{
    LookupRequestResult, PeerGroup, ReqId, RpcRequestSendError, RpcResponseError,
    SendErrorProcessor, SyncNetworkContext,
};
use beacon_chain::BlockProcessStatus;
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::{BeaconChainTypes, ExecutionStatus};
use educe::Educe;
use lighthouse_network::service::api_types::Id;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Hash256;
use strum::IntoStaticStr;
use tracing::{Span, debug, debug_span};
use types::data::FixedBlobSidecarList;
use types::{
    ChainSpec, DataColumnSidecarList, EthSpec, ExecutionBlockHash, ForkName, SignedBeaconBlock,
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
    gloas_bid_parent_hash: Option<ExecutionBlockHash>,
}

impl AwaitingParent {
    pub fn is_parent_imported<T: BeaconChainTypes>(&self, cx: &mut SyncNetworkContext<T>) -> bool {
        if self.parent_is_genesis() {
            // Zero hash is the parent of the genesis block — not a real block, so no
            // parent-known check is needed. Fall through to send the block for processing.
            return true;
        }

        if let Some(parent_block) = cx
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .get_block(&self.parent_root)
        {
            if parent_block.slot == cx.spec().genesis_slot {
                // The genesis block is always imported by definition
                return true;
            }

            if let Some(gloas_bid_parent_hash) = self.gloas_bid_parent_hash {
                // Post-gloas block, check if it's FULL or EMPTY
                let parent_hash = match parent_block.execution_status {
                    ExecutionStatus::Valid(hash) => hash,
                    ExecutionStatus::Invalid(hash) => hash,
                    ExecutionStatus::Optimistic(hash) => hash,
                    ExecutionStatus::Irrelevant(_) => {
                        if let Some(hash) = parent_block.execution_payload_block_hash {
                            hash
                        } else {
                            // This should never happen!
                            return false;
                        }
                    }
                };
                let is_full = gloas_bid_parent_hash == parent_hash;
                if is_full {
                    // Post-gloas block FULL, we need the payload to be imported first
                    cx.chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .is_payload_received(&self.parent_root)
                } else {
                    // Post-gloas block EMPTY, and block is imported
                    true
                }
            } else {
                // Pre-gloas block
                true
            }
        } else {
            // Parent is unknown
            false
        }
    }

    pub fn parent_is_genesis(&self) -> bool {
        self.parent_root == Hash256::ZERO
    }

    pub fn parent_root(&self) -> Hash256 {
        self.parent_root
    }

    pub fn gloas_bid_parent_hash(&self) -> Option<ExecutionBlockHash> {
        self.gloas_bid_parent_hash
    }

    pub fn from_block<E: EthSpec>(block: &SignedBeaconBlock<E>) -> Self {
        Self {
            parent_root: block.message().parent_root(),
            gloas_bid_parent_hash: if let Ok(bid) =
                block.message().body().signed_execution_payload_bid()
            {
                Some(bid.message.parent_block_hash)
            } else {
                None
            },
        }
    }

    pub fn from_block_header<E: EthSpec>(
        parent_root: Hash256,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Self, String> {
        if spec.fork_name_at_slot::<E>(slot).gloas_enabled() {
            Err("AwaitingParent can not be created from a Gloas header".to_owned())
        } else {
            Ok(Self {
                parent_root,
                gloas_bid_parent_hash: None,
            })
        }
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

    /// Best-effort lookup of the block: prefer the in-flight download if we have it; otherwise
    /// fall back to the chain's processing-status cache (the block may have arrived via gossip /
    /// HTTP API before this lookup downloads it).
    fn peek_block_or_cached<T: BeaconChainTypes<EthSpec = E>>(
        &self,
        block_root: Hash256,
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<Arc<SignedBeaconBlock<E>>> {
        self.peek_block().cloned().or_else(|| {
            match cx.chain.get_block_process_status(&block_root) {
                BlockProcessStatus::NotValidated(block, _)
                | BlockProcessStatus::ExecutionValidated(block) => Some(block),
                BlockProcessStatus::Unknown => None,
            }
        })
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
struct DataRequest<E: EthSpec> {
    peers: PeerSet,
    state: DataRequestState<E>,
}

#[derive(Debug)]
enum DataRequestState<E: EthSpec> {
    /// Data downloading or awaiting download
    Downloading(DataDownload<E>),
    /// Data downloaded, waiting for block processing to complete before import
    Downloaded {
        data: DownloadedData<E>,
        peer_group: PeerGroup,
    },
    /// Data sent for processing, awaiting result
    Processing { peer_group: PeerGroup },
    /// Data processing complete (or no data needed)
    Complete,
}

impl<E: EthSpec> DataRequest<E> {
    fn is_complete(&self) -> bool {
        matches!(self.state, DataRequestState::Complete)
    }
}

impl<E: EthSpec> DataRequestState<E> {
    fn is_awaiting_event(&self) -> bool {
        match &self {
            Self::Downloading(dl) => dl.is_awaiting_event(),
            Self::Processing { .. } => true,
            _ => false,
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
    fn send_request<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        id: Id,
        peers: PeerSet,
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
                state.make_request(|| cx.blob_lookup_request(id, peers, br, eb))
            }
            DataDownload::Columns { block_root, state } => {
                let br = *block_root;
                state.make_request(|| cx.custody_lookup_request(id, br, peers))
            }
        }
    }

    fn is_completed(&self) -> bool {
        match self {
            DataDownload::Blobs { state, .. } => state.is_completed(),
            DataDownload::Columns { state, .. } => state.is_completed(),
        }
    }

    fn take_download_result(&mut self) -> Option<(DownloadedData<E>, PeerGroup)> {
        match self {
            DataDownload::Blobs { state, .. } => state
                .take_download_result()
                .map(|r| (DownloadedData::Blobs(r.value), r.peer_group)),
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
}

/// Downloaded data, waiting to be sent for processing
#[derive(Debug)]
enum DownloadedData<E: EthSpec> {
    Blobs(FixedBlobSidecarList<E>),
    Columns(DataColumnSidecarList<E>),
}

impl<E: EthSpec> DownloadedData<E> {
    fn send_for_processing<T: BeaconChainTypes<EthSpec = E>>(
        &self,
        id: Id,
        block_root: Hash256,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), SendErrorProcessor> {
        match self {
            DownloadedData::Blobs(blobs) => {
                cx.send_blobs_for_processing(id, block_root, blobs.clone(), Duration::ZERO)
            }
            DownloadedData::Columns(columns) => cx.send_custody_columns_for_processing(
                id,
                block_root,
                columns.clone(),
                Duration::ZERO,
                BlockProcessType::SingleCustodyColumn(id),
            ),
        }
    }
}

// === Payload request: WaitingForBlock → Downloading → Downloaded → Processing → Complete ===

#[derive(Debug)]
struct PayloadRequest<E: EthSpec> {
    peers: PeerSet,
    state: PayloadRequestState<E>,
}

#[derive(Educe)]
#[educe(Debug)]
enum PayloadRequestState<E: EthSpec> {
    Downloading {
        state: SingleLookupRequestState<Arc<SignedExecutionPayloadEnvelope<E>>>,
    },
    Downloaded {
        #[educe(Debug(ignore))]
        envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
        peer_group: PeerGroup,
    },
    Processing {
        peer_group: PeerGroup,
    },
    /// Payload processed, or no payload needed.
    Complete,
}

impl<E: EthSpec> PayloadRequest<E> {
    fn is_complete(&self) -> bool {
        if !self.state.is_awaiting_event() && self.peers.read().is_empty() {
            return true;
        }
        matches!(self.state, PayloadRequestState::Complete)
    }
}

impl<E: EthSpec> PayloadRequestState<E> {
    fn is_awaiting_event(&self) -> bool {
        match self {
            Self::Downloading { state, .. } => state.is_awaiting_event(),
            Self::Processing { .. } => true,
            _ => false,
        }
    }
}

impl<E: EthSpec> DataRequestState<E> {
    fn new(slot: Slot, block_root: Hash256, expected_blobs: usize, spec: &ChainSpec) -> Self {
        let block_fork = spec.fork_name_at_slot::<E>(slot);

        match block_fork {
            ForkName::Base | ForkName::Altair | ForkName::Bellatrix | ForkName::Capella => {
                Self::Complete
            }
            ForkName::Deneb | ForkName::Electra => {
                if expected_blobs > 0 {
                    Self::Downloading(DataDownload::Blobs {
                        block_root,
                        expected_blobs,
                        state: SingleLookupRequestState::new(),
                    })
                } else {
                    Self::Complete
                }
            }
            ForkName::Fulu => {
                if expected_blobs > 0 {
                    Self::Downloading(DataDownload::Columns {
                        block_root,
                        state: SingleLookupRequestState::new(),
                    })
                } else {
                    Self::Complete
                }
            }
            ForkName::Gloas => {
                if expected_blobs > 0 {
                    Self::Downloading(DataDownload::Columns {
                        block_root,
                        state: SingleLookupRequestState::new(),
                    })
                    // Gloas: data peers start at 0, populated when children arrive
                } else {
                    Self::Complete
                }
            }
        }
    }
}

impl<E: EthSpec> PayloadRequestState<E> {
    /// Create payload request based on the downloaded block's content and fork.
    fn new(slot: Slot, spec: &ChainSpec) -> Self {
        let block_fork = spec.fork_name_at_slot::<E>(slot);

        match block_fork {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => Self::Complete,
            ForkName::Gloas => Self::Downloading {
                state: SingleLookupRequestState::new(),
            },
        }
    }
}

type PeerSet = Arc<RwLock<HashSet<PeerId>>>;
type GloasChildPeers = Arc<RwLock<HashMap<ExecutionBlockHash, PeerSet>>>;

// === SingleBlockLookup — three independent requests ===

#[derive(Educe)]
#[educe(Debug(bound(T: BeaconChainTypes)))]
pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    block_root: Hash256,

    // Block request — always present
    block_request: BlockRequest<T::EthSpec>,

    // Data request — starts as WaitingForBlock, set after block downloaded
    data_request: Option<DataRequest<T::EthSpec>>,

    // Payload request — starts as WaitingForBlock, set after block downloaded
    payload_request: Option<PayloadRequest<T::EthSpec>>,

    // Peer sets.
    //
    // `Arc<RwLock<..>>` is required by `ActiveCustodyRequest` (columns only), which lives
    // in `SyncNetworkContext` and needs to observe peers being added/removed at runtime
    // while it's in flight. `data_peers` and `payload_peers` use the same shape purely for
    // consistency so all three sets plug into the same `add_peer` / `remove_peer` surface.
    /// Peers for block download (also used for data in pre-Gloas forks).
    #[educe(Debug(method(fmt_peer_set_as_len)))]
    peers: PeerSet,
    /// Peers for payload download (0 initially, Gloas only).
    #[educe(Debug(method(fmt_peer_map_as_len)))]
    gloas_child_peers: GloasChildPeers,

    // Parent tracking
    awaiting_parent: Option<AwaitingParent>,
    created: Instant,
    pub(crate) span: Span,

    // Retry tracking
    failed_processing: u8,
}

pub enum PeerType {
    PreGloas,
    PostGloas(ExecutionBlockHash),
}

impl PeerType {
    pub fn from_awaiting_parent(awaiting_parent: AwaitingParent) -> Self {
        match awaiting_parent.gloas_bid_parent_hash() {
            Some(parent_hash) => Self::PostGloas(parent_hash),
            None => Self::PreGloas,
        }
    }
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

        let block_peers: PeerSet = Arc::new(RwLock::new(peers.iter().copied().collect()));
        let mut gloas_child_peers = HashMap::new();

        match peer_type {
            PeerType::PreGloas => {}
            PeerType::PostGloas(execution_hash) => {
                gloas_child_peers.insert(*execution_hash, block_peers.clone());
            }
        }

        Self {
            id,
            block_root: requested_block_root,
            block_request: BlockRequest::new(requested_block_root),
            data_request: None,
            payload_request: None,
            peers: block_peers,
            gloas_child_peers: Arc::new(RwLock::new(gloas_child_peers)),
            awaiting_parent,
            created: Instant::now(),
            failed_processing: 0,
            span: lookup_span,
        }
    }

    /// Reset the status of all requests (used on block processing failure)
    pub fn reset_requests(&mut self) {
        // Increment processing failure counter (we're resetting due to processing error)
        self.failed_processing = self.failed_processing.saturating_add(1);
        // Reset to fresh Downloading state with the updated counter
        self.block_request =
            BlockRequest::new_with_processing_failures(self.block_root, self.failed_processing);
        self.data_request = None;
        self.payload_request = None;
    }

    /// Return the slot of this lookup's block if it's currently cached
    pub fn peek_downloaded_block_slot(&self) -> Option<Slot> {
        self.block_request.peek_slot()
    }

    /// Get the block root that is being requested.
    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    /// Check the block root matches the requested block root.
    pub fn is_for_block(&self, block_root: Hash256) -> bool {
        self.block_root == block_root
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
            BlockComponent::Sidecar => {
                // For now ignore single blobs and columns, as the blob request state assumes all
                // blobs are attributed to the same peer = the peer serving the remaining blobs.
                false
            }
        }
    }

    /// Returns true if this request is expecting some event to make progress
    pub fn is_awaiting_event(&self) -> bool {
        self.awaiting_parent.is_some()
            || self.block_request.is_awaiting_event()
            || match &self.data_request {
                Some(request) => request.state.is_awaiting_event(),
                None => true,
            }
            || match &self.payload_request {
                Some(request) => request.state.is_awaiting_event(),
                None => true,
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
                        // Block is fully execution-validated and cached in the da_checker or fully
                        // imported.
                        // The block MUST be somewhere... and the code below needs to block to know
                        // if it should fetch data
                        let block = match cx.chain.get_block_process_status(&block_root) {
                            BlockProcessStatus::NotValidated(block, _)
                            | BlockProcessStatus::ExecutionValidated(block) => block,
                            BlockProcessStatus::Unknown => {
                                // Race: the block was imported into fork-choice between
                                // `block_lookup_request` and this check. All components must
                                // have landed with it, so the lookup has nothing left to do.
                                panic!("We have to find the block somewhere");
                            }
                        };
                        // No peer to attribute against on a cache hit.
                        self.block_request = BlockRequest::Complete { block, peer: None };
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

                    let awaiting_parent = AwaitingParent::from_block(block);

                    if !awaiting_parent.is_parent_imported(cx) {
                        self.awaiting_parent = Some(awaiting_parent);
                        return Ok(LookupResult::ParentUnknown {
                            awaiting_parent,
                            block_root: self.block_root,
                            peers: self.all_peers(),
                        });
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
                // None = waiting for block
                None => {
                    let Some(block) = self.block_request.peek_block_or_cached(block_root, cx)
                    else {
                        break;
                    };
                    let peers = self.get_data_peers::<T::EthSpec>(&block);
                    self.data_request = Some(DataRequest {
                        peers,
                        state: DataRequestState::new(
                            block.slot(),
                            self.block_root,
                            block.num_expected_blobs(),
                            cx.spec(),
                        ),
                    });
                }
                Some(request) => match &mut request.state {
                    DataRequestState::Downloading(dl) => {
                        // Custody column downloads dispatch against the global synced peer pool
                        // inside `ActiveCustodyRequest`, not against `data_peers`. Only gate on
                        // `data_peers` for post-Gloas, where peer sets are strictly partitioned
                        // and no fallback pool exists.
                        dl.send_request(id, request.peers.clone(), cx)?;

                        if dl.is_completed() {
                            // All data already imported (e.g. received via gossip)
                            request.state = DataRequestState::Complete;
                        } else if let Some((data, peer_group)) = dl.take_download_result() {
                            request.state = DataRequestState::Downloaded { data, peer_group };
                        } else {
                            // Wait for data to be downloaded
                            break;
                        }
                    }
                    DataRequestState::Downloaded { data, peer_group } => {
                        data.send_for_processing(id, self.block_root, cx)
                            .map_err(LookupRequestError::SendFailedProcessor)?;
                        let peer_group = peer_group.clone();
                        request.state = DataRequestState::Processing { peer_group };
                        // Processing needs an async trigger.
                        break;
                    }
                    DataRequestState::Processing { .. } | DataRequestState::Complete => break,
                },
            }
        }

        // === Payload request ===
        loop {
            match &mut self.payload_request {
                None => {
                    let Some(block) = self.block_request.peek_block_or_cached(block_root, cx)
                    else {
                        break;
                    };
                    let peers = self.get_data_peers(&block);
                    self.payload_request = Some(PayloadRequest {
                        peers,
                        state: PayloadRequestState::new(block.slot(), cx.spec()),
                    });
                }
                Some(request) => match &mut request.state {
                    PayloadRequestState::Downloading { state, .. } => {
                        // Peers in `request.peers` are those that have signalled they imported a
                        // child of this block whose bid's parent_hash matches our execution_hash —
                        // i.e. they are proven to have the envelope. `make_request` is a no-op if
                        // a request is already in flight, so it's safe to call on every tick.
                        let peers = request.peers.clone();
                        state.make_request(|| cx.payload_lookup_request(id, peers, block_root))?;

                        if state.is_completed() {
                            // Envelope already known to fork-choice (NoRequestNeeded).
                            request.state = PayloadRequestState::Complete;
                            continue;
                        }
                        if let Some(result) = state.take_download_result() {
                            request.state = PayloadRequestState::Downloaded {
                                envelope: result.value,
                                peer_group: result.peer_group,
                            };
                        } else {
                            break;
                        }
                    }
                    PayloadRequestState::Downloaded {
                        envelope,
                        peer_group,
                    } => {
                        if !self.block_request.is_complete() {
                            break;
                        }
                        let envelope = envelope.clone();
                        let peer_group = peer_group.clone();
                        cx.send_payload_for_processing(
                            block_root,
                            envelope,
                            Duration::ZERO,
                            BlockProcessType::SinglePayloadEnvelope(id),
                        )
                        .map_err(LookupRequestError::SendFailedProcessor)?;
                        request.state = PayloadRequestState::Processing { peer_group };
                        // Processing needs an async trigger.
                        break;
                    }
                    PayloadRequestState::Processing { .. } | PayloadRequestState::Complete => break,
                },
            }
        }

        // === Check completion ===
        if self.block_request.is_complete()
            && self.data_request.as_ref().is_some_and(|r| r.is_complete())
            && self
                .payload_request
                .as_ref()
                .is_some_and(|r| r.is_complete())
        {
            return Ok(LookupResult::Completed);
        }

        Ok(LookupResult::Pending)
    }

    fn get_data_peers<E: EthSpec>(&self, block: &SignedBeaconBlock<E>) -> PeerSet {
        if let Ok(bid) = block.message().body().signed_execution_payload_bid() {
            self.gloas_child_peers
                .write()
                .entry(bid.message.block_hash)
                .or_default()
                .clone()
        } else {
            self.peers.clone()
        }
    }

    // -- Processing result handlers --

    /// Handle block processing result. Advances the lookup state machine.
    pub fn on_block_processing_result(
        &mut self,
        result: BlockProcessingResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let BlockRequest::Processing { block, peer } = &self.block_request else {
            return Err(LookupRequestError::BadState(
                "block processing result but not in Processing state".to_owned(),
            ));
        };
        let block_peer = *peer;

        match result {
            BlockProcessingResult::Imported(_) => {
                let block = block.clone();
                self.block_request = BlockRequest::Complete {
                    block,
                    peer: Some(block_peer),
                };
                self.continue_requests(cx)
            }
            BlockProcessingResult::Error { penalty, reason } => {
                if let Some((action, whom)) = penalty {
                    whom.apply(action, &PeerGroup::from_single(block_peer), reason, cx);
                }
                // Block processing failed — reset everything and retry from scratch.
                self.reset_requests();
                self.continue_requests(cx)
            }
        }
    }

    /// Handle data processing result (blobs or custody columns imported).
    pub fn on_data_processing_result(
        &mut self,
        result: BlockProcessingResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let Some(DataRequest {
            state: DataRequestState::Processing { peer_group },
            ..
        }) = &self.data_request
        else {
            return Err(LookupRequestError::BadState(
                "data processing result but not in Processing state".to_owned(),
            ));
        };
        let peer_group = peer_group.clone();

        match result {
            BlockProcessingResult::Imported(_) => {
                if let Some(req) = &mut self.data_request {
                    req.state = DataRequestState::Complete;
                }
                self.continue_requests(cx)
            }
            BlockProcessingResult::Error { penalty, reason } => {
                if let Some((action, whom)) = penalty {
                    whom.apply(action, &peer_group, reason, cx);
                }
                // Data processing failed — bump the shared processing-failure counter and rebuild
                // the data request so retries stay bounded against MAX_ATTEMPTS.
                self.failed_processing = self.failed_processing.saturating_add(1);
                self.data_request = None;
                self.continue_requests(cx)
            }
        }
    }

    /// Handle payload envelope processing result (Gloas only).
    pub fn on_payload_processing_result(
        &mut self,
        result: BlockProcessingResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let Some(PayloadRequest {
            state: PayloadRequestState::Processing { peer_group },
            ..
        }) = &self.payload_request
        else {
            return Err(LookupRequestError::BadState(
                "payload processing result but not in Processing state".to_owned(),
            ));
        };
        let peer_group = peer_group.clone();

        match result {
            BlockProcessingResult::Imported(_) => {
                if let Some(req) = &mut self.payload_request {
                    req.state = PayloadRequestState::Complete;
                }
                self.continue_requests(cx)
            }
            BlockProcessingResult::Error { penalty, reason } => {
                if let Some((action, whom)) = penalty {
                    whom.apply(action, &peer_group, reason, cx);
                }
                // Bump the shared processing-failure counter so retries stay bounded against
                // MAX_ATTEMPTS, then transition back to Downloading to redownload from another peer.
                self.failed_processing = self.failed_processing.saturating_add(1);
                if let Some(req) = &mut self.payload_request {
                    req.state = PayloadRequestState::Downloading {
                        state: SingleLookupRequestState::new_with_processing_failures(
                            self.failed_processing,
                        ),
                    };
                }
                self.continue_requests(cx)
            }
        }
    }

    // -- Download response handlers --

    /// Handle a block download response. Updates download state and advances the lookup.
    pub fn on_block_download_response(
        &mut self,
        req_id: ReqId,
        result: BlockDownloadResponse<T::EthSpec>,
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
        result: BlobDownloadResponse<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let Some(DataRequest {
            state: DataRequestState::Downloading(DataDownload::Blobs { state, .. }),
            ..
        }) = &mut self.data_request
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
        result: CustodyDownloadResponse<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let Some(DataRequest {
            state: DataRequestState::Downloading(DataDownload::Columns { state, .. }),
            ..
        }) = &mut self.data_request
        else {
            return Err(LookupRequestError::BadState(
                "custody response but not downloading columns".to_owned(),
            ));
        };
        state.on_download_response(req_id, self.block_root, result)?;
        self.continue_requests(cx)
    }

    /// Handle a payload envelope download response. Updates download state and advances the lookup.
    pub fn on_payload_download_response(
        &mut self,
        req_id: ReqId,
        result: PayloadDownloadResponse<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let Some(PayloadRequest {
            state: PayloadRequestState::Downloading { state, .. },
            ..
        }) = &mut self.payload_request
        else {
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

        match peer_type {
            PeerType::PostGloas(execution_hash) => {
                // This peer claims to have imported a child of this block with parent_hash. We
                // can't know whether the child is full or empty until we know the payload hash of
                // this lookup.
                added |= self
                    .gloas_child_peers
                    .write()
                    .entry(*execution_hash)
                    .or_default()
                    .write()
                    .insert(peer_id);
            }
            PeerType::PreGloas => {}
        }

        // Always add to the main block peers
        added |= self.peers.write().insert(peer_id);
        added
    }

    /// Remove peer from available peers.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
        for set in self.gloas_child_peers.write().values_mut() {
            set.write().remove(peer_id);
        }
    }

    /// Returns true if this lookup has zero peers
    pub fn has_peers(&self) -> bool {
        if !self.peers.read().is_empty() {
            return true;
        }

        let gloas_child_peers = self.gloas_child_peers.read();
        !gloas_child_peers.is_empty()
            && gloas_child_peers.values().any(|set| !set.read().is_empty())
    }
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
        result: Result<(T, PeerGroup, Duration), RpcResponseError>,
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
            Err(_) => self.on_download_failure(req_id),
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

impl std::fmt::Display for AwaitingParent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.gloas_bid_parent_hash {
            Some(parent_hash) => write!(f, "{}/{}", self.parent_root, parent_hash),
            None => write!(f, "{}", self.parent_root),
        }
    }
}

fn fmt_peer_set_as_len(
    peer_set: &PeerSet,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{}", peer_set.read().len())
}

fn fmt_peer_map_as_len(
    peer_map: &GloasChildPeers,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    let total = peer_map
        .read()
        .values()
        .map(|set| set.read().len())
        .sum::<usize>();
    write!(f, "{}", total)
}
