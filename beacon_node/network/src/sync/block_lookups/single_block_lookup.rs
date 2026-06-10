use super::{BlockComponent, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS};
use crate::network_beacon_processor::BlockProcessingResult;
use crate::sync::block_lookups::{
    BlockDownloadResponse, CustodyDownloadResponse, PayloadDownloadResponse,
};
use crate::sync::manager::BlockProcessType;
use crate::sync::network_context::{
    LookupRequestResult, PeerGroup, ReqId, RpcRequestSendError, RpcResponseError,
    SendErrorProcessor, SyncNetworkContext,
};
use beacon_chain::BeaconChainTypes;
use beacon_chain::block_verification_types::AsBlock;
use educe::Educe;
use lighthouse_network::service::api_types::Id;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Hash256;
use strum::IntoStaticStr;
use tracing::{Span, debug_span};
use types::{
    DataColumnSidecarList, EthSpec, ExecutionBlockHash, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope, Slot,
};

// Dedicated enum for LookupResult to force its usage
#[must_use = "LookupResult must be handled with on_lookup_result"]
pub enum LookupResult {
    /// Lookup completed successfully
    Completed,
    /// Lookup is expecting some future event from the network
    Pending,
    /// Block's parent is not known to fork-choice, a parent lookup is needed
    ParentUnknown {
        parent_root: Hash256,
        parent_block_hash: Option<ExecutionBlockHash>,
        block_root: Hash256,
        peers: Vec<PeerId>,
    },
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupRequestError {
    /// Too many failed attempts
    TooManyAttempts,
    /// Error sending event to network
    SendFailedNetwork(RpcRequestSendError),
    /// Error sending event to processor
    SendFailedProcessor(SendErrorProcessor),
    /// Inconsistent lookup request state
    BadState(String),
    /// Lookup failed for some other reason and should be dropped
    Failed(/* reason: */ String),
    /// Received a download result for a different request id than the in-flight request.
    /// There should only exist a single request at a time. Having multiple requests is a bug and
    /// can result in undefined state, so it's treated as a hard error and the lookup is dropped.
    UnexpectedRequestId {
        expected_req_id: ReqId,
        req_id: ReqId,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct AwaitingParent {
    parent_root: Hash256,
    parent_block_hash: Option<ExecutionBlockHash>,
}

impl AwaitingParent {
    pub fn new(parent_root: Hash256, parent_block_hash: Option<ExecutionBlockHash>) -> Self {
        Self {
            parent_root,
            parent_block_hash,
        }
    }

    pub fn parent_root(&self) -> Hash256 {
        self.parent_root
    }

    pub fn into_peer_type(self) -> PeerType {
        PeerType::new(self.parent_block_hash)
    }
}

type PeerSet = Arc<RwLock<HashSet<PeerId>>>;

#[derive(Debug)]
struct BlockRequest<E: EthSpec> {
    state: SingleLookupRequestState<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlockRequest<E> {
    fn new() -> Self {
        Self {
            state: SingleLookupRequestState::new(),
        }
    }

    fn is_complete(&self) -> bool {
        self.state.is_processed()
    }
}

#[derive(Debug)]
enum DataRequest<E: EthSpec> {
    WaitingForBlock,
    Request {
        slot: Slot,
        /// Peers to fetch the data columns from. Pre-Gloas this is the lookup's `peers`; for FULL
        /// Gloas blocks this is the `gloas_child_peers` set proven to hold the columns.
        peers: PeerSet,
        state: SingleLookupRequestState<DataColumnSidecarList<E>>,
    },
    NoData,
}

impl<E: EthSpec> DataRequest<E> {
    fn is_complete(&self) -> bool {
        match &self {
            DataRequest::WaitingForBlock => false,
            DataRequest::Request { state, .. } => state.is_processed(),
            DataRequest::NoData => true,
        }
    }
}

/// Tracks the download + processing of a Gloas execution payload envelope. For FULL Gloas blocks the
/// execution payload arrives as a separate `SignedExecutionPayloadEnvelope`, mirroring the way data
/// columns are fetched and processed by `DataRequest`.
#[derive(Debug)]
enum PayloadRequest<E: EthSpec> {
    /// Block not yet downloaded, can't tell if a payload is needed.
    WaitingForBlock,
    /// Post-Gloas block: an execution payload envelope must be fetched and processed *if* the block
    /// is FULL. We can't tell FULL from EMPTY from the block alone: only a FULL child of this block
    /// proves a payload was published, which is signalled by `peers` becoming non-empty.
    Request {
        peers: PeerSet,
        state: SingleLookupRequestState<Arc<SignedExecutionPayloadEnvelope<E>>>,
    },
    /// Pre-Gloas block: no payload envelope exists, nothing to fetch.
    PreGloas,
}

impl<E: EthSpec> PayloadRequest<E> {
    fn is_complete(&self) -> bool {
        match &self {
            PayloadRequest::WaitingForBlock => false,
            PayloadRequest::Request { state, .. } => state.is_processed(),
            PayloadRequest::PreGloas => true,
        }
    }
}

/// Classifies how a peer relates to a lookup, controlling which peer set it is added to.
pub enum PeerType {
    /// The peer can serve the looked-up block and (pre-Gloas) its data columns.
    Block,
    /// The peer claims to have imported a FULL child of this block whose bid references
    /// `ExecutionBlockHash` as its parent. Such peers can serve this block's payload envelope and
    /// data columns.
    PayloadEnvelope(ExecutionBlockHash),
}

impl PeerType {
    /// `PayloadEnvelope` when the block's bid `parent_block_hash` is known (post-Gloas), else `Block`.
    pub fn new(parent_block_hash: Option<ExecutionBlockHash>) -> Self {
        match parent_block_hash {
            Some(execution_hash) => PeerType::PayloadEnvelope(execution_hash),
            None => PeerType::Block,
        }
    }
}

/// Used by `is_awaiting_parent` to decide if it can resolve its awaiting parent status
#[derive(Debug, Clone, Copy)]
pub enum ImportedParent {
    /// All requests of a lookup are complete, both for pre and post Gloas
    LookupComplete,
    /// Only post-Gloas, the block request has just been completed. Includes the bid block hash
    OnlyGloasBlock(ExecutionBlockHash),
}

#[derive(Educe)]
#[educe(Debug(bound(T: BeaconChainTypes)))]
pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    block_root: Hash256,
    block_request: BlockRequest<T::EthSpec>,
    data_request: DataRequest<T::EthSpec>,
    payload_request: PayloadRequest<T::EthSpec>,
    /// Peers that claim to have imported this set of block components. This state is shared with
    /// the custody request to have an updated view of the peers that claim to have imported the
    /// block associated with this lookup. The peer set of a lookup can change rapidly, and faster
    /// than the lifetime of a custody request.
    #[educe(Debug(method(fmt_peer_set_as_len)))]
    peers: PeerSet,
    /// Post-Gloas only: peers that claim to have imported a FULL child of this block, keyed by the
    /// child's bid `parent_block_hash`. These (not `peers`) are the peers proven to hold this
    /// block's payload envelope and data columns.
    #[educe(Debug(method(fmt_peer_map_as_len)))]
    gloas_child_peers: HashMap<ExecutionBlockHash, PeerSet>,
    awaiting_parent: Option<AwaitingParent>,
    created: Instant,
    pub(crate) span: Span,
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
            PeerType::Block => {}
            PeerType::PayloadEnvelope(execution_hash) => {
                gloas_child_peers.insert(*execution_hash, block_peers.clone());
            }
        }

        Self {
            id,
            block_root: requested_block_root,
            block_request: BlockRequest::new(),
            data_request: DataRequest::WaitingForBlock,
            payload_request: PayloadRequest::WaitingForBlock,
            peers: block_peers,
            gloas_child_peers,
            awaiting_parent,
            created: Instant::now(),
            span: lookup_span,
        }
    }

    /// Return the slot of this lookup's block if it's currently cached
    pub fn peek_downloaded_block_slot(&self) -> Option<Slot> {
        self.block_request
            .state
            .peek_downloaded_data()
            .map(|block| block.slot())
    }

    pub fn peek_downloaded_bid_block_hash(&self) -> Option<ExecutionBlockHash> {
        self.block_request
            .state
            .peek_downloaded_data()
            .and_then(|block| {
                block
                    .message()
                    .body()
                    .signed_execution_payload_bid()
                    .ok()
                    .map(|bid| bid.message.block_hash)
            })
    }

    /// Get the block root that is being requested.
    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn awaiting_parent(&self) -> Option<&AwaitingParent> {
        self.awaiting_parent.as_ref()
    }

    pub fn is_awaiting_block(&self, block_root: Hash256) -> bool {
        if let Some(awaiting_parent) = &self.awaiting_parent {
            awaiting_parent.parent_root() == block_root
        } else {
            false
        }
    }

    /// Mark this lookup as awaiting a parent lookup from being processed. Meanwhile don't send
    /// components for processing.
    pub fn set_awaiting_parent(&mut self, parent: AwaitingParent) {
        self.awaiting_parent = Some(parent);
    }

    /// Mark this lookup as no longer awaiting a parent lookup. Components can be sent for
    /// processing.
    pub fn resolve_awaiting_parent(&mut self) {
        self.awaiting_parent = None;
    }

    /// Check if this lookup awaiting_parent status can be resolved given that `parent_root` and
    /// `imported_parent` have just been imported
    pub fn is_awaiting_parent(
        &mut self,
        parent_root: Hash256,
        imported_parent: ImportedParent,
    ) -> bool {
        let Some(awaiting_parent) = self.awaiting_parent else {
            return false;
        };
        if awaiting_parent.parent_root() != parent_root {
            return false;
        }
        match imported_parent {
            ImportedParent::LookupComplete => true,
            ImportedParent::OnlyGloasBlock(bid_block_hash) => {
                if let Some(parent_block_hash) = awaiting_parent.parent_block_hash {
                    // This lookup is the execution child of `parent_execution_hash`. If the
                    // parent hash the same `bid_block_hash` this is FULL child and we must wait
                    // for the entire parent lookup to be imported. Otherwise it's a EMPTY child
                    // and we can import now.
                    parent_block_hash != bid_block_hash
                } else {
                    // A parent that's gloas imported and this lookup claims to be before gloas.
                    debug_assert!(false, "Received post-gloas action for pre-gloas lookup");
                    false
                }
            }
        }
    }

    /// Returns the time elapsed since this lookup was created
    pub fn elapsed_since_created(&self) -> Duration {
        self.created.elapsed()
    }

    /// Maybe insert a verified response into this lookup. Returns true if imported
    pub fn add_child_components(&mut self, block_component: BlockComponent<T::EthSpec>) -> bool {
        match block_component {
            BlockComponent::Block(block) => {
                self.block_request.state.insert_verified_response(block)
            }
            BlockComponent::Sidecar => {
                // There's nothing to do here, there's no component to insert. The lookup downloads
                // its required data columns itself once it has the block.
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
            || self.block_request.state.is_awaiting_event()
            || match &self.data_request {
                DataRequest::WaitingForBlock => true,
                DataRequest::Request { state, .. } => state.is_awaiting_event(),
                DataRequest::NoData => false,
            }
            || match &self.payload_request {
                PayloadRequest::WaitingForBlock => true,
                PayloadRequest::Request { state, .. } => state.is_awaiting_event(),
                PayloadRequest::PreGloas => false,
            }
    }

    /// Makes progress on all requests of this lookup. Any error is not recoverable and must result
    /// in dropping the lookup. May mark the lookup as completed.
    pub fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let _guard = self.span.clone().entered();

        // === Block request ===
        self.block_request.state.maybe_start_downloading(|| {
            cx.block_lookup_request(self.id, self.peers.clone(), self.block_root)
        })?;
        if self.awaiting_parent.is_none()
            && let Some(data) = self.block_request.state.maybe_start_processing()
        {
            cx.send_block_for_processing(self.id, self.block_root, data.value, data.seen_timestamp)
                .map_err(LookupRequestError::SendFailedProcessor)?;
        }

        // === Data request ===
        loop {
            match &mut self.data_request {
                DataRequest::WaitingForBlock => {
                    if let Some(block) = self.block_request.state.peek_downloaded_data() {
                        let block_epoch = block
                            .slot()
                            .epoch(<T as BeaconChainTypes>::EthSpec::slots_per_epoch());
                        self.data_request = if block.num_expected_blobs() == 0 {
                            DataRequest::NoData
                        } else if cx.chain.should_fetch_custody_columns(block_epoch) {
                            DataRequest::Request {
                                slot: block.slot(),
                                peers: self.get_data_peers(block.payload_bid_block_hash().ok()),
                                state: SingleLookupRequestState::new(),
                            }
                        } else {
                            DataRequest::NoData
                        };
                    } else {
                        break;
                    }
                }
                DataRequest::Request { slot, peers, state } => {
                    state.maybe_start_downloading(|| {
                        cx.custody_lookup_request(self.id, self.block_root, *slot, peers.clone())
                    })?;
                    // Wait for the current block and parent to be imported, data column processing result handle does
                    // not support `ParentUnknown`.
                    if self.block_request.state.is_processed()
                        && self.awaiting_parent.is_none()
                        && let Some(data) = state.maybe_start_processing()
                    {
                        cx.send_custody_columns_for_processing(
                            self.id,
                            self.block_root,
                            data.value,
                            data.seen_timestamp,
                            BlockProcessType::SingleCustodyColumn(self.id),
                        )
                        .map_err(LookupRequestError::SendFailedProcessor)?;
                    }
                    break;
                }
                DataRequest::NoData => break,
            }
        }

        // === Payload request (Gloas only) ===
        loop {
            match &mut self.payload_request {
                PayloadRequest::WaitingForBlock => {
                    if let Some(block) = self.block_request.state.peek_downloaded_data() {
                        self.payload_request = if block.fork_name_unchecked().gloas_enabled() {
                            PayloadRequest::Request {
                                peers: self.get_data_peers(block.payload_bid_block_hash().ok()),
                                state: SingleLookupRequestState::new(),
                            }
                        } else {
                            PayloadRequest::PreGloas
                        };
                    } else {
                        break;
                    }
                }
                PayloadRequest::Request { peers, state } => {
                    state.maybe_start_downloading(|| {
                        cx.payload_lookup_request(self.id, peers.clone(), self.block_root)
                    })?;
                    // The envelope can only be verified once the block itself is imported;
                    // otherwise processing returns `BlockRootUnknown` and the lookup burns retries
                    // until `TooManyAttempts` while the block is parked awaiting its parent.
                    if self.block_request.state.is_processed()
                        && let Some(data) = state.maybe_start_processing()
                    {
                        cx.send_payload_for_processing(
                            self.block_root,
                            data.value,
                            data.seen_timestamp,
                            BlockProcessType::SinglePayloadEnvelope(self.id),
                        )
                        .map_err(LookupRequestError::SendFailedProcessor)?;
                    }
                    break;
                }
                PayloadRequest::PreGloas => break,
            }
        }

        // If all components of this lookup are already processed, there will be no future events
        // that can make progress so it must be dropped. Consider the lookup completed.
        // This case can happen if we receive the components from gossip during a retry.
        if self.block_request.is_complete()
            && self.data_request.is_complete()
            && self.payload_request.is_complete()
        {
            return Ok(LookupResult::Completed);
        }

        Ok(LookupResult::Pending)
    }

    /// Returns the peers that should serve this block's data columns and payload envelope. For FULL
    /// Gloas blocks these are the peers that claimed to have imported a FULL child of this block
    /// (keyed by this block's bid `block_hash`). Pre-Gloas blocks carry no bid, so this returns the
    /// lookup's `peers` unchanged.
    fn get_data_peers(&mut self, bid_block_hash: Option<ExecutionBlockHash>) -> PeerSet {
        if let Some(bid_block_hash) = bid_block_hash {
            // Gloas: the child-attested peer set for this bid is the canonical peer set. DO NOT
            // default to `self.peers`: post-Gloas `self.peers` have not claimed to import this
            // block's data nor its payload. This set may remain empty until a FULL child arrives.
            self.gloas_child_peers
                .entry(bid_block_hash)
                .or_default()
                .clone()
        } else {
            self.peers.clone()
        }
    }

    /// Handle block processing result. Advances the lookup state machine.
    pub fn on_block_processing_result(
        &mut self,
        result: BlockProcessingResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        match result {
            BlockProcessingResult::Imported(_fully_imported, _info) => {
                self.block_request.state.on_processing_success()?;
            }
            BlockProcessingResult::ParentUnknown {
                parent_root,
                parent_block_hash,
            } => {
                // `BlockError::ParentUnknown` is only returned when processing blocks. Revert the
                // block request to `Downloaded` and park this lookup until the parent resolves; a
                // future call to `continue_requests` will re-submit the block for processing once
                // the parent lookup completes.
                self.block_request.state.revert_to_awaiting_processing()?;
                self.set_awaiting_parent(AwaitingParent {
                    parent_root,
                    parent_block_hash,
                });
                return Ok(LookupResult::ParentUnknown {
                    parent_root,
                    parent_block_hash,
                    block_root: self.block_root,
                    peers: self.all_peers(),
                });
            }
            BlockProcessingResult::Error { penalty, .. } => {
                let peers = self.block_request.state.on_processing_failure()?;
                if let Some((action, whom, msg)) = penalty {
                    whom.apply(action, &peers, msg, cx);
                }
            }
        }
        self.continue_requests(cx)
    }

    /// Handle data processing result
    pub fn on_data_processing_result(
        &mut self,
        result: BlockProcessingResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let DataRequest::Request { state, .. } = &mut self.data_request else {
            return Err(LookupRequestError::BadState("no data_request".to_owned()));
        };

        match result {
            BlockProcessingResult::Imported(_fully_imported, _info) => {
                state.on_processing_success()?;
            }
            BlockProcessingResult::ParentUnknown { .. } => {
                return Err(LookupRequestError::BadState(
                    "data processing returned ParentUnknown".to_owned(),
                ));
            }
            BlockProcessingResult::Error { penalty, .. } => {
                let peers = state.on_processing_failure()?;
                if let Some((action, whom, msg)) = penalty {
                    whom.apply(action, &peers, msg, cx);
                }
            }
        }
        self.continue_requests(cx)
    }

    /// Handle payload envelope processing result (Gloas only).
    pub fn on_payload_processing_result(
        &mut self,
        result: BlockProcessingResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let PayloadRequest::Request { state, .. } = &mut self.payload_request else {
            return Err(LookupRequestError::BadState(
                "no payload_request".to_owned(),
            ));
        };

        match result {
            BlockProcessingResult::Imported(_fully_imported, _info) => {
                state.on_processing_success()?;
            }
            BlockProcessingResult::ParentUnknown { .. } => {
                return Err(LookupRequestError::BadState(
                    "payload processing returned ParentUnknown".to_owned(),
                ));
            }
            BlockProcessingResult::Error { penalty, .. } => {
                let peers = state.on_processing_failure()?;
                if let Some((action, whom, msg)) = penalty {
                    whom.apply(action, &peers, msg, cx);
                }
            }
        }
        self.continue_requests(cx)
    }

    /// Handle a block download response. Updates download state and advances the lookup.
    pub fn on_block_download_response(
        &mut self,
        req_id: ReqId,
        result: BlockDownloadResponse<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        self.block_request
            .state
            .on_download_response(req_id, result)?;
        self.continue_requests(cx)
    }

    /// Handle a custody columns download response. Updates download state and advances the lookup.
    pub fn on_custody_download_response(
        &mut self,
        req_id: ReqId,
        result: CustodyDownloadResponse<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let DataRequest::Request { state, .. } = &mut self.data_request else {
            return Err(LookupRequestError::BadState("no data_request".to_owned()));
        };

        state.on_download_response(req_id, result)?;
        self.continue_requests(cx)
    }

    /// Handle a payload envelope download response. Updates download state and advances the lookup.
    pub fn on_payload_download_response(
        &mut self,
        req_id: ReqId,
        result: PayloadDownloadResponse<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let PayloadRequest::Request { state, .. } = &mut self.payload_request else {
            return Err(LookupRequestError::BadState(
                "no payload_request".to_owned(),
            ));
        };

        state.on_download_response(req_id, result)?;
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
            PeerType::PayloadEnvelope(execution_hash) => {
                // This peer claims to have imported a FULL child of this block whose bid references
                // `execution_hash` as its parent. It is therefore proven to hold this block's
                // payload envelope and data columns.
                added |= self
                    .gloas_child_peers
                    .entry(*execution_hash)
                    .or_default()
                    .write()
                    .insert(peer_id);
            }
            PeerType::Block => {}
        }
        // Always add to the main block peers, they can at least serve the block.
        added |= self.peers.write().insert(peer_id);
        added
    }

    /// Remove peer from available peers.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
        for set in self.gloas_child_peers.values() {
            set.write().remove(peer_id);
        }
    }

    /// Returns true if this lookup has zero peers
    pub fn has_no_peers(&self) -> bool {
        if self.block_request.is_complete()
            && let Some(block) = self.block_request.state.peek_downloaded_data()
            && let Ok(bid_block_hash) = block.payload_bid_block_hash()
        {
            // Gloas block request complete, the main peer set is irrelevant. Check only the gloas
            // child peers
            match self.gloas_child_peers.get(&bid_block_hash) {
                Some(set) => set.read().is_empty(),
                None => false,
            }
        } else {
            self.peers.read().is_empty()
                && self
                    .gloas_child_peers
                    .values()
                    .all(|set| set.read().is_empty())
        }
    }
}

#[derive(Debug, Clone)]
pub struct DownloadResult<T: Clone> {
    pub value: T,
    pub seen_timestamp: Duration,
    pub peer_group: PeerGroup,
}

impl<T: Clone> DownloadResult<T> {
    pub fn new(value: T, peer_group: PeerGroup, seen_timestamp: Duration) -> Self {
        Self {
            value,
            seen_timestamp,
            peer_group,
        }
    }
}

#[derive(IntoStaticStr)]
pub enum State<T: Clone> {
    AwaitingDownload(/* reason */ &'static str),
    Downloading(ReqId),
    AwaitingProcess(DownloadResult<T>),
    /// Request is processing, sent by lookup sync
    Processing(DownloadResult<T>),
    /// Request is processed
    Processed(/* reason */ &'static str, T),
}

/// Object representing the state of a single block or blob lookup request.
#[derive(Debug)]
pub struct SingleLookupRequestState<T: Clone> {
    /// State of this request.
    state: State<T>,
    /// How many times have we attempted to process this block or blob.
    failed_processing: u8,
    /// How many times have we attempted to download this block or blob.
    failed_downloading: u8,
}

impl<T: Clone> SingleLookupRequestState<T> {
    pub fn new() -> Self {
        Self {
            state: State::AwaitingDownload("not started"),
            failed_processing: 0,
            failed_downloading: 0,
        }
    }

    pub fn is_awaiting_download(&self) -> bool {
        match self.state {
            State::AwaitingDownload { .. } => true,
            State::Downloading { .. }
            | State::AwaitingProcess { .. }
            | State::Processing { .. }
            | State::Processed { .. } => false,
        }
    }

    pub fn is_processed(&self) -> bool {
        match self.state {
            State::AwaitingDownload { .. }
            | State::Downloading { .. }
            | State::AwaitingProcess { .. }
            | State::Processing { .. } => false,
            State::Processed { .. } => true,
        }
    }

    /// Returns true if we can expect some future event to progress this block component request
    /// specifically.
    pub fn is_awaiting_event(&self) -> bool {
        match self.state {
            // No event will progress this request specifically, but the request may be put on hold
            // due to some external event
            State::AwaitingDownload { .. } => false,
            // Network will emit a download success / error event
            State::Downloading { .. } => true,
            // Not awaiting any external event
            State::AwaitingProcess { .. } => false,
            // Beacon processor will emit a processing result event
            State::Processing { .. } => true,
            // Request complete, no future event left
            State::Processed { .. } => false,
        }
    }

    pub fn peek_downloaded_data(&self) -> Option<&T> {
        match &self.state {
            State::AwaitingDownload { .. } => None,
            State::Downloading { .. } => None,
            State::AwaitingProcess(result) => Some(&result.value),
            State::Processing(result) => Some(&result.value),
            State::Processed(_, value) => Some(value),
        }
    }

    /// Drive download: check max attempts, issue request, handle result.
    fn maybe_start_downloading(
        &mut self,
        request_fn: impl FnOnce() -> Result<LookupRequestResult<T>, RpcRequestSendError>,
    ) -> Result<(), LookupRequestError> {
        if self.is_awaiting_download() {
            match request_fn().map_err(LookupRequestError::SendFailedNetwork)? {
                LookupRequestResult::RequestSent(req_id) => self.on_download_start(req_id)?,
                LookupRequestResult::NoRequestNeeded(reason, value) => {
                    self.on_completed_request(reason, value)?
                }
                LookupRequestResult::Pending(reason) => {
                    self.update_awaiting_download_status(reason)
                }
            }
        }
        Ok(())
    }

    /// Switch to `AwaitingProcessing` if the request is in `AwaitingDownload` state, otherwise
    /// ignore.
    pub fn insert_verified_response(&mut self, result: DownloadResult<T>) -> bool {
        if let State::AwaitingDownload { .. } = &self.state {
            self.state = State::AwaitingProcess(result);
            true
        } else {
            false
        }
    }

    /// Append metadata on why this request is in AwaitingDownload status. Very helpful to debug
    /// stuck lookups. Not fallible as it's purely informational.
    pub fn update_awaiting_download_status(&mut self, new_status: &'static str) {
        if let State::AwaitingDownload(status) = &mut self.state {
            *status = new_status
        }
    }

    /// Switch to `Downloading` if the request is in `AwaitingDownload` state, otherwise returns None.
    pub fn on_download_start(&mut self, req_id: ReqId) -> Result<(), LookupRequestError> {
        match &self.state {
            State::AwaitingDownload { .. } => {
                self.state = State::Downloading(req_id);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_start expected AwaitingDownload got {other}"
            ))),
        }
    }

    pub fn on_download_response(
        &mut self,
        req_id: ReqId,
        result: Result<DownloadResult<T>, RpcResponseError>,
    ) -> Result<(), LookupRequestError> {
        match result {
            Ok(result) => self.on_download_success(req_id, result),
            Err(_) => self.on_download_failure(req_id),
        }
    }

    /// Registers a failure in downloading a block. This might be a peer disconnection or a wrong
    /// block.
    pub fn on_download_failure(&mut self, req_id: ReqId) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(LookupRequestError::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.failed_downloading = self.failed_downloading.saturating_add(1);
                if self.failed_downloading >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                    return Err(LookupRequestError::TooManyAttempts);
                }

                self.state = State::AwaitingDownload("not started");
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_failure expected Downloading got {other}"
            ))),
        }
    }

    pub fn on_download_success(
        &mut self,
        req_id: ReqId,
        result: DownloadResult<T>,
    ) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(LookupRequestError::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.state = State::AwaitingProcess(result);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_success expected Downloading got {other}"
            ))),
        }
    }

    /// Switch to `Processing` if the request is in `AwaitingProcess` state, otherwise returns None.
    pub fn maybe_start_processing(&mut self) -> Option<DownloadResult<T>> {
        // For 2 lines replace state with placeholder to gain ownership of `result`
        match &self.state {
            State::AwaitingProcess(result) => {
                let result = result.clone();
                self.state = State::Processing(result.clone());
                Some(result)
            }
            _ => None,
        }
    }

    /// Revert into `AwaitingProcessing`, if the payload if not invalid and can be submitted for
    /// processing latter.
    pub fn revert_to_awaiting_processing(&mut self) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Processing(result) => {
                self.state = State::AwaitingProcess(result.clone());
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on revert_to_awaiting_processing expected Processing got {other}"
            ))),
        }
    }

    /// Registers a failure in processing a block.
    pub fn on_processing_failure(&mut self) -> Result<PeerGroup, LookupRequestError> {
        match &self.state {
            State::Processing(result) => {
                let peers_source = result.peer_group.clone();
                self.failed_processing = self.failed_processing.saturating_add(1);
                if self.failed_processing >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                    return Err(LookupRequestError::TooManyAttempts);
                }
                self.state = State::AwaitingDownload("not started");
                Ok(peers_source)
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_processing_failure expected Processing got {other}"
            ))),
        }
    }

    pub fn on_processing_success(&mut self) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Processing(data) => {
                self.state = State::Processed("processing success", data.value.clone());
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_processing_success expected Processing got {other}"
            ))),
        }
    }

    /// Mark a request as complete without any download or processing
    pub fn on_completed_request(
        &mut self,
        reason: &'static str,
        value: T,
    ) -> Result<(), LookupRequestError> {
        match &self.state {
            State::AwaitingDownload { .. } => {
                self.state = State::Processed(reason, value);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_completed_request expected AwaitingDownload got {other}"
            ))),
        }
    }
}

// Display is used in the BadState assertions above
impl<T: Clone> std::fmt::Display for State<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(self))
    }
}

// Debug is used in the log_stuck_lookups print to include some more info. Implements custom Debug
// to not dump an entire block or blob to terminal which don't add valuable data.
impl<T: Clone> std::fmt::Debug for State<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwaitingDownload(reason) => write!(f, "AwaitingDownload({})", reason),
            Self::Downloading(req_id) => write!(f, "Downloading({:?})", req_id),
            Self::AwaitingProcess(_) => write!(f, "AwaitingProcess"),
            Self::Processing(_) => write!(f, "Processing"),
            Self::Processed(reason, _) => write!(f, "Processed({})", reason),
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
    peer_map: &HashMap<ExecutionBlockHash, PeerSet>,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    let total = peer_map.values().map(|set| set.read().len()).sum::<usize>();
    write!(f, "{}", total)
}
