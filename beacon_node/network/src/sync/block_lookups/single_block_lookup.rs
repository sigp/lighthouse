use super::{BlockComponent, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS};
use crate::network_beacon_processor::BlockProcessingResult;
use crate::sync::block_lookups::{BlockDownloadResponse, CustodyDownloadResponse};
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
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Hash256;
use strum::IntoStaticStr;
use tracing::{Span, debug, debug_span};
use types::{DataColumnSidecarList, EthSpec, SignedBeaconBlock, Slot};

/// What a child lookup is waiting for its parent to resolve.
#[derive(Debug, Clone, Copy)]
pub struct AwaitingParent {
    parent_root: Hash256,
}

impl AwaitingParent {
    pub fn parent_root(&self) -> Hash256 {
        self.parent_root
    }

    pub fn from_block<E: EthSpec>(block: &SignedBeaconBlock<E>) -> Self {
        Self {
            parent_root: block.message().parent_root(),
        }
    }

    pub fn from_root(parent_root: Hash256) -> Self {
        Self { parent_root }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
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
        parent_root: Hash256,
        block_root: Hash256,
        peers: Vec<PeerId>,
    },
}

#[derive(Debug)]
struct BlockRequest<E: EthSpec> {
    state: SingleLookupRequestState<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlockRequest<E> {
    fn new(block_root: Hash256) -> Self {
        Self { state: todo!() }
    }
}

#[derive(Debug)]
struct DataRequest<E: EthSpec> {
    peers: PeerSet,
    block_root: Hash256,
    slot: Slot,
    state: SingleLookupRequestState<DataColumnSidecarList<E>>,
}

type PeerSet = Arc<RwLock<HashSet<PeerId>>>;

#[derive(Educe)]
#[educe(Debug(bound(T: BeaconChainTypes)))]
pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    block_root: Hash256,

    // Block request — always present
    block_request: BlockRequest<T::EthSpec>,

    // Data request — starts as None, set after block downloaded
    data_request: Option<DataRequest<T::EthSpec>>,

    // Peer sets.
    //
    // `Arc<RwLock<..>>` is required by `ActiveCustodyRequest` (columns only), which lives
    // in `SyncNetworkContext` and needs to observe peers being added/removed at runtime
    // while it's in flight.
    /// Peers for block and data download.
    #[educe(Debug(method(fmt_peer_set_as_len)))]
    peers: PeerSet,

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
        id: Id,
        awaiting_parent: Option<AwaitingParent>,
    ) -> Self {
        let lookup_span = debug_span!(
            "lh_single_block_lookup",
            block_root = %requested_block_root,
            id = id,
        );

        Self {
            id,
            block_root: requested_block_root,
            block_request: BlockRequest::new(requested_block_root),
            data_request: None,
            peers: Arc::new(RwLock::new(peers.iter().copied().collect())),
            awaiting_parent,
            created: Instant::now(),
            failed_processing: 0,
            span: lookup_span,
        }
    }

    /// Reset the status of all requests (used on block processing failure)
    pub fn reset_requests(&mut self) {
        self.block_request = BlockRequest::new(self.block_root);
        self.data_request = None;
    }

    /// Return the slot of this lookup's block if it's currently cached
    pub fn peek_downloaded_block_slot(&self) -> Option<Slot> {
        self.block_request
            .state
            .peek_downloaded_data()
            .map(|block| block.slot())
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
            BlockComponent::Block(block) => {
                self.block_request.state.insert_verified_response(block)
            }
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
            || self.block_request.state.is_awaiting_event()
            || match &self.data_request {
                Some(request) => request.state.is_awaiting_event(),
                None => true,
            }
    }

    /// Makes progress on all requests of this lookup. Any error is not recoverable and must result
    /// in dropping the lookup. May mark the lookup as completed.
    ///
    /// Each of the block / data sub-state-machines is driven inside its own `loop`
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
            if self.block_request.state.is_awaiting_download() {
                self.block_request
                    .state
                    .make_request(|| cx.block_lookup_request(id, self.peers.clone(), block_root))?;
            }
            if self.awaiting_parent.is_none() {
                if let Some(data) = self.block_request.state.maybe_start_processing() {
                    cx.send_block_for_processing(id, self.block_root, data.value, Duration::ZERO)
                        .map_err(LookupRequestError::SendFailedProcessor)?;
                }
            }
            break;
        }

        // === Data request ===
        loop {
            match &mut self.data_request {
                // None = waiting for block
                None => {
                    let Some(block) = self.block_request.state.peek_downloaded_data() else {
                        break;
                    };
                    // TODO(gloas): Only start if expected_blobs > 0
                    let peers = self.peers.clone();
                    self.data_request = Some(DataRequest {
                        peers,
                        block_root: self.block_root,
                        slot: block.slot(),
                        state: SingleLookupRequestState::new(),
                    });
                }
                Some(request) => {
                    if request.state.is_awaiting_download() {
                        request.state.make_request(|| {
                            cx.custody_lookup_request(
                                id,
                                request.block_root,
                                request.slot,
                                request.peers.clone(),
                            )
                        })?;
                    }
                    // Do not send data for processing until the block has been imported (the
                    // availability check needs the block) and we are not awaiting a parent
                    // lookup. Otherwise data processing can fail with a transient
                    // `ParentUnknown` / missing-block error.
                    if self.awaiting_parent.is_some() || !self.block_request.state.is_processed() {
                        break;
                    }
                    if let Some(data) = request.state.maybe_start_processing() {
                        cx.send_custody_columns_for_processing(
                            id,
                            block_root,
                            data.value,
                            Duration::ZERO,
                            BlockProcessType::SingleCustodyColumn(id),
                        )
                        .map_err(LookupRequestError::SendFailedProcessor)?;
                    }
                }
            }
        }

        // === Check completion ===
        if self.block_request.state.is_processed()
            && self
                .data_request
                .as_ref()
                .is_some_and(|r| r.state.is_processed())
        {
            return Ok(LookupResult::Completed);
        }

        Ok(LookupResult::Pending)
    }

    // -- Processing result handlers --

    /// Handle block processing result. Advances the lookup state machine.
    pub fn on_block_processing_result(
        &mut self,
        result: BlockProcessingResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        match result {
            BlockProcessingResult::Imported(_fully_imported, _info) => {
                self.block_request.state.on_processing_success()?;
                self.continue_requests(cx)
            }
            BlockProcessingResult::ParentUnknown { parent_root } => {
                // `BlockError::ParentUnknown` is only returned when processing blocks. Revert the
                // block request to `Downloaded` and park this lookup until the parent resolves; a
                // future call to `continue_requests` will re-submit the block for processing once
                // the parent lookup completes.
                self.block_request.state.revert_to_awaiting_processing()?;
                self.awaiting_parent = Some(AwaitingParent::from_root(parent_root));
                Ok(LookupResult::ParentUnknown {
                    parent_root,
                    block_root: self.block_root,
                    peers: self.all_peers(),
                })
            }
            BlockProcessingResult::Error { penalty, reason } => {
                debug!(
                    block_root = ?self.block_root,
                    reason,
                    ?penalty,
                    "Lookup block processing failed; retrying"
                );
                let block_peer = self.block_request.state.on_processing_failure()?;
                if let Some((action, whom, msg)) = penalty {
                    whom.apply(action, &block_peer, msg, cx);
                }
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
        let DataRequest { state, .. } = self
            .data_request
            .as_mut()
            .ok_or(LookupRequestError::BadState("no data_request".to_owned()))?;

        match result {
            BlockProcessingResult::Imported(_fully_imported, _info) => {
                state.on_processing_success()?;
                self.continue_requests(cx)
            }
            BlockProcessingResult::ParentUnknown { .. } => Err(LookupRequestError::BadState(
                "data processing returned ParentUnknown".to_owned(),
            )),
            BlockProcessingResult::Error { penalty, reason } => {
                debug!(
                    block_root = ?self.block_root,
                    reason,
                    ?penalty,
                    "Lookup data processing failed; retrying"
                );
                let peer_group = state.on_processing_failure()?;
                if let Some((action, whom, msg)) = penalty {
                    whom.apply(action, &peer_group, msg, cx);
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
        self.data_request
            .as_mut()
            .ok_or(LookupRequestError::BadState("no data_request".to_owned()))?
            .state
            .on_download_response(req_id, result)?;
        self.continue_requests(cx)
    }

    /// Get all unique peers that claim to have imported this set of block components
    pub fn all_peers(&self) -> Vec<PeerId> {
        self.peers.read().iter().copied().collect()
    }

    /// Add peer to all request states. The peer must be able to serve this request.
    /// Returns true if the peer was newly inserted into any peer set.
    pub fn add_peer(&mut self, peer_id: PeerId) -> bool {
        self.peers.write().insert(peer_id)
    }

    /// Remove peer from available peers.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
    }

    /// Returns true if this lookup has zero peers
    pub fn has_peers(&self) -> bool {
        !self.peers.read().is_empty()
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
            State::Processed(_, value) => Some(&value),
        }
    }

    /// Drive download: check max attempts, issue request, handle result.
    fn make_request(
        &mut self,
        request_fn: impl FnOnce() -> Result<LookupRequestResult<T>, RpcRequestSendError>,
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
            LookupRequestResult::NoRequestNeeded(reason, value) => {
                self.on_completed_request(reason, value)?
            }
            LookupRequestResult::Pending(reason) => self.update_awaiting_download_status(reason),
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

    /// The total number of failures, whether it be processing or downloading.
    pub fn failed_attempts(&self) -> u8 {
        self.failed_processing + self.failed_downloading
    }

    pub fn more_failed_processing_attempts(&self) -> bool {
        self.failed_processing >= self.failed_downloading
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

impl std::fmt::Display for AwaitingParent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.parent_root)
    }
}

fn fmt_peer_set_as_len(
    peer_set: &PeerSet,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{}", peer_set.read().len())
}
