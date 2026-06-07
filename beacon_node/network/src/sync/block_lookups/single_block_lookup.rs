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
use tracing::{Span, debug_span};
use types::{DataColumnSidecarList, EthSpec, SignedBeaconBlock, Slot};

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
    /// Attempted to retrieve a not known lookup id
    UnknownLookup,
    /// Received a download result for a different request id than the in-flight request.
    /// There should only exist a single request at a time. Having multiple requests is a bug and
    /// can result in undefined state, so it's treated as a hard error and the lookup is dropped.
    UnexpectedRequestId {
        expected_req_id: ReqId,
        req_id: ReqId,
    },
}

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

type PeerSet = Arc<RwLock<HashSet<PeerId>>>;

#[derive(Educe)]
#[educe(Debug(bound(T: BeaconChainTypes)))]
pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    block_root: Hash256,
    block_request: BlockRequest<T::EthSpec>,
    data_request: DataRequest<T::EthSpec>,
    /// Peers that claim to have imported this set of block components. This state is shared with
    /// the custody request to have an updated view of the peers that claim to have imported the
    /// block associated with this lookup. The peer set of a lookup can change rapidly, and faster
    /// than the lifetime of a custody request.
    #[educe(Debug(method(fmt_peer_set_as_len)))]
    peers: PeerSet,
    awaiting_parent: Option<Hash256>,
    created: Instant,
    pub(crate) span: Span,
}

impl<T: BeaconChainTypes> SingleBlockLookup<T> {
    pub fn new(
        requested_block_root: Hash256,
        peers: &[PeerId],
        id: Id,
        awaiting_parent: Option<Hash256>,
    ) -> Self {
        let lookup_span = debug_span!(
            "lh_single_block_lookup",
            block_root = %requested_block_root,
            id = id,
        );

        Self {
            id,
            block_root: requested_block_root,
            block_request: BlockRequest::new(),
            data_request: DataRequest::WaitingForBlock,
            peers: Arc::new(RwLock::new(peers.iter().copied().collect())),
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

    /// Get the block root that is being requested.
    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn awaiting_parent(&self) -> Option<Hash256> {
        self.awaiting_parent
    }

    /// Mark this lookup as awaiting a parent lookup from being processed. Meanwhile don't send
    /// components for processing.
    pub fn set_awaiting_parent(&mut self, parent_root: Hash256) {
        self.awaiting_parent = Some(parent_root)
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
                                state: SingleLookupRequestState::new(),
                            }
                        } else {
                            DataRequest::NoData
                        };
                    } else {
                        break;
                    }
                }
                DataRequest::Request { slot, state } => {
                    state.maybe_start_downloading(|| {
                        cx.custody_lookup_request(
                            self.id,
                            self.block_root,
                            *slot,
                            self.peers.clone(),
                        )
                    })?;
                    // Wait for the parent to be imported, data column processing result handle does
                    // not support `ParentUnknown`.
                    if self.awaiting_parent.is_none()
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

        // If all components of this lookup are already processed, there will be no future events
        // that can make progress so it must be dropped. Consider the lookup completed.
        // This case can happen if we receive the components from gossip during a retry.
        if self.block_request.is_complete() && self.data_request.is_complete() {
            return Ok(LookupResult::Completed);
        }

        Ok(LookupResult::Pending)
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
            BlockProcessingResult::ParentUnknown { parent_root } => {
                // `BlockError::ParentUnknown` is only returned when processing blocks. Revert the
                // block request to `Downloaded` and park this lookup until the parent resolves; a
                // future call to `continue_requests` will re-submit the block for processing once
                // the parent lookup completes.
                self.block_request.state.revert_to_awaiting_processing()?;
                self.set_awaiting_parent(parent_root);
                return Ok(LookupResult::ParentUnknown {
                    parent_root,
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
    pub fn has_no_peers(&self) -> bool {
        self.peers.read().is_empty()
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
