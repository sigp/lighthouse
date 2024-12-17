use super::{BlockComponent, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS};
use crate::sync::block_lookups::common::RequestState;
use crate::sync::network_context::{
    LookupRequestResult, PeerGroup, ReqId, RpcRequestSendError, SendErrorProcessor,
    SyncNetworkContext,
};
use beacon_chain::{BeaconChainTypes, BlockProcessStatus};
use derivative::Derivative;
use lighthouse_network::service::api_types::Id;
use rand::seq::IteratorRandom;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Hash256;
use strum::IntoStaticStr;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{DataColumnSidecarList, EthSpec, SignedBeaconBlock, Slot};

// Dedicated enum for LookupResult to force its usage
#[must_use = "LookupResult must be handled with on_lookup_result"]
pub enum LookupResult {
    /// Lookup completed successfully
    Completed,
    /// Lookup is expecting some future event from the network
    Pending,
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupRequestError {
    /// Too many failed attempts
    TooManyAttempts {
        /// The failed attempts were primarily due to processing failures.
        cannot_process: bool,
    },
    /// No peers left to serve this lookup
    NoPeers,
    /// Error sending event to network
    SendFailedNetwork(RpcRequestSendError),
    /// Error sending event to processor
    SendFailedProcessor(SendErrorProcessor),
    /// Inconsistent lookup request state
    BadState(String),
    /// Lookup failed for some other reason and should be dropped
    Failed,
    /// Received MissingComponents when all components have been processed. This should never
    /// happen, and indicates some internal bug
    MissingComponentsAfterAllProcessed,
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

#[derive(Derivative)]
#[derivative(Debug(bound = "T: BeaconChainTypes"))]
pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    pub block_request_state: BlockRequestState<T::EthSpec>,
    pub component_requests: ComponentRequests<T::EthSpec>,
    /// Peers that claim to have imported this set of block components
    #[derivative(Debug(format_with = "fmt_peer_set_as_len"))]
    peers: HashSet<PeerId>,
    block_root: Hash256,
    awaiting_parent: Option<Hash256>,
    created: Instant,
}

#[derive(Debug)]
pub(crate) enum ComponentRequests<E: EthSpec> {
    WaitingForBlock,
    ActiveBlobRequest(BlobRequestState<E>, usize),
    ActiveCustodyRequest(CustodyRequestState<E>),
    // When printing in debug this state display the reason why it's not needed
    #[allow(dead_code)]
    NotNeeded(&'static str),
}

impl<T: BeaconChainTypes> SingleBlockLookup<T> {
    pub fn new(
        requested_block_root: Hash256,
        peers: &[PeerId],
        id: Id,
        awaiting_parent: Option<Hash256>,
    ) -> Self {
        Self {
            id,
            block_request_state: BlockRequestState::new(requested_block_root),
            component_requests: ComponentRequests::WaitingForBlock,
            peers: HashSet::from_iter(peers.iter().copied()),
            block_root: requested_block_root,
            awaiting_parent,
            created: Instant::now(),
        }
    }

    /// Return the slot of this lookup's block if it's currently cached as `AwaitingProcessing`
    pub fn peek_downloaded_block_slot(&self) -> Option<Slot> {
        self.block_request_state
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
            BlockComponent::Block(block) => self
                .block_request_state
                .state
                .insert_verified_response(block),
            BlockComponent::Blob(_) | BlockComponent::DataColumn(_) => {
                // For now ignore single blobs and columns, as the blob request state assumes all blobs are
                // attributed to the same peer = the peer serving the remaining blobs. Ignoring this
                // block component has a minor effect, causing the node to re-request this blob
                // once the parent chain is successfully resolved
                false
            }
        }
    }

    /// Check the block root matches the requested block root.
    pub fn is_for_block(&self, block_root: Hash256) -> bool {
        self.block_root() == block_root
    }

    /// Returns true if the block has already been downloaded.
    pub fn all_components_processed(&self) -> bool {
        self.block_request_state.state.is_processed()
            && match &self.component_requests {
                ComponentRequests::WaitingForBlock => false,
                ComponentRequests::ActiveBlobRequest(request, _) => request.state.is_processed(),
                ComponentRequests::ActiveCustodyRequest(request) => request.state.is_processed(),
                ComponentRequests::NotNeeded { .. } => true,
            }
    }

    /// Returns true if this request is expecting some event to make progress
    pub fn is_awaiting_event(&self) -> bool {
        self.awaiting_parent.is_some()
            || self.block_request_state.state.is_awaiting_event()
            || match &self.component_requests {
                // If components are waiting for the block request to complete, here we should
                // check if the`block_request_state.state.is_awaiting_event(). However we already
                // checked that above, so `WaitingForBlock => false` is equivalent.
                ComponentRequests::WaitingForBlock => false,
                ComponentRequests::ActiveBlobRequest(request, _) => {
                    request.state.is_awaiting_event()
                }
                ComponentRequests::ActiveCustodyRequest(request) => {
                    request.state.is_awaiting_event()
                }
                ComponentRequests::NotNeeded { .. } => false,
            }
    }

    /// Makes progress on all requests of this lookup. Any error is not recoverable and must result
    /// in dropping the lookup. May mark the lookup as completed.
    pub fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        // TODO: Check what's necessary to download, specially for blobs
        self.continue_request::<BlockRequestState<T::EthSpec>>(cx, 0)?;

        if let ComponentRequests::WaitingForBlock = self.component_requests {
            let downloaded_block = self
                .block_request_state
                .state
                .peek_downloaded_data()
                .cloned();

            if let Some(block) = downloaded_block.or_else(|| {
                // If the block is already being processed or fully validated, retrieve how many blobs
                // it expects. Consider any stage of the block. If the block root has been validated, we
                // can assert that this is the correct value of `blob_kzg_commitments_count`.
                match cx.chain.get_block_process_status(&self.block_root) {
                    BlockProcessStatus::Unknown => None,
                    BlockProcessStatus::NotValidated(block)
                    | BlockProcessStatus::ExecutionValidated(block) => Some(block.clone()),
                }
            }) {
                let expected_blobs = block.num_expected_blobs();
                let block_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());
                if expected_blobs == 0 {
                    self.component_requests = ComponentRequests::NotNeeded("no data");
                }
                if cx.chain.should_fetch_blobs(block_epoch) {
                    self.component_requests = ComponentRequests::ActiveBlobRequest(
                        BlobRequestState::new(self.block_root),
                        expected_blobs,
                    );
                } else if cx.chain.should_fetch_custody_columns(block_epoch) {
                    self.component_requests = ComponentRequests::ActiveCustodyRequest(
                        CustodyRequestState::new(self.block_root),
                    );
                } else {
                    self.component_requests = ComponentRequests::NotNeeded("outside da window");
                }
            } else {
                // Wait to download the block before downloading blobs. Then we can be sure that the
                // block has data, so there's no need to do "blind" requests for all possible blobs and
                // latter handle the case where if the peer sent no blobs, penalize.
                //
                // Lookup sync event safety: Reaching this code means that a block is not in any pre-import
                // cache nor in the request state of this lookup. Therefore, the block must either: (1) not
                // be downloaded yet or (2) the block is already imported into the fork-choice.
                // In case (1) the lookup must either successfully download the block or get dropped.
                // In case (2) the block will be downloaded, processed, reach `DuplicateFullyImported`
                // and get dropped as completed.
            }
        }

        match &self.component_requests {
            ComponentRequests::WaitingForBlock => {} // do nothing
            ComponentRequests::ActiveBlobRequest(_, expected_blobs) => {
                self.continue_request::<BlobRequestState<T::EthSpec>>(cx, *expected_blobs)?
            }
            ComponentRequests::ActiveCustodyRequest(_) => {
                self.continue_request::<CustodyRequestState<T::EthSpec>>(cx, 0)?
            }
            ComponentRequests::NotNeeded { .. } => {} // do nothing
        }

        // If all components of this lookup are already processed, there will be no future events
        // that can make progress so it must be dropped. Consider the lookup completed.
        // This case can happen if we receive the components from gossip during a retry.
        if self.all_components_processed() {
            Ok(LookupResult::Completed)
        } else {
            Ok(LookupResult::Pending)
        }
    }

    /// Potentially makes progress on this request if it's in a progress-able state
    fn continue_request<R: RequestState<T>>(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
        expected_blobs: usize,
    ) -> Result<(), LookupRequestError> {
        let id = self.id;
        let awaiting_parent = self.awaiting_parent.is_some();
        let request =
            R::request_state_mut(self).map_err(|e| LookupRequestError::BadState(e.to_owned()))?;

        // Attempt to progress awaiting downloads
        if request.get_state().is_awaiting_download() {
            // Verify the current request has not exceeded the maximum number of attempts.
            let request_state = request.get_state();
            if request_state.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                let cannot_process = request_state.more_failed_processing_attempts();
                return Err(LookupRequestError::TooManyAttempts { cannot_process });
            }

            let Some(peer_id) = self.use_rand_available_peer() else {
                // Allow lookup to not have any peers and do nothing. This is an optimization to not
                // lose progress of lookups created from a block with unknown parent before we receive
                // attestations for said block.
                // Lookup sync event safety: If a lookup requires peers to make progress, and does
                // not receive any new peers for some time it will be dropped. If it receives a new
                // peer it must attempt to make progress.
                R::request_state_mut(self)
                    .map_err(|e| LookupRequestError::BadState(e.to_owned()))?
                    .get_state_mut()
                    .update_awaiting_download_status("no peers");
                return Ok(());
            };

            let request = R::request_state_mut(self)
                .map_err(|e| LookupRequestError::BadState(e.to_owned()))?;

            match request.make_request(id, peer_id, expected_blobs, cx)? {
                LookupRequestResult::RequestSent(req_id) => {
                    // Lookup sync event safety: If make_request returns `RequestSent`, we are
                    // guaranteed that `BlockLookups::on_download_response` will be called exactly
                    // with this `req_id`.
                    request.get_state_mut().on_download_start(req_id)?
                }
                LookupRequestResult::NoRequestNeeded(reason) => {
                    // Lookup sync event safety: Advances this request to the terminal `Processed`
                    // state. If all requests reach this state, the request is marked as completed
                    // in `Self::continue_requests`.
                    request.get_state_mut().on_completed_request(reason)?
                }
                // Sync will receive a future event to make progress on the request, do nothing now
                LookupRequestResult::Pending(reason) => {
                    // Lookup sync event safety: Refer to the code paths constructing
                    // `LookupRequestResult::Pending`
                    request
                        .get_state_mut()
                        .update_awaiting_download_status(reason);
                    return Ok(());
                }
            }

        // Otherwise, attempt to progress awaiting processing
        // If this request is awaiting a parent lookup to be processed, do not send for processing.
        // The request will be rejected with unknown parent error.
        } else if !awaiting_parent {
            // maybe_start_processing returns Some if state == AwaitingProcess. This pattern is
            // useful to conditionally access the result data.
            if let Some(result) = request.get_state_mut().maybe_start_processing() {
                // Lookup sync event safety: If `send_for_processing` returns Ok() we are guaranteed
                // that `BlockLookups::on_processing_result` will be called exactly once with this
                // lookup_id
                return R::send_for_processing(id, result, cx);
            }
            // Lookup sync event safety: If the request is not in `AwaitingDownload` or
            // `AwaitingProcessing` state it is guaranteed to receive some event to make progress.
        }

        // Lookup sync event safety: If a lookup is awaiting a parent we are guaranteed to either:
        // (1) attempt to make progress with `BlockLookups::continue_child_lookups` if the parent
        // lookup completes, or (2) get dropped if the parent fails and is dropped.

        Ok(())
    }

    /// Get all unique peers that claim to have imported this set of block components
    pub fn all_peers(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.peers.iter()
    }

    /// Add peer to all request states. The peer must be able to serve this request.
    /// Returns true if the peer was newly inserted into some request state.
    pub fn add_peer(&mut self, peer_id: PeerId) -> bool {
        self.peers.insert(peer_id)
    }

    /// Remove peer from available peers.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Returns true if this lookup has zero peers
    pub fn has_no_peers(&self) -> bool {
        self.peers.is_empty()
    }

    /// Selects a random peer from available peers if any
    fn use_rand_available_peer(&mut self) -> Option<PeerId> {
        self.peers.iter().choose(&mut rand::thread_rng()).copied()
    }
}

/// The state of the blob request component of a `SingleBlockLookup`.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct BlobRequestState<E: EthSpec> {
    #[derivative(Debug = "ignore")]
    pub block_root: Hash256,
    pub state: SingleLookupRequestState<FixedBlobSidecarList<E>>,
}

impl<E: EthSpec> BlobRequestState<E> {
    pub fn new(block_root: Hash256) -> Self {
        Self {
            block_root,
            state: SingleLookupRequestState::new(),
        }
    }
}

/// The state of the custody request component of a `SingleBlockLookup`.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct CustodyRequestState<E: EthSpec> {
    #[derivative(Debug = "ignore")]
    pub block_root: Hash256,
    pub state: SingleLookupRequestState<DataColumnSidecarList<E>>,
}

impl<E: EthSpec> CustodyRequestState<E> {
    pub fn new(block_root: Hash256) -> Self {
        Self {
            block_root,
            state: SingleLookupRequestState::new(),
        }
    }
}

/// The state of the block request component of a `SingleBlockLookup`.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct BlockRequestState<E: EthSpec> {
    #[derivative(Debug = "ignore")]
    pub requested_block_root: Hash256,
    pub state: SingleLookupRequestState<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlockRequestState<E> {
    pub fn new(block_root: Hash256) -> Self {
        Self {
            requested_block_root: block_root,
            state: SingleLookupRequestState::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DownloadResult<T: Clone> {
    pub value: T,
    pub block_root: Hash256,
    pub seen_timestamp: Duration,
    pub peer_group: PeerGroup,
}

#[derive(IntoStaticStr)]
pub enum State<T: Clone> {
    AwaitingDownload(/* reason */ &'static str),
    Downloading(ReqId),
    AwaitingProcess(DownloadResult<T>),
    /// Request is processing, sent by lookup sync
    Processing(DownloadResult<T>),
    /// Request is processed
    Processed(/* reason */ &'static str),
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
            State::Processed { .. } => None,
        }
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
            State::Processing(_) => {
                self.state = State::Processed("processing success");
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_processing_success expected Processing got {other}"
            ))),
        }
    }

    /// Mark a request as complete without any download or processing
    pub fn on_completed_request(&mut self, reason: &'static str) -> Result<(), LookupRequestError> {
        match &self.state {
            State::AwaitingDownload { .. } => {
                self.state = State::Processed(reason);
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
            Self::AwaitingProcess(d) => write!(f, "AwaitingProcess({:?})", d.peer_group),
            Self::Processing(d) => write!(f, "Processing({:?})", d.peer_group),
            Self::Processed(reason) => write!(f, "Processed({})", reason),
        }
    }
}

fn fmt_peer_set_as_len(
    peer_set: &HashSet<PeerId>,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{}", peer_set.len())
}
