use super::common::ResponseType;
use super::{BlockComponent, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS};
use crate::sync::block_lookups::common::RequestState;
use crate::sync::block_lookups::Id;
use crate::sync::network_context::{LookupRequestResult, SyncNetworkContext};
use beacon_chain::BeaconChainTypes;
use derivative::Derivative;
use itertools::Itertools;
use rand::seq::IteratorRandom;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Hash256;
use strum::IntoStaticStr;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{EthSpec, SignedBeaconBlock};

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
    /// Error sending event to network or beacon processor
    SendFailed(&'static str),
    /// Inconsistent lookup request state
    BadState(String),
    /// Lookup failed for some other reason and should be dropped
    Failed,
    /// Attempted to retrieve a not known lookup id
    UnknownLookup,
}

#[derive(Derivative)]
#[derivative(Debug(bound = "T: BeaconChainTypes"))]
pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    pub block_request_state: BlockRequestState<T::EthSpec>,
    pub blob_request_state: BlobRequestState<T::EthSpec>,
    block_root: Hash256,
    awaiting_parent: Option<Hash256>,
    created: Instant,
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
            block_request_state: BlockRequestState::new(requested_block_root, peers),
            blob_request_state: BlobRequestState::new(requested_block_root, peers),
            block_root: requested_block_root,
            awaiting_parent,
            created: Instant::now(),
        }
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
            BlockComponent::Blob(_) => {
                // For now ignore single blobs, as the blob request state assumes all blobs are
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

    /// Get all unique used peers across block and blob requests.
    pub fn all_used_peers(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.block_request_state
            .state
            .get_used_peers()
            .chain(self.blob_request_state.state.get_used_peers())
            .unique()
    }

    /// Get all unique available peers across block and blob requests.
    pub fn all_available_peers(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.block_request_state
            .state
            .get_available_peers()
            .chain(self.blob_request_state.state.get_available_peers())
            .unique()
    }

    /// Makes progress on all requests of this lookup. Any error is not recoverable and must result
    /// in dropping the lookup. May mark the lookup as completed.
    pub fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        // TODO: Check what's necessary to download, specially for blobs
        self.continue_request::<BlockRequestState<T::EthSpec>>(cx)?;
        self.continue_request::<BlobRequestState<T::EthSpec>>(cx)?;

        // If all components of this lookup are already processed, there will be no future events
        // that can make progress so it must be dropped. Consider the lookup completed.
        // This case can happen if we receive the components from gossip during a retry.
        if self.block_request_state.state.is_processed()
            && self.blob_request_state.state.is_processed()
        {
            Ok(LookupResult::Completed)
        } else {
            Ok(LookupResult::Pending)
        }
    }

    /// Potentially makes progress on this request if it's in a progress-able state
    pub fn continue_request<R: RequestState<T>>(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        let id = self.id;
        let awaiting_parent = self.awaiting_parent.is_some();
        let downloaded_block_expected_blobs = self
            .block_request_state
            .state
            .peek_downloaded_data()
            .map(|block| block.num_expected_blobs());
        let block_is_processed = self.block_request_state.state.is_processed();
        let request = R::request_state_mut(self);

        // Attempt to progress awaiting downloads
        if request.get_state().is_awaiting_download() {
            // Verify the current request has not exceeded the maximum number of attempts.
            let request_state = request.get_state();
            if request_state.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                let cannot_process = request_state.more_failed_processing_attempts();
                return Err(LookupRequestError::TooManyAttempts { cannot_process });
            }

            let Some(peer_id) = request.get_state_mut().use_rand_available_peer() else {
                if awaiting_parent {
                    // Allow lookups awaiting for a parent to have zero peers. If when the parent
                    // resolve they still have zero peers the lookup will fail gracefully.
                    return Ok(());
                } else {
                    return Err(LookupRequestError::NoPeers);
                }
            };

            match request.make_request(id, peer_id, downloaded_block_expected_blobs, cx)? {
                LookupRequestResult::RequestSent => request.get_state_mut().on_download_start()?,
                LookupRequestResult::NoRequestNeeded => {
                    request.get_state_mut().on_completed_request()?
                }
                // Sync will receive a future event to make progress on the request, do nothing now
                LookupRequestResult::Pending => return Ok(()),
            }

        // Otherwise, attempt to progress awaiting processing
        // If this request is awaiting a parent lookup to be processed, do not send for processing.
        // The request will be rejected with unknown parent error.
        } else if !awaiting_parent
            && (block_is_processed || matches!(R::response_type(), ResponseType::Block))
        {
            // maybe_start_processing returns Some if state == AwaitingProcess. This pattern is
            // useful to conditionally access the result data.
            if let Some(result) = request.get_state_mut().maybe_start_processing() {
                return R::send_for_processing(id, result, cx);
            }
        }

        Ok(())
    }

    /// Add peer to all request states. The peer must be able to serve this request.
    /// Returns true if the peer was newly inserted into some request state.
    pub fn add_peer(&mut self, peer_id: PeerId) -> bool {
        let inserted_block = self.block_request_state.state.add_peer(&peer_id);
        let inserted_blob = self.blob_request_state.state.add_peer(&peer_id);
        inserted_block || inserted_blob
    }

    /// Returns true if the block has already been downloaded.
    pub fn both_components_processed(&self) -> bool {
        self.block_request_state.state.is_processed()
            && self.blob_request_state.state.is_processed()
    }

    /// Remove peer from available peers. Return true if there are no more available peers and all
    /// requests are not expecting any future event (AwaitingDownload).
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> bool {
        self.block_request_state.state.remove_peer(peer_id)
            && self.blob_request_state.state.remove_peer(peer_id)
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
    pub fn new(block_root: Hash256, peer_source: &[PeerId]) -> Self {
        Self {
            block_root,
            state: SingleLookupRequestState::new(peer_source),
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
    pub fn new(block_root: Hash256, peers: &[PeerId]) -> Self {
        Self {
            requested_block_root: block_root,
            state: SingleLookupRequestState::new(peers),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DownloadResult<T: Clone> {
    pub value: T,
    pub block_root: Hash256,
    pub seen_timestamp: Duration,
    pub peer_id: PeerId,
}

#[derive(PartialEq, Eq, IntoStaticStr)]
pub enum State<T: Clone> {
    AwaitingDownload,
    Downloading,
    AwaitingProcess(DownloadResult<T>),
    /// Request is processing, sent by lookup sync
    Processing(DownloadResult<T>),
    /// Request is processed:
    /// - `Processed(Some)` if lookup sync downloaded and sent to process this request
    /// - `Processed(None)` if another source (i.e. gossip) sent this component for processing
    Processed(Option<PeerId>),
}

/// Object representing the state of a single block or blob lookup request.
#[derive(PartialEq, Eq, Derivative)]
#[derivative(Debug)]
pub struct SingleLookupRequestState<T: Clone> {
    /// State of this request.
    state: State<T>,
    /// Peers that should have this block or blob.
    #[derivative(Debug(format_with = "fmt_peer_set"))]
    available_peers: HashSet<PeerId>,
    /// Peers from which we have requested this block.
    #[derivative(Debug = "ignore")]
    used_peers: HashSet<PeerId>,
    /// How many times have we attempted to process this block or blob.
    failed_processing: u8,
    /// How many times have we attempted to download this block or blob.
    failed_downloading: u8,
}

impl<T: Clone> SingleLookupRequestState<T> {
    pub fn new(peers: &[PeerId]) -> Self {
        let mut available_peers = HashSet::default();
        for peer in peers.iter().copied() {
            available_peers.insert(peer);
        }

        Self {
            state: State::AwaitingDownload,
            available_peers,
            used_peers: HashSet::default(),
            failed_processing: 0,
            failed_downloading: 0,
        }
    }

    pub fn is_awaiting_download(&self) -> bool {
        match self.state {
            State::AwaitingDownload => true,
            State::Downloading { .. }
            | State::AwaitingProcess { .. }
            | State::Processing { .. }
            | State::Processed { .. } => false,
        }
    }

    pub fn is_processed(&self) -> bool {
        match self.state {
            State::AwaitingDownload
            | State::Downloading { .. }
            | State::AwaitingProcess { .. }
            | State::Processing { .. } => false,
            State::Processed { .. } => true,
        }
    }

    pub fn peek_downloaded_data(&self) -> Option<&T> {
        match &self.state {
            State::AwaitingDownload => None,
            State::Downloading { .. } => None,
            State::AwaitingProcess(result) => Some(&result.value),
            State::Processing(result) => Some(&result.value),
            State::Processed { .. } => None,
        }
    }

    /// Switch to `AwaitingProcessing` if the request is in `AwaitingDownload` state, otherwise
    /// ignore.
    pub fn insert_verified_response(&mut self, result: DownloadResult<T>) -> bool {
        if let State::AwaitingDownload = &self.state {
            self.state = State::AwaitingProcess(result);
            true
        } else {
            false
        }
    }

    /// Switch to `Downloading` if the request is in `AwaitingDownload` state, otherwise returns None.
    pub fn on_download_start(&mut self) -> Result<(), LookupRequestError> {
        match &self.state {
            State::AwaitingDownload => {
                self.state = State::Downloading;
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_start expected AwaitingDownload got {other}"
            ))),
        }
    }

    /// Registers a failure in downloading a block. This might be a peer disconnection or a wrong
    /// block.
    pub fn on_download_failure(&mut self) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Downloading => {
                self.failed_downloading = self.failed_downloading.saturating_add(1);
                self.state = State::AwaitingDownload;
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_failure expected Downloading got {other}"
            ))),
        }
    }

    pub fn on_download_success(
        &mut self,
        result: DownloadResult<T>,
    ) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Downloading => {
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
    pub fn on_processing_failure(&mut self) -> Result<PeerId, LookupRequestError> {
        match &self.state {
            State::Processing(result) => {
                let peer_id = result.peer_id;
                self.failed_processing = self.failed_processing.saturating_add(1);
                self.state = State::AwaitingDownload;
                Ok(peer_id)
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_processing_failure expected Processing got {other}"
            ))),
        }
    }

    pub fn on_processing_success(&mut self) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Processing(result) => {
                self.state = State::Processed(Some(result.peer_id));
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_processing_success expected Processing got {other}"
            ))),
        }
    }

    pub fn on_post_process_validation_failure(
        &mut self,
    ) -> Result<Option<PeerId>, LookupRequestError> {
        match &self.state {
            State::Processed(peer_id) => {
                let peer_id = *peer_id;
                self.failed_processing = self.failed_processing.saturating_add(1);
                self.state = State::AwaitingDownload;
                Ok(peer_id)
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_post_process_validation_failure expected Processed got {other}"
            ))),
        }
    }

    /// Mark a request as complete without any download or processing
    pub fn on_completed_request(&mut self) -> Result<(), LookupRequestError> {
        match &self.state {
            State::AwaitingDownload => {
                self.state = State::Processed(None);
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

    /// Add peer to this request states. The peer must be able to serve this request.
    /// Returns true if the peer is newly inserted.
    pub fn add_peer(&mut self, peer_id: &PeerId) -> bool {
        self.available_peers.insert(*peer_id)
    }

    /// Remove peer from available peers. Return true if there are no more available peers and the
    /// request is not expecting any future event (AwaitingDownload).
    pub fn remove_peer(&mut self, disconnected_peer_id: &PeerId) -> bool {
        self.available_peers.remove(disconnected_peer_id);
        self.available_peers.is_empty() && self.is_awaiting_download()
    }

    pub fn get_used_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.used_peers.iter()
    }

    pub fn get_available_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.available_peers.iter()
    }

    /// Selects a random peer from available peers if any, inserts it in used peers and returns it.
    pub fn use_rand_available_peer(&mut self) -> Option<PeerId> {
        let peer_id = self
            .available_peers
            .iter()
            .choose(&mut rand::thread_rng())
            .copied()?;
        self.used_peers.insert(peer_id);
        Some(peer_id)
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
            Self::AwaitingDownload => write!(f, "AwaitingDownload"),
            Self::Downloading => write!(f, "Downloading"),
            Self::AwaitingProcess(d) => write!(f, "AwaitingProcess({:?})", d.peer_id),
            Self::Processing(d) => write!(f, "Processing({:?})", d.peer_id),
            Self::Processed(_) => write!(f, "Processed"),
        }
    }
}

fn fmt_peer_set(
    peer_set: &HashSet<PeerId>,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{}", peer_set.len())
}
