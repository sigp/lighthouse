use super::{BlockComponent, PeerId};
use crate::sync::block_lookups::common::RequestState;
use crate::sync::block_lookups::Id;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::data_availability_checker::{DataAvailabilityChecker, MissingBlobs};
use beacon_chain::BeaconChainTypes;
use itertools::Itertools;
use rand::seq::IteratorRandom;
use slog::{debug, Logger};
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use strum::IntoStaticStr;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{EthSpec, SignedBeaconBlock};

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupRequestError {
    /// Too many failed attempts
    TooManyAttempts {
        /// The failed attempts were primarily due to processing failures.
        cannot_process: bool,
    },
    NoPeers,
    SendFailed(&'static str),
    BadState(String),
}

pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    pub block_request_state: BlockRequestState<T::EthSpec>,
    pub blob_request_state: BlobRequestState<T::EthSpec>,
    pub da_checker: Arc<DataAvailabilityChecker<T>>,
    block_root: Hash256,
    parent_root: Option<Hash256>,
}

impl<T: BeaconChainTypes> SingleBlockLookup<T> {
    pub fn new(
        requested_block_root: Hash256,
        peers: &[PeerId],
        da_checker: Arc<DataAvailabilityChecker<T>>,
        id: Id,
    ) -> Self {
        let is_deneb = da_checker.is_deneb();

        Self {
            id,
            block_request_state: BlockRequestState::new(requested_block_root, peers),
            blob_request_state: BlobRequestState::new(requested_block_root, peers, is_deneb),
            da_checker,
            block_root: requested_block_root,
            parent_root: todo!(),
        }
    }

    /// Get the block root that is being requested.
    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn parent_root(&self) -> Option<Hash256> {
        self.parent_root
    }

    pub fn add_child_components(
        &mut self,
        peer_id: PeerId,
        block_component: BlockComponent<T::EthSpec>,
    ) {
        match block_component {
            BlockComponent::Block(block) => {
                self.block_request_state
                    .state
                    .insert_verified_response(peer_id, block);
            }
            BlockComponent::Blob(blob) => {
                // For now ignore single blobs, as the blob request state assumes all blobs are
                // attributed to the same peer = the peer serving the remaining blobs. Ignoring this
                // block component has a minor effect, causing the node to re-request this blob
                // once the parent chain is successfully resolved
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
            .chain(self.blob_request_state.state.get_used_peers())
            .unique()
    }

    pub fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        // TODO: Check what's necessary to download, specially for blobs
        self.block_request_state.continue_request(self.id, cx)?;
        self.blob_request_state.continue_request(self.id, cx)?;
        Ok(())
    }

    /// Add all given peers to both block and blob request states.
    pub fn add_peer(&mut self, peer_id: PeerId) {
        self.block_request_state.state.add_peer(&peer_id);
        self.blob_request_state.state.add_peer(&peer_id);
    }

    /// Add all given peers to both block and blob request states.
    pub fn add_peers(&mut self, peers: &[PeerId]) {
        for peer in peers {
            self.add_peer(*peer);
        }
    }

    /// Returns true if the block has already been downloaded.
    pub fn both_components_processed(&self) -> bool {
        self.block_request_state.state.is_processed()
            && self.blob_request_state.state.is_processed()
    }

    /// Checks both the block and blob request states to see if the peer is disconnected.
    ///
    /// Returns true if the lookup should be dropped.
    pub fn should_drop_lookup_on_disconnected_peer(
        &mut self,
        peer_id: &PeerId,
        cx: &mut SyncNetworkContext<T>,
        log: &Logger,
    ) -> bool {
        let block_root = self.block_root();
        let block_peer_disconnected = self
            .block_request_state
            .state
            .check_peer_disconnected(peer_id)
            .is_err();
        let blob_peer_disconnected = self
            .blob_request_state
            .state
            .check_peer_disconnected(peer_id)
            .is_err();

        if self.all_available_peers().count() == 0 {
            return true;
        }

        // If there was an active download request with this peer, send them again with another
        // peer. We should receive an RPCError anyway, but this should speed things up?
        if block_peer_disconnected || blob_peer_disconnected {
            if let Err(e) = self.continue_requests(cx) {
                debug!(log, "Single lookup failed on retry after peer disconnection"; "block_root" => ?block_root, "error" => ?e);
                return true;
            }
        }
        false
    }

    /// If `child_components` is `Some`, we know block components won't hit the data
    /// availability cache, so we don't check its processing cache unless `child_components`
    /// is `None`.
    pub(crate) fn missing_blob_ids(&self) -> MissingBlobs {
        let _block_root = self.block_root();
        // TODO: Check against currently downloaded blobs, and the blobs in the da_checker to figure
        // out what is remaining to be downloaded
        todo!();
    }
}

/// The state of the blob request component of a `SingleBlockLookup`.
pub struct BlobRequestState<E: EthSpec> {
    /// The latest picture of which blobs still need to be requested. This includes information
    /// from both block/blobs downloaded in the network layer and any blocks/blobs that exist in
    /// the data availability checker.
    pub requested_ids: MissingBlobs,
    pub block_root: Hash256,
    pub state: SingleLookupRequestState<FixedBlobSidecarList<E>>,
}

impl<E: EthSpec> BlobRequestState<E> {
    pub fn new(block_root: Hash256, peer_source: &[PeerId], is_deneb: bool) -> Self {
        let default_ids = MissingBlobs::new_without_block(block_root, is_deneb);
        Self {
            block_root,
            requested_ids: default_ids,
            state: SingleLookupRequestState::new(peer_source),
        }
    }
}

/// The state of the block request component of a `SingleBlockLookup`.
pub struct BlockRequestState<E: EthSpec> {
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

pub type DownloadResult<T> = (T, Hash256, Duration);

#[derive(Debug, PartialEq, Eq)]
pub enum State<T: Clone> {
    AwaitingDownload,
    Downloading { peer_id: PeerId },
    AwaitingProcess(PeerId, DownloadResult<T>),
    Processing(PeerId, DownloadResult<T>),
    Processed { peer_id: PeerId },
}

/// Object representing the state of a single block or blob lookup request.
#[derive(PartialEq, Eq, Debug)]
pub struct SingleLookupRequestState<T: Clone> {
    /// State of this request.
    state: State<T>,
    /// Peers that should have this block or blob.
    available_peers: HashSet<PeerId>,
    /// Peers from which we have requested this block.
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

    pub fn is_processed(&self) -> bool {
        match self.state {
            State::AwaitingDownload => false,
            State::Downloading { .. } => false,
            State::AwaitingProcess { .. } => false,
            State::Processing { .. } => false,
            State::Processed { .. } => true,
        }
    }

    pub fn insert_verified_response(&mut self, peer_id: PeerId, result: DownloadResult<T>) {
        match &self.state {
            State::AwaitingDownload => {
                self.state = State::AwaitingProcess(peer_id, result);
            }
            _ => {}
        }
    }

    /// Switch to `Downloading` if the request is in `AwaitingDownload` state, otherwise returns None.
    pub fn maybe_start_download(&mut self) -> Result<Option<PeerId>, LookupRequestError> {
        Ok(match &self.state {
            State::AwaitingDownload => {
                let peer_id = self
                    .use_rand_available_peer()
                    .ok_or(LookupRequestError::NoPeers)?;
                self.state = State::Downloading { peer_id };
                Some(peer_id)
            }
            _ => None,
        })
    }

    /// Registers a failure in downloading a block. This might be a peer disconnection or a wrong
    /// block.
    pub fn on_download_failure(&mut self) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Downloading { .. } => {
                self.failed_downloading = self.failed_downloading.saturating_add(1);
                self.state = State::AwaitingDownload;
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "request bad state, expected Downloading got {other}"
            ))),
        }
    }

    pub fn on_download_success(
        &mut self,
        result: DownloadResult<T>,
    ) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Downloading { peer_id } => {
                self.state = State::AwaitingProcess(*peer_id, result);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "request bad state, expected Downloading got {other}"
            ))),
        }
    }

    /// Switch to `Processing` if the request is in `AwaitingProcess` state, otherwise returns None.
    pub fn maybe_start_processing(&mut self) -> Option<DownloadResult<T>> {
        // For 2 lines replace state with placeholder to gain ownership of `result`
        match &self.state {
            State::AwaitingProcess(peer_id, result) => {
                let result = result.clone();
                self.state = State::Processing(*peer_id, result.clone());
                Some(result)
            }
            _ => None,
        }
    }

    /// Revert into `AwaitingProcessing`, if the payload if not invalid and can be submitted for
    /// processing latter.
    pub fn into_awaiting_processing(&mut self) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Processing(peer_id, result) => {
                self.state = State::AwaitingProcess(*peer_id, result.clone());
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "request bad state, expected Processing got {other}"
            ))),
        }
    }

    /// Registers a failure in processing a block.
    pub fn on_processing_failure(&mut self) -> Result<PeerId, LookupRequestError> {
        match &self.state {
            State::Processing(peer_id, _) => {
                let peer_id = *peer_id;
                self.failed_processing = self.failed_processing.saturating_add(1);
                self.state = State::AwaitingDownload;
                Ok(peer_id)
            }
            other => Err(LookupRequestError::BadState(format!(
                "request bad state, expected Processing got {other}"
            ))),
        }
    }

    pub fn on_processing_success(&mut self) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Processing(peer_id, _) => {
                self.state = State::Processed { peer_id: *peer_id };
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "request bad state, expected Processing got {other}"
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

    /// This method should be used for peers wrapped in `PeerId::BlockAndBlobs`.
    pub fn add_peer(&mut self, peer_id: &PeerId) {
        self.available_peers.insert(*peer_id);
    }

    /// If a peer disconnects, this request could be failed. If so, an error is returned
    pub fn check_peer_disconnected(&mut self, dc_peer_id: &PeerId) -> Result<(), ()> {
        self.available_peers.remove(dc_peer_id);
        if let State::Downloading { peer_id } = &self.state {
            if peer_id == dc_peer_id {
                // Peer disconnected before providing a block
                self.on_download_failure();
                return Err(());
            }
        }
        Ok(())
    }

    /// Returns the id peer we downloaded from if we have downloaded a verified block, otherwise
    /// returns an error.
    pub fn processing_peer(&self) -> Result<PeerId, String> {
        match &self.state {
            State::Processing(peer_id, _) | State::Processed { peer_id } => Ok(*peer_id),
            other => Err(format!("not in processing state: {}", other).to_string()),
        }
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

impl<T: BeaconChainTypes> slog::Value for SingleBlockLookup<T> {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("request", key)?;
        serializer.emit_arguments("hash", &format_args!("{}", self.block_root()))?;
        serializer.emit_arguments(
            "blob_ids",
            &format_args!("{:?}", self.blob_request_state.requested_ids.indices()),
        )?;
        serializer.emit_arguments(
            "block_request_state.state",
            &format_args!("{:?}", self.block_request_state.state),
        )?;
        serializer.emit_arguments(
            "blob_request_state.state",
            &format_args!("{:?}", self.blob_request_state.state),
        )?;
        slog::Result::Ok(())
    }
}

impl<T: Clone> slog::Value for SingleLookupRequestState<T> {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("request_state", key)?;
        match &self.state {
            State::AwaitingDownload => {
                "awaiting_download".serialize(record, "state", serializer)?
            }
            State::Downloading { peer_id } => {
                serializer.emit_arguments("downloading_peer", &format_args!("{}", peer_id))?
            }
            State::AwaitingProcess(peer_id, _) => serializer
                .emit_arguments("awaiting_processing_peer", &format_args!("{}", peer_id))?,
            State::Processing(peer_id, _) => {
                serializer.emit_arguments("processing_peer", &format_args!("{}", peer_id))?
            }
            State::Processed { .. } => "processed".serialize(record, "state", serializer)?,
        }
        serializer.emit_u8("failed_downloads", self.failed_downloading)?;
        serializer.emit_u8("failed_processing", self.failed_processing)?;
        slog::Result::Ok(())
    }
}

impl<T: Clone> std::fmt::Display for State<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::AwaitingDownload => write!(f, "AwaitingDownload"),
            State::Downloading { .. } => write!(f, "Downloading"),
            State::AwaitingProcess { .. } => write!(f, "AwaitingProcessing"),
            State::Processing { .. } => write!(f, "Processing"),
            State::Processed { .. } => write!(f, "Processed"),
        }
    }
}
