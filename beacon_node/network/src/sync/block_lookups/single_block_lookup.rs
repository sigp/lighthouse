use super::common::LookupType;
use super::PeerId;
use crate::sync::block_lookups::common::RequestState;
use crate::sync::block_lookups::Id;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::data_availability_checker::ChildComponents;
use beacon_chain::data_availability_checker::{
    AvailabilityCheckError, DataAvailabilityChecker, MissingBlobs,
};
use beacon_chain::BeaconChainTypes;
use itertools::Itertools;
use lighthouse_network::PeerAction;
use rand::seq::IteratorRandom;
use slog::{debug, Logger};
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use store::Hash256;
use strum::IntoStaticStr;
use types::EthSpec;

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
    pub lookup_type: LookupType,
    pub block_request_state: BlockRequestState,
    pub blob_request_state: BlobRequestState,
    pub da_checker: Arc<DataAvailabilityChecker<T>>,
    /// Only necessary for requests triggered by an `UnknownBlockParent` or `UnknownBlockParent`
    /// because any blocks or blobs without parents won't hit the data availability cache.
    pub child_components: Option<ChildComponents<T::EthSpec>>,
}

impl<T: BeaconChainTypes> SingleBlockLookup<T> {
    pub fn new(
        requested_block_root: Hash256,
        child_components: Option<ChildComponents<T::EthSpec>>,
        peers: &[PeerId],
        da_checker: Arc<DataAvailabilityChecker<T>>,
        id: Id,
        lookup_type: LookupType,
    ) -> Self {
        let is_deneb = da_checker.is_deneb();
        Self {
            id,
            lookup_type,
            block_request_state: BlockRequestState::new(requested_block_root, peers),
            blob_request_state: BlobRequestState::new(requested_block_root, peers, is_deneb),
            da_checker,
            child_components,
        }
    }

    /// Get the block root that is being requested.
    pub fn block_root(&self) -> Hash256 {
        self.block_request_state.requested_block_root
    }

    /// Check the block root matches the requested block root.
    pub fn is_for_block(&self, block_root: Hash256) -> bool {
        self.block_root() == block_root
    }

    /// Update the requested block, this should only be used in a chain of parent lookups to request
    /// the next parent.
    pub fn update_requested_parent_block(&mut self, block_root: Hash256) {
        self.block_request_state.requested_block_root = block_root;
        self.blob_request_state.block_root = block_root;
        self.block_request_state.state.state = State::AwaitingDownload;
        self.blob_request_state.state.state = State::AwaitingDownload;
        self.child_components = Some(ChildComponents::empty(block_root));
    }

    /// Get all unique used peers across block and blob requests.
    pub fn all_used_peers(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.block_request_state
            .state
            .get_used_peers()
            .chain(self.blob_request_state.state.get_used_peers())
            .unique()
    }

    /// Send the necessary requests for blocks and/or blobs. This will check whether we have
    /// downloaded the block and/or blobs already and will not send requests if so. It will also
    /// inspect the request state or blocks and blobs to ensure we are not already processing or
    /// downloading the block and/or blobs.
    pub fn request_block_and_blobs(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        let block_already_downloaded = self.block_already_downloaded();
        let blobs_already_downloaded = self.blobs_already_downloaded();

        if !block_already_downloaded {
            self.block_request_state
                .build_request_and_send(self.id, self.lookup_type, cx)?;
        }
        if !blobs_already_downloaded {
            self.blob_request_state
                .build_request_and_send(self.id, self.lookup_type, cx)?;
        }
        Ok(())
    }

    /// Returns a `CachedChild`, which is a wrapper around a `RpcBlock` that is either:
    ///
    /// 1. `NotRequired`: there is no child caching required for this lookup.
    /// 2. `DownloadIncomplete`: Child caching is required, but all components are not yet downloaded.
    /// 3. `Ok`: The child is required and we have downloaded it.
    /// 4. `Err`: The child is required, but has failed consistency checks.
    pub fn get_cached_child_block(&self) -> CachedChild<T::EthSpec> {
        if let Some(components) = self.child_components.as_ref() {
            let Some(block) = components.downloaded_block.as_ref() else {
                return CachedChild::DownloadIncomplete;
            };

            if !self.missing_blob_ids().is_empty() {
                return CachedChild::DownloadIncomplete;
            }

            match RpcBlock::new_from_fixed(
                self.block_request_state.requested_block_root,
                block.clone(),
                components.downloaded_blobs.clone(),
            ) {
                Ok(rpc_block) => CachedChild::Ok(rpc_block),
                Err(e) => CachedChild::Err(e),
            }
        } else {
            CachedChild::NotRequired
        }
    }

    /// Accepts a verified response, and adds it to the child components if required. This method
    /// returns a `CachedChild` which provides a completed block + blob response if all components have been
    /// received, or information about whether the child is required and if it has been downloaded.
    pub fn add_response<R: RequestState<T>>(
        &mut self,
        verified_response: R::VerifiedResponseType,
    ) -> CachedChild<T::EthSpec> {
        if let Some(child_components) = self.child_components.as_mut() {
            R::add_to_child_components(verified_response, child_components);
            self.get_cached_child_block()
        } else {
            CachedChild::NotRequired
        }
    }

    /// Add a child component to the lookup request. Merges with any existing child components.
    pub fn add_child_components(&mut self, components: ChildComponents<T::EthSpec>) {
        if let Some(ref mut existing_components) = self.child_components {
            let ChildComponents {
                block_root: _,
                downloaded_block,
                downloaded_blobs,
            } = components;
            if let Some(block) = downloaded_block {
                existing_components.merge_block(block);
            }
            existing_components.merge_blobs(downloaded_blobs);
        } else {
            self.child_components = Some(components);
        }
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
    pub fn both_components_downloaded(&self) -> bool {
        self.block_request_state.state.is_downloaded()
            && self.blob_request_state.state.is_downloaded()
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

        if block_peer_disconnected || blob_peer_disconnected {
            if let Err(e) = self.request_block_and_blobs(cx) {
                debug!(log, "Single lookup failed on peer disconnection"; "block_root" => ?block_root, "error" => ?e);
                return true;
            }
        }
        false
    }

    /// Returns `true` if the block has already been downloaded.
    pub(crate) fn block_already_downloaded(&self) -> bool {
        if let Some(components) = self.child_components.as_ref() {
            components.downloaded_block.is_some()
        } else {
            self.da_checker.has_block(&self.block_root())
        }
    }

    /// Updates the `requested_ids` field of the `BlockRequestState` with the most recent picture
    /// of which blobs still need to be requested. Returns `true` if there are no more blobs to
    /// request.
    pub(crate) fn blobs_already_downloaded(&mut self) -> bool {
        if matches!(self.blob_request_state.state.state, State::AwaitingDownload) {
            self.update_blobs_request();
        }
        self.blob_request_state.requested_ids.is_empty()
    }

    /// Updates this request with the most recent picture of which blobs still need to be requested.
    pub fn update_blobs_request(&mut self) {
        self.blob_request_state.requested_ids = self.missing_blob_ids();
    }

    /// If `child_components` is `Some`, we know block components won't hit the data
    /// availability cache, so we don't check its processing cache unless `child_components`
    /// is `None`.
    pub(crate) fn missing_blob_ids(&self) -> MissingBlobs {
        let block_root = self.block_root();
        if let Some(components) = self.child_components.as_ref() {
            self.da_checker.get_missing_blob_ids(
                block_root,
                components.downloaded_block.as_ref().map(|b| b.as_ref()),
                &components.downloaded_blobs,
            )
        } else {
            self.da_checker.get_missing_blob_ids_with(block_root)
        }
    }

    /// Penalizes a blob peer if it should have blobs but didn't return them to us.
    pub fn penalize_blob_peer(&mut self, cx: &SyncNetworkContext<T>) {
        if let Ok(blob_peer) = self.blob_request_state.state.processing_peer() {
            cx.report_peer(
                blob_peer,
                PeerAction::MidToleranceError,
                "single_blob_failure",
            );
        }
    }

    /// This failure occurs on download, so register a failure downloading, penalize the peer
    /// and clear the blob cache.
    pub fn handle_consistency_failure(&mut self, cx: &SyncNetworkContext<T>) {
        self.penalize_blob_peer(cx);
        if let Some(cached_child) = self.child_components.as_mut() {
            cached_child.clear_blobs();
        }
        self.blob_request_state.state.on_download_failure()
    }

    /// This failure occurs after processing, so register a failure processing, penalize the peer
    /// and clear the blob cache.
    pub fn handle_availability_check_failure(&mut self, cx: &SyncNetworkContext<T>) {
        self.penalize_blob_peer(cx);
        if let Some(cached_child) = self.child_components.as_mut() {
            cached_child.clear_blobs();
        }
        self.blob_request_state.state.on_processing_failure()
    }
}

/// The state of the blob request component of a `SingleBlockLookup`.
pub struct BlobRequestState {
    /// The latest picture of which blobs still need to be requested. This includes information
    /// from both block/blobs downloaded in the network layer and any blocks/blobs that exist in
    /// the data availability checker.
    pub requested_ids: MissingBlobs,
    pub block_root: Hash256,
    pub state: SingleLookupRequestState,
}

impl BlobRequestState {
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
pub struct BlockRequestState {
    pub requested_block_root: Hash256,
    pub state: SingleLookupRequestState,
}

impl BlockRequestState {
    pub fn new(block_root: Hash256, peers: &[PeerId]) -> Self {
        Self {
            requested_block_root: block_root,
            state: SingleLookupRequestState::new(peers),
        }
    }
}

/// This is the status of cached components for a lookup if they are required. It provides information
/// about whether we should send a responses immediately for processing, whether we require more
/// responses, or whether all cached components have been received and the reconstructed block
/// should be sent for processing.
pub enum CachedChild<E: EthSpec> {
    /// All child components have been received, this is the reconstructed block, including all.
    /// It has been checked for consistency between blobs and block, but no consensus checks have
    /// been performed and no kzg verification has been performed.
    Ok(RpcBlock<E>),
    /// All child components have not yet been received.
    DownloadIncomplete,
    /// Child components should not be cached, send this directly for processing.
    NotRequired,
    /// There was an error during consistency checks between block and blobs.
    Err(AvailabilityCheckError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    AwaitingDownload,
    Downloading { peer_id: PeerId },
    Processing { peer_id: PeerId },
    Processed { peer_id: PeerId },
}

/// Object representing the state of a single block or blob lookup request.
#[derive(PartialEq, Eq, Debug)]
pub struct SingleLookupRequestState {
    /// State of this request.
    state: State,
    /// Peers that should have this block or blob.
    available_peers: HashSet<PeerId>,
    /// Peers from which we have requested this block.
    used_peers: HashSet<PeerId>,
    /// How many times have we attempted to process this block or blob.
    failed_processing: u8,
    /// How many times have we attempted to download this block or blob.
    failed_downloading: u8,
    /// Should be incremented everytime this request is retried. The purpose of this is to
    /// differentiate retries of the same block/blob request within a lookup. We currently penalize
    /// peers and retry requests prior to receiving the stream terminator. This means responses
    /// from a prior request may arrive after a new request has been sent, this counter allows
    /// us to differentiate these two responses.
    req_counter: u32,
}

impl SingleLookupRequestState {
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
            req_counter: 0,
        }
    }

    pub fn is_current_req_counter(&self, req_counter: u32) -> bool {
        self.req_counter == req_counter
    }

    pub fn is_awaiting_download(&self) -> bool {
        matches!(self.state, State::AwaitingDownload)
    }

    pub fn is_downloaded(&self) -> bool {
        match self.state {
            State::AwaitingDownload => false,
            State::Downloading { .. } => false,
            State::Processing { .. } => true,
            State::Processed { .. } => true,
        }
    }

    pub fn is_processed(&self) -> bool {
        match self.state {
            State::AwaitingDownload => false,
            State::Downloading { .. } => false,
            State::Processing { .. } => false,
            State::Processed { .. } => true,
        }
    }

    pub fn on_download_start(&mut self, peer_id: PeerId) -> u32 {
        self.state = State::Downloading { peer_id };
        self.req_counter += 1;
        self.req_counter
    }

    /// Registers a failure in downloading a block. This might be a peer disconnection or a wrong
    /// block.
    pub fn on_download_failure(&mut self) {
        self.failed_downloading = self.failed_downloading.saturating_add(1);
        self.state = State::AwaitingDownload;
    }

    pub fn on_download_success(&mut self) -> Result<(), String> {
        match &self.state {
            State::Downloading { peer_id } => {
                self.state = State::Processing { peer_id: *peer_id };
                Ok(())
            }
            other => Err(format!(
                "request bad state, expected downloading got {other}"
            )),
        }
    }

    /// Registers a failure in processing a block.
    pub fn on_processing_failure(&mut self) {
        self.failed_processing = self.failed_processing.saturating_add(1);
        self.state = State::AwaitingDownload;
    }

    pub fn on_processing_success(&mut self) -> Result<(), String> {
        match &self.state {
            State::Processing { peer_id } => {
                self.state = State::Processed { peer_id: *peer_id };
                Ok(())
            }
            other => Err(format!("not in processing state: {}", other).to_string()),
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
            State::Processing { peer_id } | State::Processed { peer_id } => Ok(*peer_id),
            other => Err(format!("not in processing state: {}", other).to_string()),
        }
    }

    pub fn get_used_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.used_peers.iter()
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
        serializer.emit_arguments("lookup_type", &format_args!("{:?}", self.lookup_type))?;
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

impl slog::Value for SingleLookupRequestState {
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
            State::Processing { peer_id } => {
                serializer.emit_arguments("processing_peer", &format_args!("{}", peer_id))?
            }
            State::Processed { .. } => "processed".serialize(record, "state", serializer)?,
        }
        serializer.emit_u8("failed_downloads", self.failed_downloading)?;
        serializer.emit_u8("failed_processing", self.failed_processing)?;
        slog::Result::Ok(())
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::AwaitingDownload => write!(f, "AwaitingDownload"),
            State::Downloading { .. } => write!(f, "Downloading"),
            State::Processing { .. } => write!(f, "Processing"),
            State::Processed { .. } => write!(f, "Processed"),
        }
    }
}
