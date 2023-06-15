use beacon_chain::blob_verification::{AsBlock, BlockWrapper};
use beacon_chain::data_availability_checker::{AvailabilityCheckError, DataAvailabilityChecker};
use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
use lighthouse_network::rpc::RPCError;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
use slog::{debug, error, trace, warn, Logger};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use strum::Display;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{BlobSidecar, SignedBeaconBlock, Slot};

use self::parent_lookup::PARENT_FAIL_TOLERANCE;
use self::parent_lookup::{ParentLookup, ParentVerifyError};
use self::single_block_lookup::{LookupVerifyError, SingleBlockLookup};
use super::manager::BlockProcessingResult;
use super::BatchProcessResult;
use super::{
    manager::{BlockProcessType, Id},
    network_context::SyncNetworkContext,
};
use crate::beacon_processor::{ChainSegmentProcessId, WorkEvent};
use crate::metrics;
use crate::sync::block_lookups::single_block_lookup::{LookupId, UnknownParentComponents};

pub(crate) mod delayed_lookup;
mod parent_lookup;
mod single_block_lookup;
#[cfg(test)]
mod tests;

pub type DownloadedBlocks<T> = (Hash256, BlockWrapper<T>);
pub type RootBlockTuple<T> = (Hash256, Arc<SignedBeaconBlock<T>>);
pub type RootBlobsTuple<T> = (Hash256, FixedBlobSidecarList<T>);

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 3;

pub(crate) struct BlockLookups<T: BeaconChainTypes> {
    /// Parent chain lookups being downloaded.
    parent_lookups: SmallVec<[ParentLookup<T>; 3]>,

    processing_parent_lookups:
        HashMap<Hash256, (Vec<Hash256>, SingleBlockLookup<PARENT_FAIL_TOLERANCE, T>)>,

    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    single_block_lookups: Vec<SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>>,

    da_checker: Arc<DataAvailabilityChecker<T>>,

    /// The logger for the import manager.
    log: Logger,
}

pub type BlockRequestId = Id;
pub type BlobRequestId = Id;

#[derive(Debug, PartialEq)]
enum StreamTerminator {
    True,
    False,
}

impl From<bool> for StreamTerminator {
    fn from(value: bool) -> Self {
        if value {
            StreamTerminator::True
        } else {
            StreamTerminator::False
        }
    }
}

/// Used to track block or blob responses in places we want to reduce code duplication in
/// response handling.
// NOTE: a better solution may be to wrap request `Id` in an enum.
#[derive(Debug, Copy, Clone)]
pub enum ResponseType {
    Block,
    Blob,
}

/// This enum is used to track what a peer *should* be able to respond with respond based on
/// other messages we've seen from this peer on the network. This is useful for peer scoring.
/// We expect a peer tracked by the `BlockAndBlobs` variant to be able to respond to all
/// components of a block. This peer has either sent an attestation for the requested block
/// or has forwarded a block or blob that is a descendant of the requested block. An honest node
/// should not attest unless it has all components of a block, and it should not forward
/// messages if it does not have all components of the parent block. A peer tracked by the
/// `Neither` variant has likely just sent us a block or blob over gossip, in which case we
/// can't know whether the peer has all components of the block, and could be acting honestly
/// by forwarding a message without any other block components.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Display)]
pub enum PeerShouldHave {
    BlockAndBlobs(PeerId),
    Neither(PeerId),
}

impl PeerShouldHave {
    fn as_peer_id(&self) -> &PeerId {
        match self {
            PeerShouldHave::BlockAndBlobs(id) => id,
            PeerShouldHave::Neither(id) => id,
        }
    }
    fn to_peer_id(self) -> PeerId {
        match self {
            PeerShouldHave::BlockAndBlobs(id) => id,
            PeerShouldHave::Neither(id) => id,
        }
    }
    fn should_have_block(&self) -> bool {
        match self {
            PeerShouldHave::BlockAndBlobs(_) => true,
            PeerShouldHave::Neither(_) => false,
        }
    }
}

/// Tracks the conditions under which we want to drop a parent or single block lookup.
#[derive(Debug, Copy, Clone)]
pub enum ShouldRemoveLookup {
    True,
    False,
}

/// Tracks the event that triggered the lookup. This is useful to know whether the lookup
/// is require to cache `UnknownParentComponents`.
pub enum LookupSource {
    UnknownParent,
    MissingComponents,
}

impl<T: BeaconChainTypes> BlockLookups<T> {
    pub fn new(da_checker: Arc<DataAvailabilityChecker<T>>, log: Logger) -> Self {
        Self {
            parent_lookups: Default::default(),
            processing_parent_lookups: Default::default(),
            failed_chains: LRUTimeCache::new(Duration::from_secs(
                FAILED_CHAINS_CACHE_EXPIRY_SECONDS,
            )),
            single_block_lookups: Default::default(),
            da_checker,
            log,
        }
    }

    /* Lookup requests */

    /// Creates a lookup for the block with the given `block_root` and immediately triggers it.
    pub fn search_block(
        &mut self,
        block_root: Hash256,
        peer_source: PeerShouldHave,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let lookup = self.search_block_with(
            block_root,
            None,
            None,
            &[peer_source],
            LookupSource::MissingComponents,
        );

        self.trigger_single_lookup(lookup, cx);
    }
    /// Creates a lookup for the block with the given `block_root`.
    ///
    /// The request is not immediately triggered, and should be triggered by a call to
    /// `trigger_lookup_by_root`.
    pub fn search_block_delayed(&mut self, block_root: Hash256, peer_source: PeerShouldHave) {
        let lookup = self.search_block_with(
            block_root,
            None,
            None,
            &[peer_source],
            LookupSource::MissingComponents,
        );

        self.add_single_lookup(lookup)
    }

    /// Creates a lookup for the block with the given `block_root`, while caching other block
    /// components we've already received. The block components are cached here because we haven't
    /// imported it's parent and therefore can't fully validate it and store it in the data
    /// availability cache.
    ///
    /// The request is immediately triggered.
    pub fn search_child_block(
        &mut self,
        block_root: Hash256,
        block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        blobs: Option<FixedBlobSidecarList<T::EthSpec>>,
        peer_source: &[PeerShouldHave],
        cx: &mut SyncNetworkContext<T>,
    ) {
        let lookup = self.search_block_with(
            block_root,
            block,
            blobs,
            peer_source,
            LookupSource::UnknownParent,
        );

        self.trigger_single_lookup(lookup, cx);
    }

    /// Creates a lookup for the block with the given `block_root`, while caching other block
    /// components we've already received. The block components are cached here because we haven't
    /// imported it's parent and therefore can't fully validate it and store it in the data
    /// availability cache.
    ///
    /// The request is not immediately triggered, and should be triggered by a call to
    /// `trigger_lookup_by_root`.
    pub fn search_child_delayed(
        &mut self,
        block_root: Hash256,
        block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        blobs: Option<FixedBlobSidecarList<T::EthSpec>>,
        peer_source: &[PeerShouldHave],
    ) {
        let lookup = self.search_block_with(
            block_root,
            block,
            blobs,
            peer_source,
            LookupSource::UnknownParent,
        );

        self.add_single_lookup(lookup)
    }

    /// Attempts to trigger the request matching the given `block_root`.
    pub fn trigger_single_lookup(
        &mut self,
        mut single_block_lookup: Option<SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        if let Some(single_block_lookup) = single_block_lookup.as_mut() {
            if !single_block_lookup.triggered
                && single_block_lookup.request_block_and_blobs(cx).is_ok()
            {
                single_block_lookup.triggered = true;
            } else {
                return;
            }
        }
        self.add_single_lookup(single_block_lookup)
    }

    pub fn add_single_lookup(
        &mut self,
        single_block_lookup: Option<SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>>,
    ) {
        if let Some(single_block_lookup) = single_block_lookup {
            self.single_block_lookups.push(single_block_lookup);

            metrics::set_gauge(
                &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
                self.single_block_lookups.len() as i64,
            );
        }
    }

    pub fn trigger_lookup_by_root(
        &mut self,
        block_root: Hash256,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), ()> {
        for lookup in self.single_block_lookups.iter_mut() {
            if lookup.block_request_state.requested_block_root == block_root && !lookup.triggered {
                lookup.request_block_and_blobs(cx)?;
                lookup.triggered = true;
            }
        }
        Ok(())
    }

    pub fn remove_lookup_by_root(&mut self, block_root: Hash256) {
        self.single_block_lookups
            .retain(|lookup| lookup.block_request_state.requested_block_root != block_root);
    }

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    pub fn search_block_with(
        &mut self,
        block_root: Hash256,
        block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        blobs: Option<FixedBlobSidecarList<T::EthSpec>>,
        peers: &[PeerShouldHave],
        lookup_source: LookupSource,
    ) -> Option<SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>> {
        // Do not re-request a block that is already being requested
        if let Some(lookup) = self
            .single_block_lookups
            .iter_mut()
            .find(|lookup| lookup.is_for_block(block_root))
        {
            lookup.add_peers(peers);
            if let Some(block) = block {
                lookup.add_unknown_parent_block(block)
            }
            if let Some(blobs) = blobs {
                lookup.add_unknown_parent_blobs(blobs)
            }
            return None;
        }

        if let Some(parent_lookup) = self.parent_lookups.iter_mut().find(|parent_req| {
            parent_req.is_for_block(block_root) || parent_req.contains_block(&block_root)
        }) {
            parent_lookup.add_peers(peers);

            // If the block was already downloaded, or is being downloaded in this moment, do not
            // request it.
            return None;
        }

        if self
            .processing_parent_lookups
            .values()
            .any(|(hashes, _last_parent_request)| hashes.contains(&block_root))
        {
            // we are already processing this block, ignore it.
            return None;
        }

        debug!(
            self.log,
            "Searching for block";
            "peer_id" => ?peers,
            "block" => ?block_root
        );

        let unknown_parent_components = if matches!(lookup_source, LookupSource::UnknownParent) {
            Some(UnknownParentComponents {
                downloaded_block: block,
                downloaded_blobs: blobs.unwrap_or_default(),
            })
        } else {
            None
        };

        Some(SingleBlockLookup::new(
            block_root,
            unknown_parent_components,
            peers,
            self.da_checker.clone(),
        ))
    }

    /// If a block is attempted to be processed but we do not know its parent, this function is
    /// called in order to find the block's parent.
    pub fn search_parent(
        &mut self,
        slot: Slot,
        block_root: Hash256,
        parent_root: Hash256,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        // Gossip blocks or blobs shouldn't be propagated if parents are unavailable.
        let peer_source = PeerShouldHave::BlockAndBlobs(peer_id);

        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&parent_root) || self.failed_chains.contains(&block_root) {
            debug!(self.log, "Block is from a past failed chain. Dropping";
                "block_root" => ?block_root, "block_slot" => slot);
            return;
        }

        // Make sure this block is not already downloaded, and that neither it or its parent is
        // being searched for.
        if let Some(parent_lookup) = self.parent_lookups.iter_mut().find(|parent_req| {
            parent_req.contains_block(&block_root) || parent_req.is_for_block(block_root)
        }) {
            parent_lookup.add_peers(&[peer_source]);
            // we are already searching for this block, ignore it
            return;
        }

        if self
            .processing_parent_lookups
            .values()
            .any(|(hashes, _peers)| hashes.contains(&block_root) || hashes.contains(&parent_root))
        {
            // we are already processing this block, ignore it.
            return;
        }

        let parent_lookup = ParentLookup::new(
            block_root,
            parent_root,
            peer_source,
            self.da_checker.clone(),
        );
        self.request_parent_block_and_blobs(parent_lookup, cx);
    }

    /* Lookup responses */

    pub fn single_block_lookup_response(
        &mut self,
        id: Id,
        peer_id: PeerId,
        block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        seen_timestamp: Duration,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let stream_terminator = block.is_none().into();
        let log = self.log.clone();

        let Some((has_pending_parent_request, request_ref)) = self.find_single_lookup_request(id, stream_terminator, ResponseType::Block) else {
            return;
        };

        let should_remove = match request_ref.verify_block(block) {
            Ok(Some((block_root, block))) => {
                if let Some(parent_components) = request_ref.unknown_parent_components.as_mut() {
                    parent_components.add_unknown_parent_block(block.clone());
                };

                if !has_pending_parent_request {
                    let block_wrapper = request_ref
                        .get_downloaded_block()
                        .unwrap_or(BlockWrapper::Block(block));
                    // This is the correct block, send it for processing
                    match self.send_block_for_processing(
                        block_root,
                        block_wrapper,
                        seen_timestamp,
                        BlockProcessType::SingleBlock { id },
                        cx,
                    ) {
                        Ok(()) => ShouldRemoveLookup::False,
                        Err(()) => ShouldRemoveLookup::True,
                    }
                } else {
                    ShouldRemoveLookup::False
                }
            }
            Ok(None) => ShouldRemoveLookup::False,
            Err(e) => handle_block_lookup_verify_error(
                request_ref,
                ResponseType::Block,
                peer_id,
                e,
                cx,
                &log,
            ),
        };

        if matches!(should_remove, ShouldRemoveLookup::True) {
            self.single_block_lookups
                .retain(|req| req.id.block_request_id != Some(id));
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    pub fn single_blob_lookup_response(
        &mut self,
        id: Id,
        peer_id: PeerId,
        blob: Option<Arc<BlobSidecar<T::EthSpec>>>,
        seen_timestamp: Duration,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let stream_terminator = blob.is_none().into();

        let log = self.log.clone();

        let Some((has_pending_parent_requests, request_ref)) =
            self.find_single_lookup_request(id, stream_terminator, ResponseType::Blob) else {
            return;
        };

        let should_remove = match request_ref.verify_blob(blob) {
            Ok(Some((block_root, blobs))) => {
                if let Some(parent_components) = request_ref.unknown_parent_components.as_mut() {
                    parent_components.add_unknown_parent_blobs(blobs);

                    if !has_pending_parent_requests {
                        request_ref
                            .get_downloaded_block()
                            .map(|block| {
                                match self.send_block_for_processing(
                                    block_root,
                                    block,
                                    seen_timestamp,
                                    BlockProcessType::SingleBlock { id },
                                    cx,
                                ) {
                                    Ok(()) => ShouldRemoveLookup::False,
                                    Err(()) => ShouldRemoveLookup::True,
                                }
                            })
                            .unwrap_or(ShouldRemoveLookup::False)
                    } else {
                        ShouldRemoveLookup::False
                    }
                } else {
                    // These are the correct blobs, send them for processing
                    match self.send_blobs_for_processing(
                        block_root,
                        blobs,
                        seen_timestamp,
                        BlockProcessType::SingleBlock { id },
                        cx,
                    ) {
                        Ok(()) => ShouldRemoveLookup::False,
                        Err(()) => ShouldRemoveLookup::True,
                    }
                }
            }
            Ok(None) => ShouldRemoveLookup::False,
            Err(e) => handle_block_lookup_verify_error(
                request_ref,
                ResponseType::Blob,
                peer_id,
                e,
                cx,
                &log,
            ),
        };

        if matches!(should_remove, ShouldRemoveLookup::True) {
            self.single_block_lookups
                .retain(|req| req.id.blob_request_id != Some(id));
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /// Returns the lookup along with a `bool` representing whether the lookup has an outstanding
    /// parent lookup that has yet to be resolved. This determines whether we send the
    /// block or blob for processing because we would fail block processing and trigger a new lookup
    /// via `UnknownParentBlock` or `UnknownParentBlob` until we process the parent.
    fn find_single_lookup_request(
        &mut self,
        target_id: Id,
        stream_terminator: StreamTerminator,
        response_type: ResponseType,
    ) -> Option<(
        bool,
        &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    )> {
        let lookup = self.single_block_lookups.iter_mut().find_map(|req| {
            let id_opt = match response_type {
                ResponseType::Block => req.id.block_request_id,
                ResponseType::Blob => req.id.blob_request_id,
            };
            if let Some(lookup_id) = id_opt {
                if lookup_id == target_id {
                    let has_pending_parent_request = self.parent_lookups.iter().any(|lookup| {
                        lookup.chain_hash() == req.block_request_state.requested_block_root
                    });

                    return Some((has_pending_parent_request, req));
                }
            }
            None
        });

        if lookup.is_none() && matches!(stream_terminator, StreamTerminator::False) {
            warn!(
                self.log,
                "Block returned for single block lookup not present";
                "response_type" => ?response_type,
            );
        }
        lookup
    }

    /// Process a response received from a parent lookup request.
    pub fn parent_lookup_response(
        &mut self,
        id: Id,
        peer_id: PeerId,
        block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        seen_timestamp: Duration,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let mut parent_lookup = if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.pending_block_response(id))
        {
            self.parent_lookups.remove(pos)
        } else {
            if block.is_some() {
                debug!(self.log, "Response for a parent lookup request that was not found"; "peer_id" => %peer_id);
            }
            return;
        };

        match parent_lookup.verify_block(block, &mut self.failed_chains) {
            Ok(Some((block_root, block))) => {
                parent_lookup.add_current_request_block(block);
                if let Some(block_wrapper) =
                    parent_lookup.current_parent_request.get_downloaded_block()
                {
                    let chain_hash = parent_lookup.chain_hash();
                    if self
                        .send_block_for_processing(
                            block_root,
                            block_wrapper,
                            seen_timestamp,
                            BlockProcessType::ParentLookup { chain_hash },
                            cx,
                        )
                        .is_ok()
                    {
                        self.parent_lookups.push(parent_lookup)
                    }
                } else {
                    let outstanding_blobs_req = parent_lookup
                        .current_parent_request
                        .id
                        .blob_request_id
                        .is_some();
                    if !outstanding_blobs_req {
                        if let Ok(peer_id) = parent_lookup
                            .current_parent_request
                            .downloading_peer(ResponseType::Blob)
                        {
                            cx.report_peer(
                                peer_id.to_peer_id(),
                                PeerAction::MidToleranceError,
                                "bbroot_failed_chains",
                            );
                        }

                        self.request_parent_blobs(parent_lookup, cx);
                    } else {
                        self.parent_lookups.push(parent_lookup)
                    }
                }
            }
            Ok(None) => {
                // Request finished successfully, nothing else to do. It will be removed after the
                // processing result arrives.
                self.parent_lookups.push(parent_lookup);
            }
            Err(e) => {
                self.handle_parent_verify_error(peer_id, parent_lookup, ResponseType::Block, e, cx)
            }
        };

        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    pub fn parent_lookup_blob_response(
        &mut self,
        id: Id,
        peer_id: PeerId,
        blob: Option<Arc<BlobSidecar<T::EthSpec>>>,
        seen_timestamp: Duration,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let mut parent_lookup = if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.pending_blob_response(id))
        {
            self.parent_lookups.remove(pos)
        } else {
            if blob.is_some() {
                debug!(self.log, "Response for a parent lookup blob request that was not found"; "peer_id" => %peer_id);
            }
            return;
        };

        match parent_lookup.verify_blob(blob, &mut self.failed_chains) {
            Ok(Some((block_root, blobs))) => {
                parent_lookup.add_current_request_blobs(blobs);
                let chain_hash = parent_lookup.chain_hash();
                if let Some(block_wrapper) =
                    parent_lookup.current_parent_request.get_downloaded_block()
                {
                    if self
                        .send_block_for_processing(
                            block_root,
                            block_wrapper,
                            seen_timestamp,
                            BlockProcessType::ParentLookup { chain_hash },
                            cx,
                        )
                        .is_ok()
                    {
                        self.parent_lookups.push(parent_lookup)
                    }
                } else {
                    self.parent_lookups.push(parent_lookup)
                }
            }
            Ok(None) => {
                // Waiting for more blobs to arrive
                self.parent_lookups.push(parent_lookup);
            }
            Err(e) => {
                self.handle_parent_verify_error(peer_id, parent_lookup, ResponseType::Blob, e, cx)
            }
        };

        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    fn handle_parent_verify_error(
        &mut self,
        peer_id: PeerId,
        mut parent_lookup: ParentLookup<T>,
        response_type: ResponseType,
        e: ParentVerifyError,
        cx: &mut SyncNetworkContext<T>,
    ) {
        match e {
            ParentVerifyError::RootMismatch
            | ParentVerifyError::NoBlockReturned
            | ParentVerifyError::NotEnoughBlobsReturned
            | ParentVerifyError::ExtraBlocksReturned
            | ParentVerifyError::UnrequestedBlobId
            | ParentVerifyError::ExtraBlobsReturned
            | ParentVerifyError::InvalidIndex(_) => {
                let e = e.into();
                warn!(self.log, "Peer sent invalid response to parent request.";
                        "peer_id" => %peer_id, "reason" => %e);

                // We do not tolerate these kinds of errors. We will accept a few but these are signs
                // of a faulty peer.
                cx.report_peer(peer_id, PeerAction::LowToleranceError, e);

                // We try again if possible.
                match response_type {
                    ResponseType::Block => self.request_parent_block(parent_lookup, cx),
                    ResponseType::Blob => self.request_parent_blobs(parent_lookup, cx),
                };
            }
            ParentVerifyError::PreviousFailure { parent_root } => {
                debug!(
                    self.log,
                    "Parent chain ignored due to past failure";
                    "block" => %parent_root,
                );
                // Add the root block to failed chains
                self.failed_chains.insert(parent_lookup.chain_hash());

                cx.report_peer(
                    peer_id,
                    PeerAction::MidToleranceError,
                    "bbroot_failed_chains",
                );
            }
            ParentVerifyError::BenignFailure => {
                trace!(
                    self.log,
                    "Requested peer could not respond to block request, requesting a new peer";
                );
                parent_lookup
                    .current_parent_request
                    .remove_peer_if_useless(&peer_id, response_type);
                match response_type {
                    ResponseType::Block => self.request_parent_block(parent_lookup, cx),
                    ResponseType::Blob => self.request_parent_blobs(parent_lookup, cx),
                };
            }
        }
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId, cx: &mut SyncNetworkContext<T>) {
        self.single_block_lookups.retain_mut(|req| {
            let should_remove_block =
                should_remove_disconnected_peer(ResponseType::Block, peer_id, cx, req, &self.log);
            let should_remove_blob =
                should_remove_disconnected_peer(ResponseType::Blob, peer_id, cx, req, &self.log);

            matches!(should_remove_block, ShouldRemoveLookup::False)
                && matches!(should_remove_blob, ShouldRemoveLookup::False)
        });

        /* Check disconnection for parent lookups */
        while let Some(pos) = self.parent_lookups.iter_mut().position(|req| {
            req.check_block_peer_disconnected(peer_id).is_err()
                || req.check_blob_peer_disconnected(peer_id).is_err()
        }) {
            let parent_lookup = self.parent_lookups.remove(pos);
            trace!(self.log, "Parent lookup's peer disconnected"; &parent_lookup);
            self.request_parent_block_and_blobs(parent_lookup, cx);
        }
    }

    /// An RPC error has occurred during a parent lookup. This function handles this case.
    pub fn parent_lookup_failed(
        &mut self,
        id: Id,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
        error: RPCError,
    ) {
        let msg = error.as_static_str();
        if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.pending_block_response(id))
        {
            let mut parent_lookup = self.parent_lookups.remove(pos);
            parent_lookup.block_download_failed();
            trace!(self.log, "Parent lookup block request failed"; &parent_lookup, "error" => msg);

            self.request_parent_block(parent_lookup, cx);
        } else {
            return debug!(self.log, "RPC failure for a block parent lookup request that was not found"; "peer_id" => %peer_id, "error" => msg);
        };

        if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.pending_blob_response(id))
        {
            let mut parent_lookup = self.parent_lookups.remove(pos);
            parent_lookup.blob_download_failed();
            trace!(self.log, "Parent lookup blobs request failed"; &parent_lookup, "error" => msg);

            self.request_parent_blobs(parent_lookup, cx);
        } else {
            return debug!(self.log, "RPC failure for a blobs parent lookup request that was not found"; "peer_id" => %peer_id, "error" => msg);
        };
        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    pub fn single_block_lookup_failed(
        &mut self,
        id: Id,
        peer_id: &PeerId,
        cx: &mut SyncNetworkContext<T>,
        error: RPCError,
    ) {
        let msg = error.as_static_str();
        self.single_block_lookups.retain_mut(|req| {
            let should_remove_block = should_remove_failed_lookup(
                id,
                ResponseType::Block,
                msg,
                peer_id,
                cx,
                req,
                &self.log,
            );
            let should_remove_blob = should_remove_failed_lookup(
                id,
                ResponseType::Blob,
                msg,
                peer_id,
                cx,
                req,
                &self.log,
            );

            matches!(should_remove_block, ShouldRemoveLookup::False)
                && matches!(should_remove_blob, ShouldRemoveLookup::False)
        });

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /* Processing responses */

    pub fn single_block_component_processed(
        &mut self,
        target_id: Id,
        result: BlockProcessingResult<T::EthSpec>,
        response_type: ResponseType,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let lookup_components_opt =
            self.single_block_lookups
                .iter_mut()
                .enumerate()
                .find_map(|(index, req)| {
                    let block_match = req.id.block_request_id.as_ref() == Some(&target_id);
                    let blob_match = req.id.blob_request_id.as_ref() == Some(&target_id);
                    (block_match || blob_match).then_some((index, req))
                });
        let (index, request_ref) = match lookup_components_opt {
            Some(req) => req,
            None => {
                return debug!(
                    self.log,
                    "Block component processed for single block lookup not present"
                );
            }
        };

        let root = request_ref.block_request_state.requested_block_root;
        let peer_id = request_ref.processing_peer(response_type);

        let peer_id = match peer_id {
            Ok(peer) => peer,
            Err(_) => return,
        };

        let should_remove_lookup = match result {
            BlockProcessingResult::Ok(status) => match status {
                AvailabilityProcessingStatus::Imported(root) => {
                    trace!(self.log, "Single block processing succeeded"; "block" => %root);
                    ShouldRemoveLookup::True
                }
                AvailabilityProcessingStatus::MissingComponents(_, _block_root) => {
                    should_remove_missing_components(request_ref, response_type, cx, &self.log)
                }
            },
            BlockProcessingResult::Ignored => {
                // Beacon processor signalled to ignore the block processing result.
                // This implies that the cpu is overloaded. Drop the request.
                warn!(
                    self.log,
                    "Single block processing was ignored, cpu might be overloaded";
                    "action" => "dropping single block request"
                );
                ShouldRemoveLookup::True
            }
            BlockProcessingResult::Err(e) => {
                trace!(self.log, "Single block processing failed"; "block" => %root, "error" => %e);
                match e {
                    BlockError::BlockIsAlreadyKnown => {
                        // No error here
                        ShouldRemoveLookup::True
                    }
                    BlockError::BeaconChainError(e) => {
                        // Internal error
                        error!(self.log, "Beacon chain error processing single block"; "block_root" => %root, "error" => ?e);
                        ShouldRemoveLookup::True
                    }
                    BlockError::ParentUnknown(block) => {
                        let slot = block.slot();
                        let parent_root = block.parent_root();
                        let (block, blobs) = block.deconstruct();
                        request_ref.add_unknown_parent_block(block);
                        if let Some(blobs) = blobs {
                            request_ref.add_unknown_parent_blobs(blobs);
                        }
                        self.search_parent(slot, root, parent_root, peer_id.to_peer_id(), cx);
                        ShouldRemoveLookup::False
                    }
                    ref e @ BlockError::ExecutionPayloadError(ref epe) if !epe.penalize_peer() => {
                        // These errors indicate that the execution layer is offline
                        // and failed to validate the execution payload. Do not downscore peer.
                        debug!(
                            self.log,
                            "Single block lookup failed. Execution layer is offline / unsynced / misconfigured";
                            "root" => %root,
                            "error" => ?e
                        );
                        ShouldRemoveLookup::True
                    }
                    BlockError::AvailabilityCheck(
                        AvailabilityCheckError::KzgVerificationFailed,
                    )
                    | BlockError::AvailabilityCheck(AvailabilityCheckError::Kzg(_))
                    | BlockError::BlobValidation(_) => {
                        warn!(self.log, "Blob validation failure"; "root" => %root, "peer_id" => %peer_id);
                        if let Ok(blob_peer) = request_ref.processing_peer(ResponseType::Blob) {
                            cx.report_peer(
                                blob_peer.to_peer_id(),
                                PeerAction::MidToleranceError,
                                "single_blob_failure",
                            );
                            // Try it again if possible.
                            retry_request_after_failure(
                                request_ref,
                                ResponseType::Blob,
                                peer_id.as_peer_id(),
                                cx,
                                &self.log,
                            )
                        } else {
                            ShouldRemoveLookup::False
                        }
                    }
                    other => {
                        warn!(self.log, "Peer sent invalid block in single block lookup"; "root" => %root, "error" => ?other, "peer_id" => %peer_id);
                        if let Ok(block_peer) = request_ref.processing_peer(ResponseType::Block) {
                            cx.report_peer(
                                block_peer.to_peer_id(),
                                PeerAction::MidToleranceError,
                                "single_block_failure",
                            );

                            // Try it again if possible.
                            retry_request_after_failure(
                                request_ref,
                                ResponseType::Block,
                                block_peer.as_peer_id(),
                                cx,
                                &self.log,
                            )
                        } else {
                            ShouldRemoveLookup::False
                        }
                    }
                }
            }
        };

        if matches!(should_remove_lookup, ShouldRemoveLookup::True) {
            self.single_block_lookups.remove(index);
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    pub fn parent_block_processed(
        &mut self,
        chain_hash: Hash256,
        result: BlockProcessingResult<T::EthSpec>,
        response_type: ResponseType,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let index = self
            .parent_lookups
            .iter()
            .enumerate()
            .find(|(_, lookup)| lookup.chain_hash() == chain_hash)
            .map(|(index, _)| index);

        let Some(mut parent_lookup) = index.map(|index|self.parent_lookups.remove(index)) else {
            return debug!(self.log, "Process response for a parent lookup request that was not found"; "chain_hash" => %chain_hash);
        };

        let peer_id = parent_lookup
            .current_parent_request
            .processing_peer(response_type);

        let peer_id = match peer_id {
            Ok(peer) => peer,
            Err(_) => return,
        };

        match &result {
            BlockProcessingResult::Ok(status) => match status {
                AvailabilityProcessingStatus::Imported(block_root) => {
                    trace!(self.log, "Parent block processing succeeded"; &parent_lookup, "block_root" => ?block_root)
                }
                AvailabilityProcessingStatus::MissingComponents(_, block_root) => {
                    trace!(self.log, "Parent missing parts, triggering single block lookup "; &parent_lookup,"block_root" => ?block_root)
                }
            },
            BlockProcessingResult::Err(e) => {
                trace!(self.log, "Parent block processing failed"; &parent_lookup, "error" => %e)
            }
            BlockProcessingResult::Ignored => {
                trace!(
                    self.log,
                    "Parent block processing job was ignored";
                    "action" => "re-requesting block",
                    &parent_lookup
                );
            }
        }

        match result {
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                _,
                block_root,
            )) => {
                self.search_block(block_root, peer_id, cx);
            }
            BlockProcessingResult::Err(BlockError::ParentUnknown(block)) => {
                parent_lookup.add_unknown_parent_block(block);
                self.request_parent_block_and_blobs(parent_lookup, cx);
            }
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockProcessingResult::Err(BlockError::BlockIsAlreadyKnown { .. }) => {
                // Check if the beacon processor is available
                let beacon_processor_send = match cx.processor_channel_if_enabled() {
                    Some(channel) => channel,
                    None => {
                        return trace!(
                            self.log,
                            "Dropping parent chain segment that was ready for processing.";
                            parent_lookup
                        );
                    }
                };
                let (chain_hash, mut blocks, hashes, block_request) =
                    parent_lookup.parts_for_processing();
                if let Some(child_block) = self.single_block_lookups.iter_mut().find_map(|req| {
                    if req.block_request_state.requested_block_root == chain_hash {
                        req.get_downloaded_block()
                    } else {
                        None
                    }
                }) {
                    blocks.push(child_block);
                };
                let process_id = ChainSegmentProcessId::ParentLookup(chain_hash);
                let work = WorkEvent::chain_segment(process_id, blocks);

                match beacon_processor_send.try_send(work) {
                    Ok(_) => {
                        self.processing_parent_lookups
                            .insert(chain_hash, (hashes, block_request));
                    }
                    Err(e) => {
                        error!(
                            self.log,
                            "Failed to send chain segment to processor";
                            "error" => ?e
                        );
                    }
                }
            }
            ref e @ BlockProcessingResult::Err(BlockError::ExecutionPayloadError(ref epe))
                if !epe.penalize_peer() =>
            {
                // These errors indicate that the execution layer is offline
                // and failed to validate the execution payload. Do not downscore peer.
                debug!(
                    self.log,
                    "Parent lookup failed. Execution layer is offline";
                    "chain_hash" => %chain_hash,
                    "error" => ?e
                );
            }
            BlockProcessingResult::Err(outcome) => {
                self.handle_invalid_block(outcome, peer_id.to_peer_id(), cx, parent_lookup);
            }
            BlockProcessingResult::Ignored => {
                // Beacon processor signalled to ignore the block processing result.
                // This implies that the cpu is overloaded. Drop the request.
                warn!(
                    self.log,
                    "Parent block processing was ignored, cpu might be overloaded";
                    "action" => "dropping parent request"
                );
            }
        }

        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    fn handle_invalid_block(
        &mut self,
        outcome: BlockError<<T as BeaconChainTypes>::EthSpec>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
        mut parent_lookup: ParentLookup<T>,
    ) {
        // all else we consider the chain a failure and downvote the peer that sent
        // us the last block
        warn!(
            self.log, "Invalid parent chain";
            "score_adjustment" => %PeerAction::MidToleranceError,
            "outcome" => ?outcome,
            "last_peer" => %peer_id,
        );
        // This currently can be a host of errors. We permit this due to the partial
        // ambiguity.
        cx.report_peer(peer_id, PeerAction::MidToleranceError, "parent_request_err");
        // Try again if possible
        parent_lookup.block_processing_failed();
        parent_lookup.blob_processing_failed();
        self.request_parent_block_and_blobs(parent_lookup, cx);
    }

    pub fn parent_chain_processed(
        &mut self,
        chain_hash: Hash256,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let request = match self.processing_parent_lookups.remove(&chain_hash) {
            Some((_hashes, request)) => request,
            None => {
                return debug!(self.log, "Chain process response for a parent lookup request that was not found"; "chain_hash" => %chain_hash, "result" => ?result)
            }
        };

        debug!(self.log, "Parent chain processed"; "chain_hash" => %chain_hash, "result" => ?result);
        match result {
            BatchProcessResult::Success { .. } => {
                if let Some((index, _)) = self
                    .single_block_lookups
                    .iter()
                    .enumerate()
                    .find(|(_, req)| req.block_request_state.requested_block_root == chain_hash)
                {
                    if let Some((lookup_id, block_wrapper)) =
                        self.single_block_lookups.get_mut(index).and_then(|lookup| {
                            lookup
                                .get_downloaded_block()
                                .map(|block| (lookup.id.clone(), block))
                        })
                    {
                        let LookupId {
                            block_request_id,
                            blob_request_id,
                        } = lookup_id;
                        let Some(id) = block_request_id.or(blob_request_id) else {
                                warn!(self.log, "No id found for single block lookup"; "chain_hash" => %chain_hash);
                                return;
                            };

                        // This is the correct block, send it for processing
                        if self
                            .send_block_for_processing(
                                chain_hash,
                                block_wrapper,
                                Duration::from_secs(0), //TODO(sean) pipe this through
                                BlockProcessType::SingleBlock { id },
                                cx,
                            )
                            .is_err()
                        {
                            // Remove to avoid inconsistencies
                            self.single_block_lookups.remove(index);
                        }
                    }
                }
            }
            BatchProcessResult::FaultyFailure {
                imported_blocks: _,
                penalty,
            } => {
                self.failed_chains.insert(chain_hash);
                let mut all_peers = request.block_request_state.state.used_peers.clone();
                all_peers.extend(request.blob_request_state.state.used_peers);
                for peer_source in all_peers {
                    cx.report_peer(peer_source, penalty, "parent_chain_failure")
                }
            }
            BatchProcessResult::NonFaultyFailure => {
                // We might request this chain again if there is need but otherwise, don't try again
            }
        }

        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    /* Helper functions */

    fn send_block_for_processing(
        &mut self,
        block_root: Hash256,
        block: BlockWrapper<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), ()> {
        match cx.processor_channel_if_enabled() {
            Some(beacon_processor_send) => {
                trace!(self.log, "Sending block for processing"; "block" => ?block_root, "process" => ?process_type);
                let event = WorkEvent::rpc_beacon_block(block_root, block, duration, process_type);
                if let Err(e) = beacon_processor_send.try_send(event) {
                    error!(
                        self.log,
                        "Failed to send sync block to processor";
                        "error" => ?e
                    );
                    Err(())
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping block ready for processing. Beacon processor not available"; "block" => %block_root);
                Err(())
            }
        }
    }

    fn send_blobs_for_processing(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), ()> {
        let blob_count = blobs.iter().filter(|b| b.is_some()).count();
        if blob_count == 0 {
            return Ok(());
        }
        match cx.processor_channel_if_enabled() {
            Some(beacon_processor_send) => {
                trace!(self.log, "Sending blobs for processing"; "block" => ?block_root, "process_type" => ?process_type);
                let event = WorkEvent::rpc_blobs(block_root, blobs, duration, process_type);
                if let Err(e) = beacon_processor_send.try_send(event) {
                    error!(
                        self.log,
                        "Failed to send sync blobs to processor";
                        "error" => ?e
                    );
                    Err(())
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping blobs ready for processing. Beacon processor not available"; "block_root" => %block_root);
                Err(())
            }
        }
    }

    fn request_parent_block(
        &mut self,
        mut parent_lookup: ParentLookup<T>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let response = parent_lookup.request_parent_block(cx);
        self.handle_response(parent_lookup, cx, response, ResponseType::Block);
    }

    fn request_parent_blobs(
        &mut self,
        mut parent_lookup: ParentLookup<T>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let response = parent_lookup.request_parent_blobs(cx);
        self.handle_response(parent_lookup, cx, response, ResponseType::Blob);
    }

    fn request_parent_block_and_blobs(
        &mut self,
        mut parent_lookup: ParentLookup<T>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let block_res = parent_lookup.request_parent_block(cx);
        match block_res {
            Ok(()) => {
                let blob_res = parent_lookup.request_parent_blobs(cx);
                self.handle_response(parent_lookup, cx, blob_res, ResponseType::Blob)
            }
            Err(e) => {
                self.handle_response(parent_lookup, cx, Err(e), ResponseType::Block);
            }
        }
    }

    fn handle_response(
        &mut self,
        parent_lookup: ParentLookup<T>,
        cx: &mut SyncNetworkContext<T>,
        result: Result<(), parent_lookup::RequestError>,
        response_type: ResponseType,
    ) {
        match result {
            Err(e) => {
                debug!(self.log, "Failed to request parent"; &parent_lookup, "error" => e.as_static());
                match e {
                    parent_lookup::RequestError::SendFailed(_) => {
                        // Probably shutting down, nothing to do here. Drop the request
                    }
                    parent_lookup::RequestError::ChainTooLong => {
                        self.failed_chains.insert(parent_lookup.chain_hash());
                        // This indicates faulty peers.
                        for &peer_id in parent_lookup.used_peers(response_type) {
                            cx.report_peer(peer_id, PeerAction::LowToleranceError, e.as_static())
                        }
                    }
                    parent_lookup::RequestError::TooManyAttempts { cannot_process } => {
                        // We only consider the chain failed if we were unable to process it.
                        // We could have failed because one peer continually failed to send us
                        // bad blocks. We still allow other peers to send us this chain. Note
                        // that peers that do this, still get penalised.
                        if cannot_process {
                            self.failed_chains.insert(parent_lookup.chain_hash());
                        }
                        // This indicates faulty peers.
                        for &peer_id in parent_lookup.used_peers(response_type) {
                            cx.report_peer(peer_id, PeerAction::LowToleranceError, e.as_static())
                        }
                    }
                    parent_lookup::RequestError::NoPeers => {
                        // This happens if the peer disconnects while the block is being
                        // processed. Drop the request without extra penalty
                    }
                }
            }
            Ok(_) => {
                debug!(self.log, "Requesting parent"; &parent_lookup);
                self.parent_lookups.push(parent_lookup)
            }
        }

        // We remove and add back again requests so we want this updated regardless of outcome.
        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    /// Drops all the single block requests and returns how many requests were dropped.
    pub fn drop_single_block_requests(&mut self) -> usize {
        let requests_to_drop = self.single_block_lookups.len();
        self.single_block_lookups.clear();
        requests_to_drop
    }

    /// Drops all the parent chain requests and returns how many requests were dropped.
    pub fn drop_parent_chain_requests(&mut self) -> usize {
        self.parent_lookups.drain(..).len()
    }
}

fn handle_block_lookup_verify_error<T: BeaconChainTypes>(
    request_ref: &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    response_type: ResponseType,
    peer_id: PeerId,
    e: LookupVerifyError,
    cx: &mut SyncNetworkContext<T>,
    log: &Logger,
) -> ShouldRemoveLookup {
    let msg = if matches!(e, LookupVerifyError::BenignFailure) {
        request_ref.remove_peer_if_useless(&peer_id, response_type);
        "peer could not response to request"
    } else {
        let msg = e.into();
        cx.report_peer(peer_id, PeerAction::LowToleranceError, msg);
        msg
    };

    debug!(log, "Single block lookup failed";
        "peer_id" => %peer_id,
        "error" => msg,
        "block_root" => ?request_ref.block_request_state.requested_block_root,
        "response_type" => ?response_type
    );
    retry_request_after_failure(request_ref, response_type, &peer_id, cx, log)
}

fn retry_request_after_failure<T: BeaconChainTypes>(
    request_ref: &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    response_type: ResponseType,
    initial_peer_id: &PeerId,
    cx: &mut SyncNetworkContext<T>,
    log: &Logger,
) -> ShouldRemoveLookup {
    let requested_block_root = request_ref.block_request_state.requested_block_root;

    // try the request again if possible
    match response_type {
        ResponseType::Block => {
            let id = request_ref.request_block().map(|request_opt| {
                request_opt
                    .map(|(peer_id, request)| cx.single_block_lookup_request(peer_id, request))
            });
            match id {
                Ok(Some(Ok(id))) => {
                    request_ref.id.block_request_id = Some(id);
                }
                Ok(Some(Err(e))) => {
                    debug!(log, "Single block lookup failed";
                    "peer_id" => %initial_peer_id, 
                    "error" => ?e, 
                    "block_root" => ?requested_block_root, 
                    "response_type" => ?response_type);
                    return ShouldRemoveLookup::True;
                }
                Ok(None) => {
                    request_ref.id.block_request_id = None;
                    // The lookup failed but the block or blob was found via other means.
                }
                Err(e) => {
                    debug!(log, "Single block lookup failed";
                    "peer_id" => %initial_peer_id, 
                    "error" => ?e, 
                    "block_root" => ?requested_block_root, 
                    "response_type" => ?response_type);
                    return ShouldRemoveLookup::True;
                }
            }
        }
        ResponseType::Blob => {
            let id = request_ref.request_blobs().map(|request_opt| {
                request_opt
                    .map(|(peer_id, request)| cx.single_blobs_lookup_request(peer_id, request))
            });

            match id {
                Ok(Some(Ok(id))) => {
                    request_ref.id.blob_request_id = Some(id);
                }
                Ok(Some(Err(e))) => {
                    debug!(log, "Single block lookup failed";
                    "peer_id" => %initial_peer_id, 
                    "error" => ?e, 
                    "block_root" => ?requested_block_root, 
                    "response_type" => ?response_type);
                    return ShouldRemoveLookup::True;
                }
                Ok(None) => {
                    request_ref.id.blob_request_id = None;
                    // The lookup failed but the block or blob was found via other means.
                }
                Err(e) => {
                    debug!(log, "Single block lookup failed";
                    "peer_id" => %initial_peer_id, 
                    "error" => ?e, 
                    "block_root" => ?requested_block_root, 
                    "response_type" => ?response_type);
                    return ShouldRemoveLookup::True;
                }
            }
        }
    };
    ShouldRemoveLookup::False
}

fn should_remove_disconnected_peer<T: BeaconChainTypes>(
    response_type: ResponseType,
    peer_id: &PeerId,
    cx: &mut SyncNetworkContext<T>,
    req: &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    log: &Logger,
) -> ShouldRemoveLookup {
    if req.check_peer_disconnected(peer_id, response_type).is_err() {
        trace!(log, "Single lookup failed on peer disconnection"; "block_root" => ?req.block_request_state.requested_block_root, "response_type" => ?response_type);
        retry_request_after_failure(req, response_type, peer_id, cx, log)
    } else {
        ShouldRemoveLookup::False
    }
}

fn should_remove_failed_lookup<T: BeaconChainTypes>(
    id: Id,
    response_type: ResponseType,
    msg: &'static str,
    peer_id: &PeerId,
    cx: &mut SyncNetworkContext<T>,
    req: &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    log: &Logger,
) -> ShouldRemoveLookup {
    if req.id.block_request_id == Some(id) || req.id.blob_request_id == Some(id) {
        req.register_failure_downloading(response_type);
        trace!(log, "Single lookup failed"; "block" => %req.block_request_state.requested_block_root, "error" => msg, "response_type" => ?response_type);
        retry_request_after_failure(req, response_type, peer_id, cx, log)
    } else {
        ShouldRemoveLookup::False
    }
}

fn should_remove_missing_components<T: BeaconChainTypes>(
    request_ref: &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    response_type: ResponseType,
    cx: &mut SyncNetworkContext<T>,
    log: &Logger,
) -> ShouldRemoveLookup {
    request_ref.set_component_processed(response_type);

    // If we get a missing component response after processing both a blob and a block response, the
    // blobs must be what are missing.
    if request_ref.both_components_processed() {
        let Ok(blob_peer) = request_ref.processing_peer(ResponseType::Blob) else {
            return ShouldRemoveLookup::False;
        };
        if let PeerShouldHave::BlockAndBlobs(blob_peer) = blob_peer {
            cx.report_peer(
                blob_peer,
                PeerAction::MidToleranceError,
                "single_block_failure",
            );
        }
        request_ref.remove_peer_if_useless(blob_peer.as_peer_id(), ResponseType::Blob);
        if !request_ref.downloading(ResponseType::Blob) {
            // Try it again if possible.
            return retry_request_after_failure(
                request_ref,
                ResponseType::Blob,
                blob_peer.as_peer_id(),
                cx,
                log,
            );
        }
    }
    ShouldRemoveLookup::False
}
