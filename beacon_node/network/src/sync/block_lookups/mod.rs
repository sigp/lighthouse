use beacon_chain::blob_verification::{AsBlock, BlockWrapper};
use beacon_chain::data_availability_checker::DataAvailabilityChecker;
use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
use lighthouse_network::rpc::RPCError;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
use slog::{debug, error, trace, warn, Logger};
use smallvec::SmallVec;
use ssz_types::FixedVector;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use types::{BlobSidecar, EthSpec, SignedBeaconBlock, Slot};

use self::parent_lookup::{LookupDownloadStatus, PARENT_FAIL_TOLERANCE};
use self::parent_lookup::{ParentLookup, ParentVerifyError};
use self::single_block_lookup::SingleBlockLookup;
use super::manager::BlockPartProcessingResult;
use super::BatchProcessResult;
use super::{
    manager::{BlockProcessType, Id},
    network_context::SyncNetworkContext,
};
use crate::beacon_processor::{ChainSegmentProcessId, WorkEvent};
use crate::metrics;
use crate::sync::block_lookups::single_block_lookup::LookupVerifyError;

mod parent_lookup;
mod single_block_lookup;
#[cfg(test)]
mod tests;

pub type DownloadedBlocks<T> = (Hash256, BlockWrapper<T>);
pub type RootBlockTuple<T> = (Hash256, Arc<SignedBeaconBlock<T>>);

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 3;

pub(crate) struct BlockLookups<T: BeaconChainTypes> {
    /// Parent chain lookups being downloaded.
    parent_lookups: SmallVec<[ParentLookup<T>; 3]>,

    processing_parent_lookups:
        HashMap<Hash256, (Vec<Hash256>, SingleBlockLookup<PARENT_FAIL_TOLERANCE, T>)>,

    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    /// A collection of block hashes being searched for and a flag indicating if a result has been
    /// received or not.
    ///
    /// The flag allows us to determine if the peer returned data or sent us nothing.
    single_block_lookups: Vec<(
        Option<Id>,
        Option<Id>,
        SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    )>,

    da_checker: Arc<DataAvailabilityChecker<T::EthSpec, T::SlotClock>>,

    /// The logger for the import manager.
    log: Logger,
}

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

#[derive(Debug)]
pub enum ResponseType {
    Block,
    Blob,
}

#[derive(Debug, Copy, Clone)]
pub enum PeerShouldHave {
    BlockAndBlobs,
    Neither,
}

#[derive(Debug, Copy, Clone)]
pub enum ShouldRemoveLookup {
    True,
    False,
}

impl<T: BeaconChainTypes> BlockLookups<T> {
    pub fn new(
        da_checker: Arc<DataAvailabilityChecker<T::EthSpec, T::SlotClock>>,
        log: Logger,
    ) -> Self {
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

    pub fn search_block(
        &mut self,
        hash: Hash256,
        peer_id: PeerId,
        peer_usefulness: PeerShouldHave,
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.search_block_with(|_| {}, hash, peer_id, peer_usefulness, cx)
    }

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    pub fn search_block_with(
        &mut self,
        cache_fn: impl Fn(&mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>),
        hash: Hash256,
        peer_id: PeerId,
        peer_usefulness: PeerShouldHave,
        cx: &mut SyncNetworkContext<T>,
    ) {
        // Do not re-request a block that is already being requested
        if self
            .single_block_lookups
            .iter_mut()
            .any(|(_, _, single_block_request)| {
                single_block_request.add_peer_if_useful(&hash, &peer_id, peer_usefulness)
            })
        {
            return;
        }

        if self.parent_lookups.iter_mut().any(|parent_req| {
            parent_req.add_peer_if_useful(&hash, &peer_id, peer_usefulness)
                || parent_req.contains_block(&hash)
        }) {
            // If the block was already downloaded, or is being downloaded in this moment, do not
            // request it.
            return;
        }

        if self
            .processing_parent_lookups
            .values()
            .any(|(hashes, _last_parent_request)| hashes.contains(&hash))
        {
            // we are already processing this block, ignore it.
            return;
        }

        debug!(
            self.log,
            "Searching for block";
            "peer_id" => %peer_id,
            "block" => %hash
        );

        let mut single_block_request =
            SingleBlockLookup::new(hash, peer_id, self.da_checker.clone());
        cache_fn(&mut single_block_request);

        let block_request_id =
            if let Ok(Some((peer_id, block_request))) = single_block_request.request_block() {
                cx.single_block_lookup_request(peer_id, block_request).ok()
            } else {
                None
            };

        let blob_request_id =
            if let Ok(Some((peer_id, blob_request))) = single_block_request.request_blobs() {
                cx.single_blobs_lookup_request(peer_id, blob_request).ok()
            } else {
                None
            };

        self.single_block_lookups
            .push((block_request_id, blob_request_id, single_block_request));

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    pub fn search_current_unknown_parent(
        &mut self,
        block_root: Hash256,
        block: BlockWrapper<T::EthSpec>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.search_block_with(
            |request| {
                let _ = request.add_block_wrapper(block_root, block.clone());
            },
            block_root,
            peer_id,
            PeerShouldHave::Neither,
            cx,
        );
    }

    pub fn search_current_unknown_blob_parent(
        &mut self,
        blob: Arc<BlobSidecar<T::EthSpec>>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let block_root = blob.block_root;
        self.search_block_with(
            |request| {
                let _ = request.add_blob(blob.clone());
            },
            block_root,
            peer_id,
            PeerShouldHave::Neither,
            cx,
        );
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
        // Gossip blocks or blobs shouldn't be propogated if parents are unavailable.
        let peer_usefulness = PeerShouldHave::BlockAndBlobs;

        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&parent_root) || self.failed_chains.contains(&block_root) {
            debug!(self.log, "Block is from a past failed chain. Dropping";
                "block_root" => ?block_root, "block_slot" => slot);
            return;
        }

        // Make sure this block is not already downloaded, and that neither it or its parent is
        // being searched for.
        if self.parent_lookups.iter_mut().any(|parent_req| {
            parent_req.contains_block(&block_root)
                || parent_req.add_peer_if_useful(&block_root, &peer_id, peer_usefulness)
        }) {
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

        let parent_lookup =
            ParentLookup::new(block_root, parent_root, peer_id, self.da_checker.clone());
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

        let Some((triggered_parent_request, request_id_ref, request_ref)) = self.find_single_lookup_request(id, stream_terminator, ResponseType::Block) else {
            return;
        };

        let should_remove = match request_ref.verify_block(block) {
            Ok(Some((root, block))) => {
                if triggered_parent_request {
                    // The lookup status here is irrelevant because we wait until the parent chain
                    // is complete before processing the block.
                    if let Err(e) = request_ref.add_block(root, block) {
                        handle_block_lookup_verify_error(
                            request_id_ref,
                            request_ref,
                            ResponseType::Block,
                            peer_id,
                            e,
                            cx,
                            &log,
                        )
                    } else {
                        ShouldRemoveLookup::False
                    }
                } else {
                    // This is the correct block, send it for processing
                    match self.send_block_for_processing(
                        root,
                        BlockWrapper::Block(block),
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
                request_id_ref,
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
                .retain(|(block_id, _, _)| block_id != &Some(id));
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

        let Some((triggered_parent_request, request_id_ref, request_ref)) =
            self.find_single_lookup_request(id, stream_terminator, ResponseType::Blob) else {
            return;
        };

        let should_remove = match request_ref.verify_blob(blob) {
            Ok(Some((block_root, blobs))) => {
                if triggered_parent_request {
                    // The lookup status here is irrelevant because we wait until the parent chain
                    // is complete before processing the block.
                    if let Err(e) = request_ref.add_blobs(block_root, blobs) {
                        handle_block_lookup_verify_error(
                            request_id_ref,
                            request_ref,
                            ResponseType::Blob,
                            peer_id,
                            e,
                            cx,
                            &log,
                        )
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
                request_id_ref,
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
                .retain(|(_, blob_id, _)| blob_id != &Some(id));
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    fn find_single_lookup_request(
        &mut self,
        target_id: Id,
        stream_terminator: StreamTerminator,
        response_type: ResponseType,
    ) -> Option<(
        bool,
        &mut Id,
        &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    )> {
        let lookup: Option<(
            bool,
            &mut Id,
            &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
        )> = self
            .single_block_lookups
            .iter_mut()
            .find_map(|(block_id_opt, blob_id_opt, req)| {
                let id_opt = match response_type {
                    ResponseType::Block => block_id_opt,
                    ResponseType::Blob => blob_id_opt,
                };
                if let Some(lookup_id) = id_opt {
                    if *lookup_id == target_id {
                        // Only send for processing if we don't have parent requests that were triggered by
                        // this block.
                        let triggered_parent_request = self
                            .parent_lookups
                            .iter()
                            .any(|lookup| lookup.chain_hash() == req.requested_block_root);

                        return Some((triggered_parent_request, lookup_id, req));
                    }
                }
                None
            });

        let (triggered_parent_request, id_ref, request) = match lookup {
            Some((triggered_parent_request, id_ref, req)) => {
                (triggered_parent_request, id_ref, req)
            }
            None => {
                if matches!(stream_terminator, StreamTerminator::False,) {
                    debug!(
                        self.log,
                        "Block returned for single block lookup not present";
                        "response_type" => ?response_type,
                    );
                }
                return None;
            }
        };
        Some((triggered_parent_request, id_ref, request))
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
                let process_or_search = parent_lookup.add_block(block_root, block).unwrap(); //TODO(sean) fix
                match process_or_search {
                    LookupDownloadStatus::Process(wrapper) => {
                        let chain_hash = parent_lookup.chain_hash();
                        if self
                            .send_block_for_processing(
                                block_root,
                                wrapper,
                                seen_timestamp,
                                BlockProcessType::ParentLookup { chain_hash },
                                cx,
                            )
                            .is_ok()
                        {
                            self.parent_lookups.push(parent_lookup)
                        }
                    }
                    LookupDownloadStatus::SearchBlock(block_root) => {
                        self.search_block(block_root, peer_id, PeerShouldHave::BlockAndBlobs, cx);
                        self.parent_lookups.push(parent_lookup)
                    }
                }
            }
            Ok(None) => {
                // Request finished successfully, nothing else to do. It will be removed after the
                // processing result arrives.
                self.parent_lookups.push(parent_lookup);
            }
            Err(e) => match e {
                ParentVerifyError::RootMismatch
                | ParentVerifyError::NoBlockReturned
                | ParentVerifyError::ExtraBlocksReturned
                | ParentVerifyError::UnrequestedBlobId
                | ParentVerifyError::ExtraBlobsReturned
                | ParentVerifyError::InvalidIndex(_)
                | ParentVerifyError::AvailabilityCheck => {
                    let e = e.into();
                    warn!(self.log, "Peer sent invalid response to parent request.";
                        "peer_id" => %peer_id, "reason" => %e);

                    // We do not tolerate these kinds of errors. We will accept a few but these are signs
                    // of a faulty peer.
                    cx.report_peer(peer_id, PeerAction::LowToleranceError, e);

                    // We try again if possible.
                    self.request_parent_block(parent_lookup, cx);
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
            },
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
                let processed_or_search = parent_lookup.add_blobs(block_root, blobs).unwrap(); //TODO(sean) fix
                match processed_or_search {
                    LookupDownloadStatus::Process(wrapper) => {
                        let chain_hash = parent_lookup.chain_hash();
                        if self
                            .send_block_for_processing(
                                block_root,
                                wrapper,
                                seen_timestamp,
                                BlockProcessType::ParentLookup { chain_hash },
                                cx,
                            )
                            .is_ok()
                        {
                            self.parent_lookups.push(parent_lookup)
                        }
                    }
                    LookupDownloadStatus::SearchBlock(block_root) => {
                        self.search_block(block_root, peer_id, PeerShouldHave::BlockAndBlobs, cx);
                        self.parent_lookups.push(parent_lookup)
                    }
                }
            }
            Ok(None) => {
                // Request finished successfully, nothing else to do. It will be removed after the
                // processing result arrives.
                self.parent_lookups.push(parent_lookup);
            }
            Err(e) => match e {
                ParentVerifyError::RootMismatch
                | ParentVerifyError::NoBlockReturned
                | ParentVerifyError::ExtraBlocksReturned
                | ParentVerifyError::UnrequestedBlobId
                | ParentVerifyError::ExtraBlobsReturned
                | ParentVerifyError::InvalidIndex(_)
                | ParentVerifyError::AvailabilityCheck => {
                    let e = e.into();
                    warn!(self.log, "Peer sent invalid response to parent request.";
                        "peer_id" => %peer_id, "reason" => %e);

                    // We do not tolerate these kinds of errors. We will accept a few but these are signs
                    // of a faulty peer.
                    cx.report_peer(peer_id, PeerAction::LowToleranceError, e);

                    // We try again if possible.
                    self.request_parent_blob(parent_lookup, cx);
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
            },
        };

        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId, cx: &mut SyncNetworkContext<T>) {
        self.single_block_lookups
            .retain_mut(|(block_id, blob_id, req)| {
                if req
                    .block_request_state
                    .check_peer_disconnected(peer_id)
                    .is_err()
                {
                    // retry the request
                    match req.request_block() {
                        Ok(Some((peer_id, block_request))) => {
                            if let Ok(request_id) =
                                cx.single_block_lookup_request(peer_id, block_request)
                            {
                                *block_id = Some(request_id);
                                return true;
                            }
                        }
                        Ok(None) => {
                            // We've already successfully downloaded the block, we may be waiting
                            // for blobs, so don't drop the lookup.
                            return true;
                        }
                        Err(e) => {
                            trace!(
                                self.log,
                                "Single block request failed on peer disconnection";
                                "block_root" => %req.requested_block_root,
                                "peer_id" => %peer_id,
                                "reason" => <&str>::from(e),
                            );
                        }
                    }
                }
                if req
                    .blob_request_state
                    .check_peer_disconnected(peer_id)
                    .is_err()
                {
                    // retry the request
                    match req.request_blobs() {
                        Ok(Some((peer_id, blobs_request))) => {
                            if let Ok(request_id) =
                                cx.single_blobs_lookup_request(peer_id, blobs_request)
                            {
                                *blob_id = Some(request_id);
                                return true;
                            }
                        }
                        Ok(None) => {
                            // We've already successfully downloaded the blobs, we may be waiting
                            // for block, so don't drop the lookup.
                            return true;
                        }
                        Err(e) => {
                            trace!(
                                self.log,
                                "Single blobs request failed on peer disconnection";
                                "block_root" => %req.requested_block_root,
                                "peer_id" => %peer_id,
                                "reason" => <&str>::from(e),
                            );
                        }
                    }
                }
                false
            });

        /* Check disconnection for parent lookups */
        while let Some(pos) = self.parent_lookups.iter_mut().position(|req| {
            req.check_block_peer_disconnected(peer_id).is_err()
                && req.check_blob_peer_disconnected(peer_id).is_err()
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
        //TODO(sean) check if there's a pending blob response when deciding whether to drop?

        if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.pending_block_response(id))
        {
            let mut parent_lookup = self.parent_lookups.remove(pos);
            parent_lookup.block_download_failed();
            trace!(self.log, "Parent lookup block request failed"; &parent_lookup);

            self.request_parent_block(parent_lookup, cx);
        } else {
            return debug!(self.log, "RPC failure for a block parent lookup request that was not found"; "peer_id" => %peer_id);
        };

        if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.pending_blob_response(id))
        {
            let mut parent_lookup = self.parent_lookups.remove(pos);
            parent_lookup.blob_download_failed();
            trace!(self.log, "Parent lookup blobs request failed"; &parent_lookup);

            self.request_parent_blob(parent_lookup, cx);
        } else {
            return debug!(self.log, "RPC failure for a blobs parent lookup request that was not found"; "peer_id" => %peer_id);
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
        self.single_block_lookups.retain_mut(|(block_id_opt, blob_id_opt, req)|{
             let should_remove_block =  if let Some(block_id) = block_id_opt.as_mut() {
                if *block_id == id {
                    req.block_request_state.register_failure_downloading();
                    trace!(self.log, "Single block lookup failed"; "block" => %req.requested_block_root);
                    retry_request_after_failure(block_id, req, ResponseType::Block, peer_id, error.as_static_str(), cx, &self.log)
                } else {
                        ShouldRemoveLookup::False
                }
            } else {
                ShouldRemoveLookup::False
            };

             let should_remove_blob = if let Some(blob_id) = blob_id_opt.as_mut() {
                if *blob_id == id {
                req.blob_request_state.register_failure_downloading();
                trace!(self.log, "Single blob lookup failed"; "block" => %req.requested_block_root);
                 retry_request_after_failure(blob_id, req, ResponseType::Block, peer_id,error.as_static_str(), cx, &self.log)
                } else {
                        ShouldRemoveLookup::False
                }
            } else {
                ShouldRemoveLookup::False
            };
            matches!(should_remove_block, ShouldRemoveLookup::False) && matches!(should_remove_blob, ShouldRemoveLookup::False)
        });

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /* Processing responses */

    pub fn single_block_processed(
        &mut self,
        id: Id,
        result: BlockPartProcessingResult<T::EthSpec>,
        response_type: ResponseType,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let (index, req_id, req) = match self.single_block_lookups.iter_mut().enumerate().find_map(
            |(index, (block_id, blob_id, req))| match response_type {
                ResponseType::Block => {
                    if block_id == &Some(id) {
                        Some((index, block_id, req))
                    } else {
                        None
                    }
                }
                ResponseType::Blob => {
                    if blob_id == &Some(id) {
                        Some((index, blob_id, req))
                    } else {
                        None
                    }
                }
            },
        ) {
            Some(req) => req,
            None => {
                return debug!(
                    self.log,
                    "Block processed for single block lookup not present"
                );
            }
        };

        let root = req.requested_block_root;
        let peer_id = match response_type {
            ResponseType::Block => match req.block_request_state.processing_peer() {
                Ok(peer) => peer,
                Err(_) => return,
            },
            ResponseType::Blob => match req.blob_request_state.processing_peer() {
                Ok(peer) => peer,
                Err(_) => return,
            },
        };

        let remove = match result {
            BlockPartProcessingResult::Ok(status) => match status {
                AvailabilityProcessingStatus::Imported(hash) => {
                    trace!(self.log, "Single block processing succeeded"; "block" => %root);
                    true
                }
                AvailabilityProcessingStatus::MissingComponents(_, block_root) => {
                    // At this point we don't know what the peer *should* have.
                    self.search_block(block_root, peer_id, PeerShouldHave::Neither, cx);
                    false
                }
            },
            BlockPartProcessingResult::Ignored => {
                // Beacon processor signalled to ignore the block processing result.
                // This implies that the cpu is overloaded. Drop the request.
                warn!(
                    self.log,
                    "Single block processing was ignored, cpu might be overloaded";
                    "action" => "dropping single block request"
                );
                true
            }
            BlockPartProcessingResult::Err(e) => {
                trace!(self.log, "Single block processing failed"; "block" => %root, "error" => %e);
                match e {
                    BlockError::BlockIsAlreadyKnown => {
                        // No error here
                        true
                    }
                    BlockError::BeaconChainError(e) => {
                        // Internal error
                        error!(self.log, "Beacon chain error processing single block"; "block_root" => %root, "error" => ?e);
                        true
                    }
                    BlockError::ParentUnknown(block) => {
                        self.search_parent(block.slot(), root, block.parent_root(), peer_id, cx);
                        //TODO(sean) - handle request for parts of this block
                        false
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
                        //TODO(sean) is this right?
                        true
                    }
                    other => {
                        warn!(self.log, "Peer sent invalid block in single block lookup"; "root" => %root, "error" => ?other, "peer_id" => %peer_id);
                        cx.report_peer(
                            peer_id,
                            PeerAction::MidToleranceError,
                            "single_block_failure",
                        );
                        // Try it again if possible.
                        match response_type {
                            ResponseType::Block => {
                                req.block_request_state.register_failure_processing();
                                match req.request_block() {
                                    Ok(Some((peer_id, request))) => {
                                        if let Ok(request_id) =
                                            cx.single_block_lookup_request(peer_id, request)
                                        {
                                            *req_id = Some(request_id);
                                            false
                                        } else {
                                            true
                                        }
                                    }
                                    Ok(None) => false,
                                    Err(_) => true,
                                }
                            }
                            ResponseType::Blob => {
                                req.blob_request_state.register_failure_processing();
                                match req.request_blobs() {
                                    Ok(Some((peer_id, request))) => {
                                        if let Ok(request_id) =
                                            cx.single_blobs_lookup_request(peer_id, request)
                                        {
                                            *req_id = Some(request_id);
                                            false
                                        } else {
                                            true
                                        }
                                    }
                                    Ok(None) => false,
                                    Err(_) => true,
                                }
                            }
                        }
                    }
                }
            }
        };

        if remove {
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
        result: BlockPartProcessingResult<T::EthSpec>,
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

        let peer_id = match response_type {
            ResponseType::Block => parent_lookup
                .current_parent_request
                .block_request_state
                .processing_peer(),
            ResponseType::Blob => parent_lookup
                .current_parent_request
                .blob_request_state
                .processing_peer(),
        };

        let peer_id = match peer_id {
            Ok(peer) => peer,
            Err(_) => return,
        };

        match &result {
            BlockPartProcessingResult::Ok(status) => match status {
                AvailabilityProcessingStatus::Imported(hash) => {
                    trace!(self.log, "Parent block processing succeeded"; &parent_lookup)
                }
                AvailabilityProcessingStatus::MissingComponents(_, block_root) => {
                    trace!(self.log, "Parent missing parts, triggering single block lookup "; &parent_lookup)
                }
            },
            BlockPartProcessingResult::Err(e) => {
                trace!(self.log, "Parent block processing failed"; &parent_lookup, "error" => %e)
            }
            BlockPartProcessingResult::Ignored => {
                trace!(
                    self.log,
                    "Parent block processing job was ignored";
                    "action" => "re-requesting block",
                    &parent_lookup
                );
            }
        }

        match result {
            BlockPartProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                _,
                block_root,
            )) => {
                self.search_block(block_root, peer_id, PeerShouldHave::BlockAndBlobs, cx);
            }
            BlockPartProcessingResult::Err(BlockError::ParentUnknown(block)) => {
                parent_lookup.add_block_wrapper(block);
                self.request_parent_block_and_blobs(parent_lookup, cx);
            }
            BlockPartProcessingResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockPartProcessingResult::Err(BlockError::BlockIsAlreadyKnown { .. }) => {
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
                let (chain_hash, blocks, hashes, block_request) =
                    parent_lookup.parts_for_processing();
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
            ref e @ BlockPartProcessingResult::Err(BlockError::ExecutionPayloadError(ref epe))
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
            BlockPartProcessingResult::Err(outcome) => {
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
                match response_type {
                    ResponseType::Block => {
                        parent_lookup.block_processing_failed();
                        self.request_parent_block(parent_lookup, cx);
                    }
                    ResponseType::Blob => {
                        parent_lookup.blob_processing_failed();
                        self.request_parent_blob(parent_lookup, cx);
                    }
                }
            }
            BlockPartProcessingResult::Ignored => {
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
                if let Some((index, (_, _, req))) = self
                    .single_block_lookups
                    .iter()
                    .enumerate()
                    .find(|(index, (_, _, req))| req.requested_block_root == chain_hash)
                {
                    if let Some((block_id, blob_id, block_wrapper)) = self
                        .single_block_lookups
                        .get_mut(index)
                        .and_then(|(block_id, blob_id, lookup)| {
                            lookup
                                .get_downloaded_block()
                                .map(|block| (block_id, blob_id, block))
                        })
                    {
                        let Some(id) = block_id.or(*blob_id) else {
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
                //TODO(sean) improve peer scoring to block or blob granularity
                self.failed_chains.insert(chain_hash);
                let mut all_peers = request.blob_request_state.used_peers.clone();
                all_peers.extend(request.blob_request_state.used_peers);
                for peer_id in all_peers {
                    cx.report_peer(peer_id, penalty, "parent_chain_failure")
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
        blobs: FixedVector<
            Option<Arc<BlobSidecar<T::EthSpec>>>,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxBlobsPerBlock,
        >,
        duration: Duration,
        process_type: BlockProcessType,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), ()> {
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

    fn request_parent_blob(
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
    request_id_ref: &mut u32,
    request_ref: &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    response_type: ResponseType,
    peer_id: PeerId,
    error: LookupVerifyError,
    cx: &mut SyncNetworkContext<T>,
    log: &Logger,
) -> ShouldRemoveLookup {
    let msg: &str = error.into();
    cx.report_peer(peer_id, PeerAction::LowToleranceError, msg);

    debug!(log, "Single block lookup failed";
        "peer_id" => %peer_id,
        "error" => msg,
        "block_root" => ?request_ref.requested_block_root,
        "response_type" => ?response_type
    );
    retry_request_after_failure(
        request_id_ref,
        request_ref,
        response_type,
        &peer_id,
        msg,
        cx,
        log,
    )
}

fn retry_request_after_failure<T: BeaconChainTypes, Err: Debug>(
    request_id_ref: &mut u32,
    request_ref: &mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>,
    response_type: ResponseType,
    initial_peer_id: &PeerId,
    e: Err,
    cx: &mut SyncNetworkContext<T>,
    log: &Logger,
) -> ShouldRemoveLookup {
    let requested_block_root = request_ref.requested_block_root;

    // try the request again if possible
    let id_opt = match response_type {
        ResponseType::Block => request_ref.request_block().map(|request_opt| {
            request_opt.map(|(peer_id, request)| cx.single_block_lookup_request(peer_id, request))
        }),
        ResponseType::Blob => request_ref.request_blobs().map(|request_opt| {
            request_opt.map(|(peer_id, request)| cx.single_blobs_lookup_request(peer_id, request))
        }),
    };

    match id_opt {
        Ok(Some(Ok(id))) => {
            *request_id_ref = id;
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
    ShouldRemoveLookup::False
}
