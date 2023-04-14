use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use beacon_chain::blob_verification::BlockWrapper;
use beacon_chain::blob_verification::{AsBlock, MaybeAvailableBlock};
use beacon_chain::data_availability_checker::DataAvailabilityChecker;
use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
use fnv::FnvHashMap;
use itertools::Itertools;
use lighthouse_network::rpc::{RPCError, RPCResponseErrorCode};
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
use slog::{debug, error, trace, warn, Logger};
use smallvec::SmallVec;
use store::Hash256;
use types::blob_sidecar::BlobIdentifier;
use types::{BlobSidecar, SignedBeaconBlock};

use crate::beacon_processor::{ChainSegmentProcessId, WorkEvent};
use crate::metrics;
use crate::sync::block_lookups::parent_lookup::{ParentRequest, RequestResult};
use crate::sync::block_lookups::single_block_lookup::SingleBlobsRequest;
use crate::sync::network_context::BlockOrBlob;

use self::parent_lookup::PARENT_FAIL_TOLERANCE;
use self::{
    parent_lookup::{ParentLookup, VerifyError},
    single_block_lookup::SingleBlockLookup,
};

use super::manager::BlockOrBlobProcessResult;
use super::BatchProcessResult;
use super::{
    manager::{BlockProcessType, Id},
    network_context::SyncNetworkContext,
};

mod parent_lookup;
mod single_block_lookup;
#[cfg(test)]
mod tests;

pub type DownlodedBlocks<T> = (Hash256, MaybeAvailableBlock<T>);
pub type RootBlockTuple<T> = (Hash256, Arc<SignedBeaconBlock<T>>);

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 3;

pub(crate) struct BlockLookups<T: BeaconChainTypes> {
    /// Parent chain lookups being downloaded.
    parent_lookups: SmallVec<[ParentLookup<T>; 3]>,

    processing_parent_lookups: HashMap<
        Hash256,
        (
            Vec<Hash256>,
            SingleBlockLookup<PARENT_FAIL_TOLERANCE, T::EthSpec>,
        ),
    >,

    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    /// A collection of block hashes being searched for and a flag indicating if a result has been
    /// received or not.
    ///
    /// The flag allows us to determine if the peer returned data or sent us nothing.
    single_block_lookups:
        FnvHashMap<Id, SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T::EthSpec>>,

    blob_ids_to_block_ids: HashMap<Id, Id>,

    da_checker: Arc<DataAvailabilityChecker<T::EthSpec, T::SlotClock>>,

    /// The logger for the import manager.
    log: Logger,
}

// 1. on a completed single block lookup or single blob lookup, don't send for processing if a parent
//     chain is being requested or processed
// 2. when a chain is processed, find the child requests and send for processing

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
            blob_ids_to_block_ids: Default::default(),
            log,
        }
    }

    /* Lookup requests */

    pub fn search_block(&mut self, hash: Hash256, peer_id: PeerId, cx: &mut SyncNetworkContext<T>) {
        self.search_block_with(|| {}, hash, peer_id, cx)
    }

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    pub fn search_block_with(
        &mut self,
        cache_fn: impl Fn(&mut SingleBlockLookup<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS, T>),
        hash: Hash256,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        // Do not re-request a block that is already being requested
        if self
            .single_block_lookups
            .values_mut()
            .any(|single_block_request| single_block_request.add_peer(&hash, &peer_id))
        {
            return;
        }

        if self.parent_lookups.iter_mut().any(|parent_req| {
            parent_req.add_block_peer(&hash, &peer_id) || parent_req.contains_block(&hash)
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

        let mut single_block_request = SingleBlockLookup::new(hash, peer_id, da_checker);
        cache_fn(&mut single_block_request);

        let (peer_id, block_request) = single_block_request
            .request_block()
            .expect("none of the possible failure cases apply for a newly created block lookup");
        let (peer_id, blob_request) = single_block_request
            .request_blobs()
            .expect("none of the possible failure cases apply for a newly created blob lookup");

        if let (Ok(request_id), Ok(blob_request_id)) = (
            cx.single_block_lookup_request(peer_id, block_request),
            cx.single_blobs_lookup_request(peer_id, blob_request),
        ) {
            self.single_block_lookups
                .insert(request_id, single_block_request);
            self.blob_ids_to_block_ids
                .insert(blob_request_id, request_id);

            metrics::set_gauge(
                &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
                self.single_block_lookups.len() as i64,
            );
        }
    }

    pub fn search_current_unknown_parent(
        &mut self,
        block_root: Hash256,
        block: BlockWrapper<T::EthSpec>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.search_block_with(|request| request.add_block(block), block_root, peer_id, cx);
    }

    /// If a block is attempted to be processed but we do not know its parent, this function is
    /// called in order to find the block's parent.
    pub fn search_parent(
        &mut self,
        block_root: Hash256,
        parent_root: Hash256,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&parent_root) || self.failed_chains.contains(&block_root) {
            debug!(self.log, "Block is from a past failed chain. Dropping";
                "block_root" => ?block_root, "block_slot" => block.slot());
            return;
        }

        // Make sure this block is not already downloaded, and that neither it or its parent is
        // being searched for.
        if self.parent_lookups.iter_mut().any(|parent_req| {
            parent_req.contains_block(&block_root)
                || parent_req.add_block_peer(&block_root, &peer_id)
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

        let parent_lookup = ParentLookup::new(block_root, peer_id, self.da_checker.clone());
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
        let mut request = match self.single_block_lookups.entry(id) {
            Entry::Occupied(req) => req,
            Entry::Vacant(_) => {
                if block.is_some() {
                    debug!(
                        self.log,
                        "Block returned for single block lookup not present"
                    );
                }
                return;
            }
        };

        match request.get_mut().verify_response(block) {
            Ok(Some((block_root, block))) => {
                //TODO(sean) only send for processing if we don't have parent requests
                // for this block

                // This is the correct block, send it for processing
                if self
                    .send_block_for_processing(
                        block_root,
                        block,
                        seen_timestamp,
                        BlockProcessType::SingleBlock { id },
                        cx,
                    )
                    .is_err()
                {
                    // Remove to avoid inconsistencies
                    self.single_block_lookups.remove(&id);
                }
            }
            Ok(None) => {
                // request finished correctly, it will be removed after the block is processed.
            }
            Err(error) => {
                let msg: &str = error.into();
                cx.report_peer(peer_id, PeerAction::LowToleranceError, msg);
                // Remove the request, if it can be retried it will be added with a new id.
                let mut req = request.remove();

                debug!(self.log, "Single block lookup failed";
                        "peer_id" => %peer_id, "error" => msg, "block_root" => %req.requested_thing);
                // try the request again if possible
                if let Ok((peer_id, request)) = req.make_request() {
                    if let Ok(id) = cx.single_block_lookup_request(peer_id, request) {
                        self.single_block_lookups.insert(id, req);
                    }
                }
            }
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
        let mut request = match self.single_block_lookups.entry(id) {
            Entry::Occupied(req) => req,
            Entry::Vacant(_) => {
                if blob.is_some() {
                    debug!(
                        self.log,
                        "Block returned for single blob lookup not present"
                    );
                }
                return;
            }
        };

        match request.get_mut().verify_blob(blob) {
            Ok(Some((block_root, blobs))) => {
                //TODO(sean) only send for processing if we don't have parent requests trigger
                // for this block

                // This is the correct block, send it for processing
                if self
                    .send_block_for_processing(
                        block_root,
                        block,
                        seen_timestamp,
                        BlockProcessType::SingleBlock { id },
                        cx,
                    )
                    .is_err()
                {
                    // Remove to avoid inconsistencies
                    self.single_block_lookups.remove(&id);
                }
            }
            Ok(None) => {
                // request finished correctly, it will be removed after the block is processed.
            }
            Err(error) => {
                let msg: &str = error.into();
                cx.report_peer(peer_id, PeerAction::LowToleranceError, msg);
                // Remove the request, if it can be retried it will be added with a new id.
                let mut req = request.remove();

                debug!(self.log, "Single block lookup failed";
                        "peer_id" => %peer_id, "error" => msg, "block_root" => %req.requested_thing);
                // try the request again if possible
                if let Ok((peer_id, request)) = req.make_request() {
                    if let Ok(id) = cx.single_block_lookup_request(peer_id, request) {
                        self.single_block_lookups.insert(id, req);
                    }
                }
            }
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
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
                let res = parent_lookup.add_block(block_root, block);
                match res {
                    RequestResult::Process(wrapper) => {
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
                    RequestResult::SearchBlock(block_root) => {
                        self.search_block(block_root, peer_id, cx);
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
                VerifyError::RootMismatch
                | VerifyError::NoBlockReturned
                | VerifyError::ExtraBlocksReturned => {
                    let e = e.into();
                    warn!(self.log, "Peer sent invalid response to parent request.";
                        "peer_id" => %peer_id, "reason" => %e);

                    // We do not tolerate these kinds of errors. We will accept a few but these are signs
                    // of a faulty peer.
                    cx.report_peer(peer_id, PeerAction::LowToleranceError, e);

                    // We try again if possible.
                    self.request_parent_block(parent_lookup, cx);
                }
                VerifyError::PreviousFailure { parent_root } => {
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
            Ok(Some(blobs)) => {
                let processed_or_search = parent_lookup.add_blobs(blobs);

                match processed_or_search {
                    RequestResult::Process(wrapper) => {
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
                    RequestResult::SearchBlock(block_root) => {
                        self.search_block(block_root, peer_id, cx);
                        self.parent_lookups.push(parent_lookup)
                    }
                }
            }
            Ok(None) => {
                // Request finished successfully, nothing else to do. It will be removed after the
                // processing result arrives.
                self.parent_lookups.push(parent_lookup);
            }
            Err(e) => match e.into() {
                VerifyError::RootMismatch
                | VerifyError::NoBlockReturned
                | VerifyError::ExtraBlocksReturned => {
                    let e = e.into();
                    warn!(self.log, "Peer sent invalid response to parent request.";
                        "peer_id" => %peer_id, "reason" => %e);

                    // We do not tolerate these kinds of errors. We will accept a few but these are signs
                    // of a faulty peer.
                    cx.report_peer(peer_id, PeerAction::LowToleranceError, e);

                    // We try again if possible.
                    self.request_parent_blob(parent_lookup, cx);
                }
                VerifyError::PreviousFailure { parent_root } => {
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

    #[allow(clippy::needless_collect)] // false positive
    pub fn peer_disconnected(&mut self, peer_id: &PeerId, cx: &mut SyncNetworkContext<T>) {
        /* Check disconnection for single block lookups */
        // better written after https://github.com/rust-lang/rust/issues/59618
        let remove_retry_ids: Vec<Id> = self
            .single_block_lookups
            .iter_mut()
            .filter_map(|(id, req)| {
                if req.check_peer_disconnected(peer_id).is_err() {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        for mut req in remove_retry_ids
            .into_iter()
            .map(|id| self.single_block_lookups.remove(&id).unwrap())
            .collect::<Vec<_>>()
        {
            // retry the request
            match req.make_request() {
                Ok((peer_id, block_request)) => {
                    if let Ok(request_id) = cx.single_block_lookup_request(peer_id, block_request) {
                        self.single_block_lookups.insert(request_id, req);
                    }
                }
                Err(e) => {
                    trace!(
                        self.log,
                        "Single block request failed on peer disconnection";
                        "block_root" => %req.requested_thing,
                        "peer_id" => %peer_id,
                        "reason" => <&str>::from(e),
                    );
                }
            }
        }

        /* Check disconnection for parent lookups */
        while let Some(pos) = self
            .parent_lookups
            .iter_mut()
            .position(|req| req.check_block_peer_disconnected(peer_id).is_err())
        {
            let parent_lookup = self.parent_lookups.remove(pos);
            trace!(self.log, "Parent lookup's peer disconnected"; &parent_lookup);
            self.request_parent_block_and_blobs(parent_lookup, cx);
        }

        //TODO(sean) add lookups for blobs
    }

    /// An RPC error has occurred during a parent lookup. This function handles this case.
    pub fn parent_lookup_failed(
        &mut self,
        id: Id,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
        error: RPCError,
    ) {
        if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.pending_block_response(id))
        {
            let mut parent_lookup = self.parent_lookups.remove(pos);
            parent_lookup.block_download_failed(id);
            trace!(self.log, "Parent lookup request failed"; &parent_lookup);

            self.request_parent_block(parent_lookup, cx);
        } else {
            return debug!(self.log, "RPC failure for a parent lookup request that was not found"; "peer_id" => %peer_id);
        };
        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    pub fn single_block_lookup_failed(&mut self, id: Id, cx: &mut SyncNetworkContext<T>) {
        if let Some(mut request) = self.single_block_lookups.remove(&id) {
            request.register_failure_downloading();
            trace!(self.log, "Single block lookup failed"; "block" => %request.requested_thing);
            if let Ok((peer_id, block_request)) = request.make_request() {
                if let Ok(request_id) = cx.single_block_lookup_request(peer_id, block_request) {
                    self.single_block_lookups.insert(request_id, request);
                }
            }
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /* Processing responses */

    pub fn single_block_processed(
        &mut self,
        id: Id,
        result: BlockOrBlobProcessResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let mut req = match self.single_block_lookups.remove(&id) {
            Some(req) => req,
            None => {
                return debug!(
                    self.log,
                    "Block processed for single block lookup not present"
                );
            }
        };

        let root = req.requested_thing;
        let peer_id = match req.processing_peer() {
            Ok(peer) => peer,
            Err(_) => return,
        };

        match result {
            BlockOrBlobProcessResult::Ok(status) => match status {
                AvailabilityProcessingStatus::Imported(hash) => {
                    trace!(self.log, "Single block processing succeeded"; "block" => %root);
                }
                AvailabilityProcessingStatus::MissingParts(block_root) => {
                    self.search_block(block_root, peer_id, cx);
                }
            },
            BlockOrBlobProcessResult::Ignored => {
                // Beacon processor signalled to ignore the block processing result.
                // This implies that the cpu is overloaded. Drop the request.
                warn!(
                    self.log,
                    "Single block processing was ignored, cpu might be overloaded";
                    "action" => "dropping single block request"
                );
            }
            BlockOrBlobProcessResult::Err(e) => {
                trace!(self.log, "Single block processing failed"; "block" => %root, "error" => %e);
                match e {
                    BlockError::BlockIsAlreadyKnown => {
                        // No error here
                    }
                    BlockError::BeaconChainError(e) => {
                        // Internal error
                        error!(self.log, "Beacon chain error processing single block"; "block_root" => %root, "error" => ?e);
                    }
                    BlockError::ParentUnknown(block) => {
                        self.search_parent(root, block, peer_id, cx);
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
                    }
                    other => {
                        warn!(self.log, "Peer sent invalid block in single block lookup"; "root" => %root, "error" => ?other, "peer_id" => %peer_id);
                        cx.report_peer(
                            peer_id,
                            PeerAction::MidToleranceError,
                            "single_block_failure",
                        );
                        // Try it again if possible.
                        req.register_failure_processing();
                        if let Ok((peer_id, request)) = req.make_request() {
                            if let Ok(request_id) = cx.single_block_lookup_request(peer_id, request)
                            {
                                // insert with the new id
                                self.single_block_lookups.insert(request_id, req);
                            }
                        }
                    }
                }
            }
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    pub fn parent_block_processed(
        &mut self,
        chain_hash: Hash256,
        result: BlockOrBlobProcessResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let (mut parent_lookup, peer_id) = if let Some((pos, peer)) = self
            .parent_lookups
            .iter()
            .enumerate()
            .find_map(|(pos, request)| {
                request
                    .get_block_processing_peer(chain_hash)
                    .map(|peer| (pos, peer))
            }) {
            (self.parent_lookups.remove(pos), peer)
        } else {
            return debug!(self.log, "Process response for a parent lookup request that was not found"; "chain_hash" => %chain_hash);
        };

        match &result {
            BlockOrBlobProcessResult::Ok(status) => match status {
                AvailabilityProcessingStatus::Imported(hash) => {
                    trace!(self.log, "Parent block processing succeeded"; &parent_lookup)
                }
                AvailabilityProcessingStatus::MissingParts(block_root) => {
                    trace!(self.log, "Parent missing parts, triggering single block lookup "; &parent_lookup)
                }
            },
            BlockOrBlobProcessResult::Err(e) => {
                trace!(self.log, "Parent block processing failed"; &parent_lookup, "error" => %e)
            }
            BlockOrBlobProcessResult::Ignored => {
                trace!(
                    self.log,
                    "Parent block processing job was ignored";
                    "action" => "re-requesting block",
                    &parent_lookup
                );
            }
        }

        match result {
            BlockOrBlobProcessResult::Ok(AvailabilityProcessingStatus::MissingParts(
                block_root,
            )) => {
                self.search_block(block_root, peer_id, cx);
            }
            BlockOrBlobProcessResult::Err(BlockError::ParentUnknown(block)) => {
                parent_lookup.add_block(block);
                // `ParentUnknown` triggered by a parent block lookup should always have all blobs
                // so we don't re-request blobs for the current block.
                self.request_parent_block_and_blobs(parent_lookup, cx);
            }
            BlockOrBlobProcessResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockOrBlobProcessResult::Err(BlockError::BlockIsAlreadyKnown { .. }) => {
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
                let (chain_hash, blocks, hashes, block_request, blob_request) =
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
            ref e @ BlockOrBlobProcessResult::Err(BlockError::ExecutionPayloadError(ref epe))
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
            BlockOrBlobProcessResult::Err(outcome) => {
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
                self.request_parent_block(parent_lookup, cx);
            }
            BlockOrBlobProcessResult::Ignored => {
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
                //TODO(sean) find single blob and block lookups and send for processing
            }
            BatchProcessResult::FaultyFailure {
                imported_blocks: _,
                penalty,
            } => {
                self.failed_chains.insert(chain_hash);
                for peer_id in request.used_peers {
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

    fn request_parent_block(
        &mut self,
        mut parent_lookup: ParentLookup<T>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let response = parent_lookup.request_parent_block(cx);
        self.handle_response(parent_lookup, response);
    }

    fn request_parent_blob(
        &mut self,
        mut parent_lookup: ParentLookup<T>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let response = parent_lookup.request_parent_blobs(cx);
        self.handle_response(parent_lookup, response);
    }

    fn request_parent_block_and_blobs(
        &mut self,
        mut parent_lookup: ParentLookup<T>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let response = parent_lookup
            .request_parent_block(cx)
            .and_then(|| parent_lookup.request_parent_blobs(cx));
        self.handle_response(parent_lookup, response);
    }

    //TODO(sean) how should peer scoring work with failures in this method?
    fn handle_response(
        &mut self,
        mut parent_lookup: ParentLookup<T>,
        result: Result<(), parent_lookup::RequestError>,
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
                        for &peer_id in parent_lookup.used_block_peers() {
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
                        for &peer_id in parent_lookup.used_block_peers() {
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
        self.single_block_lookups.drain().len()
    }

    /// Drops all the parent chain requests and returns how many requests were dropped.
    pub fn drop_parent_chain_requests(&mut self) -> usize {
        self.parent_lookups.drain(..).len()
    }
}
