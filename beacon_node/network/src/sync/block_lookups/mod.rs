use std::collections::hash_map::Entry;
use std::time::Duration;

use beacon_chain::{BeaconChainTypes, BlockError};
use fnv::FnvHashMap;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
use slog::{debug, error, trace, warn, Logger};
use smallvec::SmallVec;
use std::sync::Arc;
use store::{Hash256, SignedBeaconBlock};

use crate::beacon_processor::{ChainSegmentProcessId, WorkEvent};
use crate::metrics;

use self::{
    parent_lookup::{ParentLookup, VerifyError},
    single_block_lookup::SingleBlockRequest,
};

use super::manager::{BlockProcessResult, BlockTy};
use super::BatchProcessResult;
use super::{
    manager::{BlockProcessType, Id},
    network_context::SyncNetworkContext,
};

mod parent_lookup;
mod single_block_lookup;
#[cfg(test)]
mod tests;

pub type RootBlockTuple<T> = (Hash256, BlockTy<T>);

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 3;

pub(crate) struct BlockLookups<T: BeaconChainTypes> {
    /// A collection of parent block lookups.
    parent_queue: SmallVec<[ParentLookup<T>; 3]>,

    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    /// A collection of block hashes being searched for and a flag indicating if a result has been
    /// received or not.
    ///
    /// The flag allows us to determine if the peer returned data or sent us nothing.
    single_block_lookups: FnvHashMap<Id, SingleBlockRequest<SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS>>,

    /// The logger for the import manager.
    log: Logger,
}

impl<T: BeaconChainTypes> BlockLookups<T> {
    pub fn new(log: Logger) -> Self {
        Self {
            parent_queue: Default::default(),
            failed_chains: LRUTimeCache::new(Duration::from_secs(
                FAILED_CHAINS_CACHE_EXPIRY_SECONDS,
            )),
            single_block_lookups: Default::default(),
            log,
        }
    }

    /* Lookup requests */

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    pub fn search_block(&mut self, hash: Hash256, peer_id: PeerId, cx: &mut SyncNetworkContext<T>) {
        // Do not re-request a block that is already being requested
        if self
            .single_block_lookups
            .values_mut()
            .any(|single_block_request| single_block_request.add_peer(&hash, &peer_id))
        {
            return;
        }

        debug!(
            self.log,
            "Searching for block";
            "peer_id" => %peer_id,
            "block" => %hash
        );

        let mut single_block_request = SingleBlockRequest::new(hash, peer_id);

        let (peer_id, request) = single_block_request
            .request_block()
            .expect("none of the possible failure cases apply for a newly created block lookup");
        if let Ok(request_id) = cx.single_block_lookup_request(peer_id, request) {
            self.single_block_lookups
                .insert(request_id, single_block_request);

            metrics::set_gauge(
                &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
                self.single_block_lookups.len() as i64,
            );
        }
    }

    /// If a block is attempted to be processed but we do not know its parent, this function is
    /// called in order to find the block's parent.
    pub fn search_parent(
        &mut self,
        block_root: Hash256,
        block: BlockTy<T::EthSpec>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let parent_root = block.parent_root();
        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&parent_root) || self.failed_chains.contains(&block_root) {
            debug!(self.log, "Block is from a past failed chain. Dropping";
                "block_root" => ?block_root, "block_slot" => block.slot());
            return;
        }

        // Make sure this block is not already downloaded, and that neither it or its parent is
        // being searched for.
        if self.parent_queue.iter_mut().any(|parent_req| {
            parent_req.contains_block(block.block())
                || parent_req.add_peer(&block_root, &peer_id)
                || parent_req.add_peer(&parent_root, &peer_id)
        }) {
            // we are already searching for this block, ignore it
            return;
        }

        let parent_lookup = ParentLookup::new(block_root, block, peer_id);
        self.request_parent(parent_lookup, cx);
    }

    /* Lookup responses */

    pub fn single_block_lookup_response(
        &mut self,
        id: Id,
        peer_id: PeerId,
        block: Option<BlockTy<T::EthSpec>>,
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

        match request.get_mut().verify_block(block) {
            Ok(Some((block_root, block))) => {
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
                        "peer_id" => %peer_id, "error" => msg, "block_root" => %req.hash);
                // try the request again if possible
                if let Ok((peer_id, request)) = req.request_block() {
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
        block: Option<BlockTy<T::EthSpec>>,
        seen_timestamp: Duration,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let mut parent_lookup = if let Some(pos) = self
            .parent_queue
            .iter()
            .position(|request| request.pending_response(id))
        {
            self.parent_queue.remove(pos)
        } else {
            if block.is_some() {
                debug!(self.log, "Response for a parent lookup request that was not found"; "peer_id" => %peer_id);
            }
            return;
        };

        match parent_lookup.verify_block(block, &mut self.failed_chains) {
            Ok(Some((block_root, block))) => {
                // Block is correct, send to the beacon processor.
                let chain_hash = parent_lookup.chain_hash();
                if self
                    .send_block_for_processing(
                        block_root,
                        block,
                        seen_timestamp,
                        BlockProcessType::ParentLookup { chain_hash },
                        cx,
                    )
                    .is_ok()
                {
                    self.parent_queue.push(parent_lookup)
                }
            }
            Ok(None) => {
                // Request finished successfully, nothing else to do. It will be removed after the
                // processing result arrives.
                self.parent_queue.push(parent_lookup);
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
                    self.request_parent(parent_lookup, cx);
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
            self.parent_queue.len() as i64,
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
            match req.request_block() {
                Ok((peer_id, block_request)) => {
                    if let Ok(request_id) = cx.single_block_lookup_request(peer_id, block_request) {
                        self.single_block_lookups.insert(request_id, req);
                    }
                }
                Err(e) => {
                    trace!(
                        self.log,
                        "Single block request failed on peer disconnection";
                        "block_root" => %req.hash,
                        "peer_id" => %peer_id,
                        "reason" => <&str>::from(e),
                    );
                }
            }
        }

        /* Check disconnection for parent lookups */
        while let Some(pos) = self
            .parent_queue
            .iter_mut()
            .position(|req| req.check_peer_disconnected(peer_id).is_err())
        {
            let parent_lookup = self.parent_queue.remove(pos);
            trace!(self.log, "Parent lookup's peer disconnected"; &parent_lookup);
            self.request_parent(parent_lookup, cx);
        }
    }

    /// An RPC error has occurred during a parent lookup. This function handles this case.
    pub fn parent_lookup_failed(
        &mut self,
        id: Id,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        if let Some(pos) = self
            .parent_queue
            .iter()
            .position(|request| request.pending_response(id))
        {
            let mut parent_lookup = self.parent_queue.remove(pos);
            parent_lookup.download_failed();
            trace!(self.log, "Parent lookup request failed"; &parent_lookup);
            self.request_parent(parent_lookup, cx);
        } else {
            return debug!(self.log, "RPC failure for a parent lookup request that was not found"; "peer_id" => %peer_id);
        };
        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_queue.len() as i64,
        );
    }

    pub fn single_block_lookup_failed(&mut self, id: Id, cx: &mut SyncNetworkContext<T>) {
        if let Some(mut request) = self.single_block_lookups.remove(&id) {
            request.register_failure_downloading();
            trace!(self.log, "Single block lookup failed"; "block" => %request.hash);
            if let Ok((peer_id, block_request)) = request.request_block() {
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
        result: BlockProcessResult<T::EthSpec>,
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

        let root = req.hash;
        let peer_id = match req.processing_peer() {
            Ok(peer) => peer,
            Err(_) => return,
        };

        match result {
            BlockProcessResult::Ok => {
                trace!(self.log, "Single block processing succeeded"; "block" => %root);
            }
            BlockProcessResult::Ignored => {
                // Beacon processor signalled to ignore the block processing result.
                // This implies that the cpu is overloaded. Drop the request.
                warn!(
                    self.log,
                    "Single block processing was ignored, cpu might be overloaded";
                    "action" => "dropping single block request"
                );
            }
            BlockProcessResult::Err(e) => {
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
                        self.search_parent(root, BlockTy::Block { block }, peer_id, cx);
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
                        if let Ok((peer_id, request)) = req.request_block() {
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
        result: BlockProcessResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let (mut parent_lookup, peer_id) = if let Some((pos, peer)) = self
            .parent_queue
            .iter()
            .enumerate()
            .find_map(|(pos, request)| {
                request
                    .get_processing_peer(chain_hash)
                    .map(|peer| (pos, peer))
            }) {
            (self.parent_queue.remove(pos), peer)
        } else {
            return debug!(self.log, "Process response for a parent lookup request that was not found"; "chain_hash" => %chain_hash);
        };

        match &result {
            BlockProcessResult::Ok => {
                trace!(self.log, "Parent block processing succeeded"; &parent_lookup)
            }
            BlockProcessResult::Err(e) => {
                trace!(self.log, "Parent block processing failed"; &parent_lookup, "error" => %e)
            }
            BlockProcessResult::Ignored => {
                trace!(
                    self.log,
                    "Parent block processing job was ignored";
                    "action" => "re-requesting block",
                    &parent_lookup
                );
            }
        }

        match result {
            BlockProcessResult::Err(BlockError::ParentUnknown(block)) => {
                // need to keep looking for parents
                // add the block back to the queue and continue the search
                parent_lookup.add_block(BlockTy::Block { block });
                self.request_parent(parent_lookup, cx);
            }
            BlockProcessResult::Ok
            | BlockProcessResult::Err(BlockError::BlockIsAlreadyKnown { .. }) => {
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
                let chain_hash = parent_lookup.chain_hash();
                let blocks = parent_lookup.chain_blocks();
                let process_id = ChainSegmentProcessId::ParentLookup(chain_hash);
                // let work = WorkEvent::chain_segment(process_id, blocks);
                let work = todo!("this means we can have batches of mixed type");

                match beacon_processor_send.try_send(work) {
                    Ok(_) => {
                        self.parent_queue.push(parent_lookup);
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
            ref e @ BlockProcessResult::Err(BlockError::ExecutionPayloadError(ref epe))
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
            BlockProcessResult::Err(outcome) => {
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
                parent_lookup.processing_failed();
                self.request_parent(parent_lookup, cx);
            }
            BlockProcessResult::Ignored => {
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
            self.parent_queue.len() as i64,
        );
    }

    pub fn parent_chain_processed(
        &mut self,
        chain_hash: Hash256,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let parent_lookup = if let Some(pos) = self
            .parent_queue
            .iter()
            .position(|request| request.chain_hash() == chain_hash)
        {
            self.parent_queue.remove(pos)
        } else {
            return debug!(self.log, "Chain process response for a parent lookup request that was not found"; "chain_hash" => %chain_hash);
        };

        debug!(self.log, "Parent chain processed"; "chain_hash" => %chain_hash, "result" => ?result);
        match result {
            BatchProcessResult::Success { .. } => {
                // nothing to do.
            }
            BatchProcessResult::FaultyFailure {
                imported_blocks: _,
                penalty,
            } => {
                self.failed_chains.insert(parent_lookup.chain_hash());
                for &peer_id in parent_lookup.used_peers() {
                    cx.report_peer(peer_id, penalty, "parent_chain_failure")
                }
            }
            BatchProcessResult::NonFaultyFailure => {
                // We might request this chain again if there is need but otherwise, don't try again
            }
        }

        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_queue.len() as i64,
        );
    }

    /* Helper functions */

    fn send_block_for_processing(
        &mut self,
        block_root: Hash256,
        block: BlockTy<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), ()> {
        match cx.processor_channel_if_enabled() {
            Some(beacon_processor_send) => {
                trace!(self.log, "Sending block for processing"; "block" => ?block_root, "process" => ?process_type);
                let event = match block {
                    BlockTy::Block { block } => {
                        WorkEvent::rpc_beacon_block(block_root, block, duration, process_type)
                    }
                    BlockTy::BlockAndBlob { block_sidecar_pair } => {
                        //FIXME(sean)
                        // WorkEvent::rpc_block_and_glob(block_sidecar_pair)
                        todo!("we also need to process block-glob pairs for rpc")
                    }
                };
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

    fn request_parent(
        &mut self,
        mut parent_lookup: ParentLookup<T>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        match parent_lookup.request_parent(cx) {
            Err(e) => {
                debug!(self.log, "Failed to request parent"; &parent_lookup, "error" => e.as_static());
                match e {
                    parent_lookup::RequestError::SendFailed(_) => {
                        // Probably shutting down, nothing to do here. Drop the request
                    }
                    parent_lookup::RequestError::ChainTooLong => {
                        self.failed_chains.insert(parent_lookup.chain_hash());
                        // This indicates faulty peers.
                        for &peer_id in parent_lookup.used_peers() {
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
                        for &peer_id in parent_lookup.used_peers() {
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
                self.parent_queue.push(parent_lookup)
            }
        }

        // We remove and add back again requests so we want this updated regardless of outcome.
        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_queue.len() as i64,
        );
    }

    /// Drops all the single block requests and returns how many requests were dropped.
    pub fn drop_single_block_requests(&mut self) -> usize {
        self.single_block_lookups.drain().len()
    }

    /// Drops all the parent chain requests and returns how many requests were dropped.
    pub fn drop_parent_chain_requests(&mut self) -> usize {
        self.parent_queue.drain(..).len()
    }
}
