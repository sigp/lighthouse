use self::parent_lookup::ParentVerifyError;
use self::single_block_lookup::SingleBlockLookup;
use super::manager::BlockProcessingResult;
use super::BatchProcessResult;
use super::{manager::BlockProcessType, network_context::SyncNetworkContext};
use crate::metrics;
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::block_lookups::common::LookupType;
use crate::sync::block_lookups::parent_lookup::{ParentLookup, RequestError};
use crate::sync::block_lookups::single_block_lookup::{CachedChild, LookupRequestError};
use crate::sync::manager::{Id, SingleLookupReqId};
use beacon_chain::block_verification_types::{AsBlock, RpcBlock};
pub use beacon_chain::data_availability_checker::ChildComponents;
use beacon_chain::data_availability_checker::{
    AvailabilityCheckErrorCategory, DataAvailabilityChecker,
};
use beacon_chain::validator_monitor::timestamp_now;
use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
pub use common::Current;
pub use common::Lookup;
pub use common::Parent;
pub use common::RequestState;
use fnv::FnvHashMap;
use lighthouse_network::rpc::RPCError;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
pub use single_block_lookup::{BlobRequestState, BlockRequestState};
use slog::{debug, error, trace, warn, Logger};
use smallvec::SmallVec;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use types::blob_sidecar::FixedBlobSidecarList;
use types::Slot;

pub mod common;
mod parent_lookup;
mod single_block_lookup;
#[cfg(test)]
mod tests;

pub type DownloadedBlock<T> = (Hash256, RpcBlock<T>);

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 3;

pub struct BlockLookups<T: BeaconChainTypes> {
    /// Parent chain lookups being downloaded.
    parent_lookups: SmallVec<[ParentLookup<T>; 3]>,

    processing_parent_lookups: HashMap<Hash256, (Vec<Hash256>, SingleBlockLookup<Parent, T>)>,

    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    single_block_lookups: FnvHashMap<Id, SingleBlockLookup<Current, T>>,

    pub(crate) da_checker: Arc<DataAvailabilityChecker<T>>,

    /// The logger for the import manager.
    log: Logger,
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
        peer_source: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.new_current_lookup(block_root, None, peer_source, cx)
    }

    /// Creates a lookup for the block with the given `block_root`, while caching other block
    /// components we've already received. The block components are cached here because we haven't
    /// imported its parent and therefore can't fully validate it and store it in the data
    /// availability cache.
    ///
    /// The request is immediately triggered.
    pub fn search_child_block(
        &mut self,
        block_root: Hash256,
        child_components: ChildComponents<T::EthSpec>,
        peer_source: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.new_current_lookup(block_root, Some(child_components), peer_source, cx)
    }

    /// Attempts to trigger the request matching the given `block_root`.
    pub fn trigger_single_lookup(
        &mut self,
        mut single_block_lookup: SingleBlockLookup<Current, T>,
        cx: &SyncNetworkContext<T>,
    ) {
        let block_root = single_block_lookup.block_root();
        match single_block_lookup.request_block_and_blobs(cx) {
            Ok(()) => self.add_single_lookup(single_block_lookup),
            Err(e) => {
                debug!(self.log, "Single block lookup failed";
                    "error" => ?e,
                    "block_root" => ?block_root,
                );
            }
        }
    }

    /// Adds a lookup to the `single_block_lookups` map.
    pub fn add_single_lookup(&mut self, single_block_lookup: SingleBlockLookup<Current, T>) {
        self.single_block_lookups
            .insert(single_block_lookup.id, single_block_lookup);

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    pub fn new_current_lookup(
        &mut self,
        block_root: Hash256,
        child_components: Option<ChildComponents<T::EthSpec>>,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        // Do not re-request a block that is already being requested
        if let Some((_, lookup)) = self
            .single_block_lookups
            .iter_mut()
            .find(|(_id, lookup)| lookup.is_for_block(block_root))
        {
            lookup.add_peers(peers);
            if let Some(components) = child_components {
                lookup.add_child_components(components);
            }
            return;
        }

        if let Some(parent_lookup) = self.parent_lookups.iter_mut().find(|parent_req| {
            parent_req.is_for_block(block_root) || parent_req.contains_block(&block_root)
        }) {
            parent_lookup.add_peers(peers);

            // If the block was already downloaded, or is being downloaded in this moment, do not
            // request it.
            return;
        }

        if self
            .processing_parent_lookups
            .values()
            .any(|(hashes, _last_parent_request)| hashes.contains(&block_root))
        {
            // we are already processing this block, ignore it.
            return;
        }

        let msg = if child_components.is_some() {
            "Searching for components of a block with unknown parent"
        } else {
            "Searching for block components"
        };

        let lookup = SingleBlockLookup::new(
            block_root,
            child_components,
            peers,
            self.da_checker.clone(),
            cx.next_id(),
        );

        debug!(
            self.log,
            "{}", msg;
            "peer_ids" => ?peers,
            "block" => ?block_root,
        );
        self.trigger_single_lookup(lookup, cx);
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
            parent_lookup.add_peer(peer_id);
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
            peer_id,
            self.da_checker.clone(),
            cx,
        );
        self.request_parent(parent_lookup, cx);
    }

    /* Lookup responses */

    /// Get a single block lookup by its ID. This method additionally ensures the `req_counter`
    /// matches the current `req_counter` for the lookup. This ensures any stale responses from requests
    /// that have been retried are ignored.
    fn get_single_lookup<R: RequestState<Current, T>>(
        &mut self,
        id: SingleLookupReqId,
    ) -> Option<SingleBlockLookup<Current, T>> {
        let mut lookup = self.single_block_lookups.remove(&id.id)?;

        let request_state = R::request_state_mut(&mut lookup);
        if id.req_counter != request_state.get_state().req_counter {
            // We don't want to drop the lookup, just ignore the old response.
            self.single_block_lookups.insert(id.id, lookup);
            return None;
        }
        Some(lookup)
    }

    /// Checks whether a single block lookup is waiting for a parent lookup to complete. This is
    /// necessary because we want to make sure all parents are processed before sending a child
    /// for processing, otherwise the block will fail validation and will be returned to the network
    /// layer with an `UnknownParent` error.
    pub fn has_pending_parent_request(&self, block_root: Hash256) -> bool {
        self.parent_lookups
            .iter()
            .any(|parent_lookup| parent_lookup.chain_hash() == block_root)
    }

    /// Process a block or blob response received from a single lookup request.
    pub fn single_lookup_response<R: RequestState<Current, T>>(
        &mut self,
        lookup_id: SingleLookupReqId,
        peer_id: PeerId,
        response: Option<R::ResponseType>,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
    ) {
        let id = lookup_id.id;
        let response_type = R::response_type();

        let Some(lookup) = self.get_single_lookup::<R>(lookup_id) else {
            if response.is_some() {
                // We don't have the ability to cancel in-flight RPC requests. So this can happen
                // if we started this RPC request, and later saw the block/blobs via gossip.
                debug!(
                    self.log,
                    "Block returned for single block lookup not present";
                        "response_type" => ?response_type,
                );
            }
            return;
        };

        let expected_block_root = lookup.block_root();

        match self.single_lookup_response_inner::<R>(peer_id, response, seen_timestamp, cx, lookup)
        {
            Ok(lookup) => {
                self.single_block_lookups.insert(id, lookup);
            }
            Err(e) => {
                debug!(self.log,
                    "Single lookup request failed";
                    "error" => ?e,
                    "block_root" => ?expected_block_root,
                );
            }
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /// Consolidates error handling for `single_lookup_response`. An `Err` here should always mean
    /// the lookup is dropped.
    fn single_lookup_response_inner<R: RequestState<Current, T>>(
        &self,
        peer_id: PeerId,
        response: Option<R::ResponseType>,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
        mut lookup: SingleBlockLookup<Current, T>,
    ) -> Result<SingleBlockLookup<Current, T>, LookupRequestError> {
        let response_type = R::response_type();
        let log = self.log.clone();
        let expected_block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup);

        match request_state.verify_response(expected_block_root, response) {
            Ok(Some(verified_response)) => {
                self.handle_verified_response::<Current, R>(
                    seen_timestamp,
                    cx,
                    BlockProcessType::SingleBlock { id: lookup.id },
                    verified_response,
                    &mut lookup,
                )?;
            }
            Ok(None) => {}
            Err(e) => {
                debug!(
                    log,
                    "Single lookup response verification failed, retrying";
                    "block_root" => ?expected_block_root,
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type,
                    "error" => ?e
                );
                let msg = e.into();
                cx.report_peer(peer_id, PeerAction::LowToleranceError, msg);

                request_state.register_failure_downloading();
                lookup.request_block_and_blobs(cx)?;
            }
        }
        Ok(lookup)
    }

    fn handle_verified_response<L: Lookup, R: RequestState<L, T>>(
        &self,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
        process_type: BlockProcessType,
        verified_response: R::VerifiedResponseType,
        lookup: &mut SingleBlockLookup<L, T>,
    ) -> Result<(), LookupRequestError> {
        let id = lookup.id;
        let block_root = lookup.block_root();

        R::request_state_mut(lookup)
            .get_state_mut()
            .component_downloaded = true;

        let cached_child = lookup.add_response::<R>(verified_response.clone());
        match cached_child {
            CachedChild::Ok(block) => {
                // If we have an outstanding parent request for this block, delay sending the response until
                // all parent blocks have been processed, otherwise we will fail validation with an
                // `UnknownParent`.
                let delay_send = match L::lookup_type() {
                    LookupType::Parent => false,
                    LookupType::Current => self.has_pending_parent_request(lookup.block_root()),
                };

                if !delay_send {
                    self.send_block_for_processing(
                        block_root,
                        block,
                        seen_timestamp,
                        process_type,
                        cx,
                    )?
                }
            }
            CachedChild::DownloadIncomplete => {
                // If this was the result of a block request, we can't determine if the block peer
                // did anything wrong. If we already had both a block and blobs response processed,
                // we should penalize the blobs peer because they did not provide all blobs on the
                // initial request.
                if lookup.both_components_downloaded() {
                    lookup.penalize_blob_peer(cx);
                    lookup
                        .blob_request_state
                        .state
                        .register_failure_downloading();
                }
                lookup.request_block_and_blobs(cx)?;
            }
            CachedChild::NotRequired => R::send_reconstructed_for_processing(
                id,
                self,
                block_root,
                R::verified_to_reconstructed(block_root, verified_response),
                seen_timestamp,
                cx,
            )?,
            CachedChild::Err(e) => {
                warn!(self.log, "Consistency error in cached block";
                    "error" => ?e,
                    "block_root" => ?block_root
                );
                lookup.handle_consistency_failure(cx);
                lookup.request_block_and_blobs(cx)?;
            }
        }
        Ok(())
    }

    /// Get a parent block lookup by its ID. This method additionally ensures the `req_counter`
    /// matches the current `req_counter` for the lookup. This any stale responses from requests
    /// that have been retried are ignored.
    fn get_parent_lookup<R: RequestState<Parent, T>>(
        &mut self,
        id: SingleLookupReqId,
    ) -> Option<ParentLookup<T>> {
        let mut parent_lookup = if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.current_parent_request.id == id.id)
        {
            self.parent_lookups.remove(pos)
        } else {
            return None;
        };

        if R::request_state_mut(&mut parent_lookup.current_parent_request)
            .get_state()
            .req_counter
            != id.req_counter
        {
            self.parent_lookups.push(parent_lookup);
            return None;
        }
        Some(parent_lookup)
    }

    /// Process a response received from a parent lookup request.
    pub fn parent_lookup_response<R: RequestState<Parent, T>>(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        response: Option<R::ResponseType>,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
    ) {
        let Some(mut parent_lookup) = self.get_parent_lookup::<R>(id) else {
            if response.is_some() {
                debug!(self.log, "Response for a parent lookup request that was not found"; "peer_id" => %peer_id);
            }
            return;
        };

        match self.parent_lookup_response_inner::<R>(
            peer_id,
            response,
            seen_timestamp,
            cx,
            &mut parent_lookup,
        ) {
            Ok(()) => {
                self.parent_lookups.push(parent_lookup);
            }
            Err(e) => {
                self.handle_parent_request_error(&mut parent_lookup, cx, e);
            }
        }

        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    /// Consolidates error handling for `parent_lookup_response`. An `Err` here should always mean
    /// the lookup is dropped.
    fn parent_lookup_response_inner<R: RequestState<Parent, T>>(
        &mut self,
        peer_id: PeerId,
        response: Option<R::ResponseType>,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
        parent_lookup: &mut ParentLookup<T>,
    ) -> Result<(), RequestError> {
        match parent_lookup.verify_response::<R>(response, &mut self.failed_chains) {
            Ok(Some(verified_response)) => {
                self.handle_verified_response::<Parent, R>(
                    seen_timestamp,
                    cx,
                    BlockProcessType::ParentLookup {
                        chain_hash: parent_lookup.chain_hash(),
                    },
                    verified_response,
                    &mut parent_lookup.current_parent_request,
                )?;
            }
            Ok(None) => {}
            Err(e) => self.handle_parent_verify_error::<R>(peer_id, parent_lookup, e, cx)?,
        };
        Ok(())
    }

    /// Handle logging and peer scoring for `ParentVerifyError`s during parent lookup requests.
    fn handle_parent_verify_error<R: RequestState<Parent, T>>(
        &mut self,
        peer_id: PeerId,
        parent_lookup: &mut ParentLookup<T>,
        e: ParentVerifyError,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), RequestError> {
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
                parent_lookup.request_parent(cx)?;
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
        }
        Ok(())
    }

    /// Handle logging and peer scoring for `RequestError`s during parent lookup requests.
    fn handle_parent_request_error(
        &mut self,
        parent_lookup: &mut ParentLookup<T>,
        cx: &SyncNetworkContext<T>,
        e: RequestError,
    ) {
        debug!(self.log, "Failed to request parent";  "error" => e.as_static());
        match e {
            RequestError::SendFailed(_) => {
                // Probably shutting down, nothing to do here. Drop the request
            }
            RequestError::ChainTooLong => {
                self.failed_chains.insert(parent_lookup.chain_hash());
                // This indicates faulty peers.
                for &peer_id in parent_lookup.used_peers() {
                    cx.report_peer(peer_id, PeerAction::LowToleranceError, e.as_static())
                }
            }
            RequestError::TooManyAttempts { cannot_process } => {
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
            RequestError::NoPeers => {
                // This happens if the peer disconnects while the block is being
                // processed. Drop the request without extra penalty
            }
        }
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId, cx: &mut SyncNetworkContext<T>) {
        /* Check disconnection for single lookups */
        self.single_block_lookups.retain(|_, req| {
            let should_drop_lookup =
                req.should_drop_lookup_on_disconnected_peer(peer_id, cx, &self.log);

            !should_drop_lookup
        });

        /* Check disconnection for parent lookups */
        while let Some(pos) = self
            .parent_lookups
            .iter_mut()
            .position(|req| req.check_peer_disconnected(peer_id).is_err())
        {
            let parent_lookup = self.parent_lookups.remove(pos);
            trace!(self.log, "Parent lookup's peer disconnected"; &parent_lookup);
            self.request_parent(parent_lookup, cx);
        }
    }

    /// An RPC error has occurred during a parent lookup. This function handles this case.
    pub fn parent_lookup_failed<R: RequestState<Parent, T>>(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        cx: &SyncNetworkContext<T>,
        error: RPCError,
    ) {
        let msg = error.as_static_str();
        let Some(mut parent_lookup) = self.get_parent_lookup::<R>(id) else {
            debug!(self.log,
                "RPC failure for a block parent lookup request that was not found";
                "peer_id" => %peer_id,
                "error" => msg
            );
            return;
        };
        R::request_state_mut(&mut parent_lookup.current_parent_request)
            .register_failure_downloading();
        trace!(self.log, "Parent lookup block request failed"; &parent_lookup, "error" => msg);

        self.request_parent(parent_lookup, cx);

        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    /// An RPC error has occurred during a single lookup. This function handles this case.\
    pub fn single_block_lookup_failed<R: RequestState<Current, T>>(
        &mut self,
        id: SingleLookupReqId,
        peer_id: &PeerId,
        cx: &SyncNetworkContext<T>,
        error: RPCError,
    ) {
        let msg = error.as_static_str();
        let log = self.log.clone();
        let Some(mut lookup) = self.get_single_lookup::<R>(id) else {
            debug!(log, "Error response to dropped lookup"; "error" => ?error);
            return;
        };
        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup);
        let response_type = R::response_type();
        trace!(log,
            "Single lookup failed";
            "block_root" => ?block_root,
            "error" => msg,
            "peer_id" => %peer_id,
            "response_type" => ?response_type
        );
        let id = id.id;
        request_state.register_failure_downloading();
        if let Err(e) = lookup.request_block_and_blobs(cx) {
            debug!(self.log,
                "Single lookup retry failed";
                "error" => ?e,
                "block_root" => ?block_root,
            );
            self.single_block_lookups.remove(&id);
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /* Processing responses */

    pub fn single_block_component_processed<R: RequestState<Current, T>>(
        &mut self,
        target_id: Id,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(mut lookup) = self.single_block_lookups.remove(&target_id) else {
            return;
        };

        let root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup);

        let Ok(peer_id) = request_state.get_state().processing_peer() else {
            return;
        };
        debug!(
            self.log,
            "Block component processed for lookup";
            "response_type" => ?R::response_type(),
            "block_root" => ?root,
        );

        match result {
            BlockProcessingResult::Ok(status) => match status {
                AvailabilityProcessingStatus::Imported(root) => {
                    trace!(self.log, "Single block processing succeeded"; "block" => %root);
                }
                AvailabilityProcessingStatus::MissingComponents(_, _block_root) => {
                    match self.handle_missing_components::<R>(cx, &mut lookup) {
                        Ok(()) => {
                            self.single_block_lookups.insert(target_id, lookup);
                        }
                        Err(e) => {
                            // Drop with an additional error.
                            warn!(self.log, "Single block lookup failed"; "block" => %root, "error" => ?e);
                        }
                    }
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
            }
            BlockProcessingResult::Err(e) => {
                match self.handle_single_lookup_block_error(cx, lookup, peer_id, e) {
                    Ok(Some(lookup)) => {
                        self.single_block_lookups.insert(target_id, lookup);
                    }
                    Ok(None) => {
                        // Drop without an additional error.
                    }
                    Err(e) => {
                        // Drop with an additional error.
                        warn!(self.log, "Single block lookup failed"; "block" => %root, "error" => ?e);
                    }
                }
            }
        };
    }

    /// Handles a `MissingComponents` block processing error. Handles peer scoring and retries.
    ///
    /// If this was the result of a block request, we can't determined if the block peer did anything
    /// wrong. If we already had both a block and blobs response processed, we should penalize the
    /// blobs peer because they did not provide all blobs on the initial request.
    fn handle_missing_components<R: RequestState<Current, T>>(
        &self,
        cx: &SyncNetworkContext<T>,
        lookup: &mut SingleBlockLookup<Current, T>,
    ) -> Result<(), LookupRequestError> {
        let request_state = R::request_state_mut(lookup);

        request_state.get_state_mut().component_processed = true;
        if lookup.both_components_processed() {
            lookup.penalize_blob_peer(cx);

            // Try it again if possible.
            lookup
                .blob_request_state
                .state
                .register_failure_processing();
            lookup.request_block_and_blobs(cx)?;
        }
        Ok(())
    }

    /// Handles peer scoring and retries related to a `BlockError` in response to a single block
    /// or blob lookup processing result.
    fn handle_single_lookup_block_error(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
        mut lookup: SingleBlockLookup<Current, T>,
        peer_id: PeerId,
        e: BlockError<T::EthSpec>,
    ) -> Result<Option<SingleBlockLookup<Current, T>>, LookupRequestError> {
        let root = lookup.block_root();
        trace!(self.log, "Single block processing failed"; "block" => %root, "error" => %e);
        match e {
            BlockError::BlockIsAlreadyKnown => {
                // No error here
                return Ok(None);
            }
            BlockError::BeaconChainError(e) => {
                // Internal error
                error!(self.log, "Beacon chain error processing single block"; "block_root" => %root, "error" => ?e);
                return Ok(None);
            }
            BlockError::ParentUnknown(block) => {
                let slot = block.slot();
                let parent_root = block.parent_root();
                lookup.add_child_components(block.into());
                lookup.request_block_and_blobs(cx)?;
                self.search_parent(slot, root, parent_root, peer_id, cx);
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
                return Ok(None);
            }
            BlockError::AvailabilityCheck(e) => match e.category() {
                AvailabilityCheckErrorCategory::Internal => {
                    warn!(self.log, "Internal availability check failure"; "root" => %root, "peer_id" => %peer_id, "error" => ?e);
                    lookup
                        .block_request_state
                        .state
                        .register_failure_downloading();
                    lookup
                        .blob_request_state
                        .state
                        .register_failure_downloading();
                    lookup.request_block_and_blobs(cx)?
                }
                AvailabilityCheckErrorCategory::Malicious => {
                    warn!(self.log, "Availability check failure"; "root" => %root, "peer_id" => %peer_id, "error" => ?e);
                    lookup.handle_availability_check_failure(cx);
                    lookup.request_block_and_blobs(cx)?
                }
            },
            other => {
                warn!(self.log, "Peer sent invalid block in single block lookup"; "root" => %root, "error" => ?other, "peer_id" => %peer_id);
                if let Ok(block_peer) = lookup.block_request_state.state.processing_peer() {
                    cx.report_peer(
                        block_peer,
                        PeerAction::MidToleranceError,
                        "single_block_failure",
                    );

                    // Try it again if possible.
                    lookup
                        .block_request_state
                        .state
                        .register_failure_processing();
                    lookup.request_block_and_blobs(cx)?
                }
            }
        }
        Ok(Some(lookup))
    }

    pub fn parent_block_processed(
        &mut self,
        chain_hash: Hash256,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let index = self
            .parent_lookups
            .iter()
            .enumerate()
            .find(|(_, lookup)| lookup.chain_hash() == chain_hash)
            .map(|(index, _)| index);

        let Some(mut parent_lookup) = index.map(|index| self.parent_lookups.remove(index)) else {
            return debug!(self.log, "Process response for a parent lookup request that was not found"; "chain_hash" => %chain_hash);
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
                let expected_block_root = parent_lookup.current_parent_request.block_root();
                if block_root != expected_block_root {
                    warn!(
                        self.log,
                        "Parent block processing result/request root mismatch";
                        "request" =>?expected_block_root,
                        "result" => ?block_root
                    );
                    return;
                }

                // We only send parent blocks + blobs for processing together. This means a
                // `MissingComponents` response here indicates missing blobs. Therefore we always
                // register a blob processing failure here.
                parent_lookup
                    .current_parent_request
                    .blob_request_state
                    .state
                    .register_failure_processing();
                match parent_lookup
                    .current_parent_request
                    .request_block_and_blobs(cx)
                {
                    Ok(()) => self.parent_lookups.push(parent_lookup),
                    Err(e) => self.handle_parent_request_error(&mut parent_lookup, cx, e.into()),
                }
            }
            BlockProcessingResult::Err(BlockError::ParentUnknown(block)) => {
                parent_lookup.add_unknown_parent_block(block);
                self.request_parent(parent_lookup, cx);
            }
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockProcessingResult::Err(BlockError::BlockIsAlreadyKnown { .. }) => {
                // Check if the beacon processor is available
                let Some(beacon_processor) = cx.beacon_processor_if_enabled() else {
                    return trace!(
                        self.log,
                        "Dropping parent chain segment that was ready for processing.";
                        parent_lookup
                    );
                };
                let (chain_hash, blocks, hashes, block_request) =
                    parent_lookup.parts_for_processing();

                let blocks = self.add_child_block_to_chain(chain_hash, blocks, cx).into();

                let process_id = ChainSegmentProcessId::ParentLookup(chain_hash);

                match beacon_processor.send_chain_segment(process_id, blocks) {
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
                self.handle_parent_block_error(outcome, cx, parent_lookup);
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

    /// Find the child block that spawned the parent lookup request and add it to the chain
    /// to send for processing.
    fn add_child_block_to_chain(
        &mut self,
        chain_hash: Hash256,
        mut blocks: VecDeque<RpcBlock<T::EthSpec>>,
        cx: &SyncNetworkContext<T>,
    ) -> VecDeque<RpcBlock<T::EthSpec>> {
        // Find the child block that spawned the parent lookup request and add it to the chain
        // to send for processing.
        if let Some(child_lookup_id) = self
            .single_block_lookups
            .iter()
            .find_map(|(id, lookup)| (lookup.block_root() == chain_hash).then_some(*id))
        {
            let Some(child_lookup) = self.single_block_lookups.get_mut(&child_lookup_id) else {
                debug!(self.log, "Missing child for parent lookup request"; "child_root" => ?chain_hash);
                return blocks;
            };
            match child_lookup.get_cached_child_block() {
                CachedChild::Ok(rpc_block) => {
                    // Insert this block at the front. This order is important because we later check
                    // for linear roots in `filter_chain_segment`
                    blocks.push_front(rpc_block);
                }
                CachedChild::DownloadIncomplete => {
                    trace!(self.log, "Parent lookup chain complete, awaiting child response"; "chain_hash" => ?chain_hash);
                }
                CachedChild::NotRequired => {
                    warn!(self.log, "Child not cached for parent lookup"; "chain_hash" => %chain_hash);
                }
                CachedChild::Err(e) => {
                    warn!(
                        self.log,
                        "Consistency error in child block triggering chain or parent lookups";
                        "error" => ?e,
                        "chain_hash" => ?chain_hash
                    );
                    child_lookup.handle_consistency_failure(cx);
                    if let Err(e) = child_lookup.request_block_and_blobs(cx) {
                        debug!(self.log,
                            "Failed to request block and blobs, dropping lookup";
                            "error" => ?e
                        );
                        self.single_block_lookups.remove(&child_lookup_id);
                    }
                }
            }
        } else {
            debug!(self.log, "Missing child for parent lookup request"; "child_root" => ?chain_hash);
        };
        blocks
    }

    /// Handle the peer scoring, retries, and logging related to a `BlockError` returned from
    /// processing a block + blobs for a parent lookup.
    fn handle_parent_block_error(
        &mut self,
        outcome: BlockError<<T as BeaconChainTypes>::EthSpec>,
        cx: &SyncNetworkContext<T>,
        mut parent_lookup: ParentLookup<T>,
    ) {
        // We should always have a block peer.
        let Ok(block_peer_id) = parent_lookup.block_processing_peer() else {
            return;
        };

        // We may not have a blob peer, if there were no blobs required for this block.
        let blob_peer_id = parent_lookup.blob_processing_peer().ok();

        // all else we consider the chain a failure and downvote the peer that sent
        // us the last block
        warn!(
            self.log, "Invalid parent chain";
            "score_adjustment" => %PeerAction::MidToleranceError,
            "outcome" => ?outcome,
            "block_peer_id" => %block_peer_id,
        );
        // This currently can be a host of errors. We permit this due to the partial
        // ambiguity.
        cx.report_peer(
            block_peer_id,
            PeerAction::MidToleranceError,
            "parent_request_err",
        );
        // Don't downscore the same peer twice
        if let Some(blob_peer_id) = blob_peer_id {
            if block_peer_id != blob_peer_id {
                debug!(
                    self.log, "Additionally down-scoring blob peer";
                    "score_adjustment" => %PeerAction::MidToleranceError,
                    "outcome" => ?outcome,
                    "blob_peer_id" => %blob_peer_id,
                );
                cx.report_peer(
                    blob_peer_id,
                    PeerAction::MidToleranceError,
                    "parent_request_err",
                );
            }
        }

        // Try again if possible
        parent_lookup.processing_failed();
        self.request_parent(parent_lookup, cx);
    }

    pub fn parent_chain_processed(
        &mut self,
        chain_hash: Hash256,
        result: BatchProcessResult,
        cx: &SyncNetworkContext<T>,
    ) {
        let Some((_hashes, request)) = self.processing_parent_lookups.remove(&chain_hash) else {
            return debug!(self.log, "Chain process response for a parent lookup request that was not found"; "chain_hash" => %chain_hash, "result" => ?result);
        };

        debug!(self.log, "Parent chain processed"; "chain_hash" => %chain_hash, "result" => ?result);
        match result {
            BatchProcessResult::Success { .. } => {
                let Some(id) = self
                    .single_block_lookups
                    .iter()
                    .find_map(|(id, req)| (req.block_root() == chain_hash).then_some(*id))
                else {
                    warn!(self.log, "No id found for single block lookup"; "chain_hash" => %chain_hash);
                    return;
                };

                let Some(lookup) = self.single_block_lookups.get_mut(&id) else {
                    warn!(self.log, "No id found for single block lookup"; "chain_hash" => %chain_hash);
                    return;
                };

                match lookup.get_cached_child_block() {
                    CachedChild::Ok(rpc_block) => {
                        // This is the correct block, send it for processing
                        if self
                            .send_block_for_processing(
                                chain_hash,
                                rpc_block,
                                timestamp_now(),
                                BlockProcessType::SingleBlock { id },
                                cx,
                            )
                            .is_err()
                        {
                            // Remove to avoid inconsistencies
                            self.single_block_lookups.remove(&id);
                        }
                    }
                    CachedChild::DownloadIncomplete => {
                        trace!(self.log, "Parent chain complete, awaiting child response"; "chain_hash" => %chain_hash);
                    }
                    CachedChild::NotRequired => {
                        warn!(self.log, "Child not cached for parent lookup"; "chain_hash" => %chain_hash);
                    }
                    CachedChild::Err(e) => {
                        warn!(
                            self.log,
                            "Consistency error in child block triggering parent lookup";
                            "chain_hash" => %chain_hash,
                            "error" => ?e
                        );
                        lookup.handle_consistency_failure(cx);
                        if let Err(e) = lookup.request_block_and_blobs(cx) {
                            debug!(self.log,
                                "Failed to request block and blobs, dropping lookup";
                                "error" => ?e
                            );
                            self.single_block_lookups.remove(&id);
                        }
                    }
                }
            }
            BatchProcessResult::FaultyFailure {
                imported_blocks: _,
                penalty,
            } => {
                self.failed_chains.insert(chain_hash);
                for peer_source in request.all_peers() {
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
        &self,
        block_root: Hash256,
        block: RpcBlock<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        match cx.beacon_processor_if_enabled() {
            Some(beacon_processor) => {
                trace!(self.log, "Sending block for processing"; "block" => ?block_root, "process" => ?process_type);
                if let Err(e) = beacon_processor.send_rpc_beacon_block(
                    block_root,
                    block,
                    duration,
                    process_type,
                ) {
                    error!(
                        self.log,
                        "Failed to send sync block to processor";
                        "error" => ?e
                    );
                    Err(LookupRequestError::SendFailed(
                        "beacon processor send failure",
                    ))
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping block ready for processing. Beacon processor not available"; "block" => %block_root);
                Err(LookupRequestError::SendFailed(
                    "beacon processor unavailable",
                ))
            }
        }
    }

    fn send_blobs_for_processing(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        match cx.beacon_processor_if_enabled() {
            Some(beacon_processor) => {
                trace!(self.log, "Sending blobs for processing"; "block" => ?block_root, "process_type" => ?process_type);
                if let Err(e) =
                    beacon_processor.send_rpc_blobs(block_root, blobs, duration, process_type)
                {
                    error!(
                        self.log,
                        "Failed to send sync blobs to processor";
                        "error" => ?e
                    );
                    Err(LookupRequestError::SendFailed(
                        "beacon processor send failure",
                    ))
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping blobs ready for processing. Beacon processor not available"; "block_root" => %block_root);
                Err(LookupRequestError::SendFailed(
                    "beacon processor unavailable",
                ))
            }
        }
    }

    /// Attempts to request the next unknown parent. This method handles peer scoring and dropping
    /// the lookup in the event of failure.
    fn request_parent(&mut self, mut parent_lookup: ParentLookup<T>, cx: &SyncNetworkContext<T>) {
        let response = parent_lookup.request_parent(cx);

        match response {
            Err(e) => {
                self.handle_parent_request_error(&mut parent_lookup, cx, e);
            }
            Ok(_) => self.parent_lookups.push(parent_lookup),
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
