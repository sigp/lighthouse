use self::parent_chain::{compute_parent_chains, NodeChain};
pub use self::single_block_lookup::DownloadResult;
use self::single_block_lookup::{LookupRequestError, LookupResult, SingleBlockLookup};
use super::manager::{BlockProcessType, BlockProcessingResult};
use super::network_context::{RpcProcessingResult, SyncNetworkContext};
use crate::metrics;
use crate::sync::block_lookups::common::{ResponseType, PARENT_DEPTH_TOLERANCE};
use crate::sync::block_lookups::parent_chain::find_oldest_fork_ancestor;
use crate::sync::manager::Id;
use crate::sync::network_context::LookupFailure;
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::data_availability_checker::AvailabilityCheckErrorCategory;
use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
pub use common::RequestState;
use fnv::FnvHashMap;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
pub use single_block_lookup::{BlobRequestState, BlockRequestState};
use slog::{debug, error, trace, warn, Logger};
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use types::{BlobSidecar, EthSpec, SignedBeaconBlock};

pub mod common;
pub mod parent_chain;
mod single_block_lookup;
#[cfg(test)]
mod tests;

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 4;

pub enum BlockComponent<E: EthSpec> {
    Block(DownloadResult<Arc<SignedBeaconBlock<E>>>),
    Blob(DownloadResult<Arc<BlobSidecar<E>>>),
}

impl<E: EthSpec> BlockComponent<E> {
    fn parent_root(&self) -> Hash256 {
        match self {
            BlockComponent::Block(block) => block.value.parent_root(),
            BlockComponent::Blob(blob) => blob.value.block_parent_root(),
        }
    }
    fn get_type(&self) -> &'static str {
        match self {
            BlockComponent::Block(_) => "block",
            BlockComponent::Blob(_) => "blob",
        }
    }
}

pub type SingleLookupId = u32;

enum Action {
    Retry,
    ParentUnknown { parent_root: Hash256 },
    Drop,
    Continue,
}

pub struct BlockLookups<T: BeaconChainTypes> {
    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    // TODO: Why not index lookups by block_root?
    single_block_lookups: FnvHashMap<SingleLookupId, SingleBlockLookup<T>>,

    /// The logger for the import manager.
    log: Logger,
}

impl<T: BeaconChainTypes> BlockLookups<T> {
    pub fn new(log: Logger) -> Self {
        Self {
            failed_chains: LRUTimeCache::new(Duration::from_secs(
                FAILED_CHAINS_CACHE_EXPIRY_SECONDS,
            )),
            single_block_lookups: Default::default(),
            log,
        }
    }

    #[cfg(test)]
    pub(crate) fn insert_failed_chain(&mut self, block_root: Hash256) {
        self.failed_chains.insert(block_root);
    }

    #[cfg(test)]
    pub(crate) fn get_failed_chains(&mut self) -> Vec<Hash256> {
        self.failed_chains.keys().cloned().collect()
    }

    #[cfg(test)]
    pub(crate) fn active_single_lookups(&self) -> Vec<(Id, Hash256, Option<Hash256>)> {
        self.single_block_lookups
            .iter()
            .map(|(id, e)| (*id, e.block_root(), e.awaiting_parent()))
            .collect()
    }

    /// Returns a vec of all parent lookup chains by tip, in descending slot order (tip first)
    pub(crate) fn active_parent_lookups(&self) -> Vec<NodeChain> {
        compute_parent_chains(
            &self
                .single_block_lookups
                .values()
                .map(|lookup| lookup.into())
                .collect::<Vec<_>>(),
        )
    }

    /* Lookup requests */

    /// Creates a parent lookup for the block with the given `block_root` and immediately triggers it.
    /// If a parent lookup exists or is triggered, a current lookup will be created.
    pub fn search_child_and_parent(
        &mut self,
        block_root: Hash256,
        block_component: BlockComponent<T::EthSpec>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let parent_root = block_component.parent_root();

        let parent_lookup_exists =
            self.search_parent_of_child(parent_root, block_root, &[peer_id], cx);
        // Only create the child lookup if the parent exists
        if parent_lookup_exists {
            // `search_parent_of_child` ensures that parent root is not a failed chain
            self.new_current_lookup(
                block_root,
                Some(block_component),
                Some(parent_root),
                &[peer_id],
                cx,
            );
        }
    }

    /// Seach a block whose parent root is unknown.
    /// Returns true if the lookup is created or already exists
    pub fn search_unknown_block(
        &mut self,
        block_root: Hash256,
        peer_source: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.new_current_lookup(block_root, None, None, peer_source, cx);
    }

    /// A block or blob triggers the search of a parent.
    /// Check if this new lookup extends a bad chain:
    /// - Extending `child_block_root_trigger` would exceed the max depth
    /// - `block_root_to_search` is a failed chain
    /// Returns true if the lookup is created or already exists
    pub fn search_parent_of_child(
        &mut self,
        block_root_to_search: Hash256,
        child_block_root_trigger: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> bool {
        let parent_chains = self.active_parent_lookups();

        for (chain_idx, parent_chain) in parent_chains.iter().enumerate() {
            if parent_chain.ancestor() == child_block_root_trigger
                && parent_chain.len() >= PARENT_DEPTH_TOLERANCE
            {
                debug!(self.log, "Parent lookup chain too long"; "block_root" => ?block_root_to_search);

                // Searching for this parent would extend a parent chain over the max
                // Insert the tip only to failed chains
                self.failed_chains.insert(parent_chain.tip);

                // Note: Drop only the chain that's too long until it merges with another chain
                // that's not too long. Consider this attack: there's a chain of valid unknown
                // blocks A -> B. A malicious peer builds `PARENT_DEPTH_TOLERANCE` garbage
                // blocks on top of A forming A -> C. The malicious peer forces us to fetch C
                // from it, which will result in parent A hitting the chain_too_long error. Then
                // the valid chain A -> B is dropped too.
                if let Ok(block_to_drop) = find_oldest_fork_ancestor(parent_chains, chain_idx) {
                    // Drop all lookups descending from the child of the too long parent chain
                    if let Some((lookup_id, lookup)) = self
                        .single_block_lookups
                        .iter()
                        .find(|(_, l)| l.block_root() == block_to_drop)
                    {
                        for &peer_id in lookup.all_used_peers() {
                            cx.report_peer(
                                peer_id,
                                PeerAction::LowToleranceError,
                                "chain_too_long",
                            );
                        }
                        self.drop_lookup_and_children(*lookup_id);
                    }
                }

                return false;
            }
        }

        // `block_root_to_search` is a failed chain check happens inside new_current_lookup
        self.new_current_lookup(block_root_to_search, None, None, peers, cx)
    }

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    /// Returns true if the lookup is created or already exists
    fn new_current_lookup(
        &mut self,
        block_root: Hash256,
        block_component: Option<BlockComponent<T::EthSpec>>,
        awaiting_parent: Option<Hash256>,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> bool {
        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&block_root) {
            debug!(self.log, "Block is from a past failed chain. Dropping"; "block_root" => ?block_root);
            for peer_id in peers {
                cx.report_peer(*peer_id, PeerAction::MidToleranceError, "failed_chain");
            }
            return false;
        }

        // Do not re-request a block that is already being requested
        if let Some((_, lookup)) = self
            .single_block_lookups
            .iter_mut()
            .find(|(_id, lookup)| lookup.is_for_block(block_root))
        {
            trace!(self.log, "Adding peer to existing single block lookup"; "block_root" => %block_root);
            lookup.add_peers(peers);
            if let Some(block_component) = block_component {
                let component_type = block_component.get_type();
                let imported = lookup.add_child_components(block_component);
                if !imported {
                    debug!(self.log, "Lookup child component ignored"; "block_root" => %block_root, "type" => component_type);
                }
            }
            return true;
        }

        // Ensure that awaiting parent exists, otherwise this lookup won't be able to make progress
        if let Some(awaiting_parent) = awaiting_parent {
            if !self
                .single_block_lookups
                .iter()
                .any(|(_, lookup)| lookup.is_for_block(awaiting_parent))
            {
                return false;
            }
        }

        let msg = if block_component.is_some() {
            "Searching for components of a block with unknown parent"
        } else {
            "Searching for block components"
        };
        debug!(
            self.log,
            "{}", msg;
            "peer_ids" => ?peers,
            "block" => ?block_root,
        );
        metrics::inc_counter(&metrics::SYNC_LOOKUP_CREATED);

        // If we know that this lookup has unknown parent (is awaiting a parent lookup to resolve),
        // signal here to hold processing downloaded data.
        let mut lookup = SingleBlockLookup::new(block_root, peers, cx.next_id(), awaiting_parent);

        // Add block components to the new request
        if let Some(block_component) = block_component {
            lookup.add_child_components(block_component);
        }

        let id = lookup.id;
        let lookup = match self.single_block_lookups.entry(id) {
            Entry::Vacant(entry) => entry.insert(lookup),
            Entry::Occupied(_) => {
                // Should never happen
                warn!(self.log, "Lookup exists with same id"; "id" => id);
                return false;
            }
        };

        let result = lookup.continue_requests(cx);
        self.on_lookup_result(id, result, "new_current_lookup", cx);
        self.update_metrics();
        true
    }

    /* Lookup responses */

    /// Process a block or blob response received from a single lookup request.
    pub fn on_download_response<R: RequestState<T>>(
        &mut self,
        id: SingleLookupId,
        peer_id: PeerId,
        response: RpcProcessingResult<R::VerifiedResponseType>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let result = self.on_download_response_inner::<R>(id, peer_id, response, cx);
        self.on_lookup_result(id, result, "download_response", cx);
    }

    /// Process a block or blob response received from a single lookup request.
    pub fn on_download_response_inner<R: RequestState<T>>(
        &mut self,
        id: SingleLookupId,
        peer_id: PeerId,
        response: RpcProcessingResult<R::VerifiedResponseType>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        // Downscore peer even if lookup is not known
        // Only downscore lookup verify errors. RPC errors are downscored in the network handler.
        if let Err(LookupFailure::LookupVerifyError(e)) = &response {
            // Note: the error is displayed in full debug form on the match below
            cx.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
        }

        let response_type = R::response_type();
        let Some(lookup) = self.single_block_lookups.get_mut(&id) else {
            // We don't have the ability to cancel in-flight RPC requests. So this can happen
            // if we started this RPC request, and later saw the block/blobs via gossip.
            debug!(self.log, "Block returned for single block lookup not present"; "id" => id);
            return Err(LookupRequestError::UnknownLookup);
        };

        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(lookup).get_state_mut();

        match response {
            Ok((response, seen_timestamp)) => {
                debug!(self.log,
                    "Received lookup download success";
                    "block_root" => %block_root,
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type,
                );

                // Register the download peer here. Once we have received some data over the wire we
                // attribute it to this peer for scoring latter regardless of how the request was
                // done.
                request_state.on_download_success(DownloadResult {
                    value: response,
                    block_root,
                    seen_timestamp,
                    peer_id,
                })?;
                // continue_request will send for  processing as the request state is AwaitingProcessing
            }
            Err(e) => {
                debug!(self.log,
                    "Received lookup download failure";
                    "block_root" => %block_root,
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type,
                    "error" => %e,
                );

                request_state.on_download_failure()?;
                // continue_request will retry a download as the request state is AwaitingDownload
            }
        }

        lookup.continue_requests(cx)
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId) {
        /* Check disconnection for single lookups */
        self.single_block_lookups.retain(|_, req| {
            let should_drop_lookup =
                req.should_drop_lookup_on_disconnected_peer(peer_id );

            if should_drop_lookup {
                debug!(self.log, "Dropping single lookup after peer disconnection"; "block_root" => %req.block_root());
            }

            !should_drop_lookup
        });
    }

    /* Processing responses */

    pub fn on_processing_result(
        &mut self,
        process_type: BlockProcessType,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let lookup_result = match process_type {
            BlockProcessType::SingleBlock { id } => {
                self.on_processing_result_inner::<BlockRequestState<T::EthSpec>>(id, result, cx)
            }
            BlockProcessType::SingleBlob { id } => {
                self.on_processing_result_inner::<BlobRequestState<T::EthSpec>>(id, result, cx)
            }
        };
        self.on_lookup_result(process_type.id(), lookup_result, "processing_result", cx);
    }

    pub fn on_processing_result_inner<R: RequestState<T>>(
        &mut self,
        lookup_id: SingleLookupId,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let Some(lookup) = self.single_block_lookups.get_mut(&lookup_id) else {
            debug!(self.log, "Unknown single block lookup"; "id" => lookup_id);
            return Err(LookupRequestError::UnknownLookup);
        };

        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(lookup).get_state_mut();

        debug!(
            self.log,
            "Received lookup processing result";
            "component" => ?R::response_type(),
            "block_root" => ?block_root,
            "result" => ?result,
        );

        let action = match result {
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockProcessingResult::Err(BlockError::BlockIsAlreadyKnown(_)) => {
                // Successfully imported
                request_state.on_processing_success()?;
                Action::Continue
            }

            BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                _,
                _block_root,
            )) => {
                // `on_processing_success` is called here to ensure the request state is updated prior to checking
                // if both components have been processed.
                request_state.on_processing_success()?;

                // If this was the result of a block request, we can't determined if the block peer did anything
                // wrong. If we already had both a block and blobs response processed, we should penalize the
                // blobs peer because they did not provide all blobs on the initial request.
                if lookup.both_components_processed() {
                    if let Some(blob_peer) = lookup
                        .blob_request_state
                        .state
                        .on_post_process_validation_failure()?
                    {
                        cx.report_peer(
                            blob_peer,
                            PeerAction::MidToleranceError,
                            "sent_incomplete_blobs",
                        );
                    }
                }
                Action::Retry
            }
            BlockProcessingResult::Ignored => {
                // Beacon processor signalled to ignore the block processing result.
                // This implies that the cpu is overloaded. Drop the request.
                warn!(
                    self.log,
                    "Lookup component processing ignored, cpu might be overloaded";
                    "component" => ?R::response_type(),
                );
                Action::Drop
            }
            BlockProcessingResult::Err(e) => {
                match e {
                    BlockError::BeaconChainError(e) => {
                        // Internal error
                        error!(self.log, "Beacon chain error processing lookup component"; "block_root" => %block_root, "error" => ?e);
                        Action::Drop
                    }
                    BlockError::ParentUnknown(block) => {
                        // Reverts the status of this request to `AwaitingProcessing` holding the
                        // downloaded data. A future call to `continue_requests` will re-submit it
                        // once there are no pending parent requests.
                        // Note: `BlockError::ParentUnknown` is only returned when processing
                        // blocks, not blobs.
                        request_state.revert_to_awaiting_processing()?;
                        Action::ParentUnknown {
                            parent_root: block.parent_root(),
                        }
                    }
                    ref e @ BlockError::ExecutionPayloadError(ref epe) if !epe.penalize_peer() => {
                        // These errors indicate that the execution layer is offline
                        // and failed to validate the execution payload. Do not downscore peer.
                        debug!(
                            self.log,
                            "Single block lookup failed. Execution layer is offline / unsynced / misconfigured";
                            "block_root" => %block_root,
                            "error" => ?e
                        );
                        Action::Drop
                    }
                    BlockError::AvailabilityCheck(e)
                        if e.category() == AvailabilityCheckErrorCategory::Internal =>
                    {
                        // There errors indicate internal problems and should not downscore the  peer
                        warn!(self.log, "Internal availability check failure"; "block_root" => %block_root, "error" => ?e);

                        // Here we choose *not* to call `on_processing_failure` because this could result in a bad
                        // lookup state transition. This error invalidates both blob and block requests, and we don't know the
                        // state of both requests. Blobs may have already successfullly processed for example.
                        // We opt to drop the lookup instead.
                        Action::Drop
                    }
                    other => {
                        debug!(self.log, "Invalid lookup component"; "block_root" => %block_root, "component" => ?R::response_type(), "error" => ?other);
                        let peer_id = request_state.on_processing_failure()?;
                        cx.report_peer(
                            peer_id,
                            PeerAction::MidToleranceError,
                            match R::response_type() {
                                ResponseType::Block => "lookup_block_processing_failure",
                                ResponseType::Blob => "lookup_blobs_processing_failure",
                            },
                        );

                        Action::Retry
                    }
                }
            }
        };

        match action {
            Action::Retry => {
                // Trigger download for all components in case `MissingComponents` failed the blob
                // request. Also if blobs are `AwaitingProcessing` and need to be progressed
                lookup.continue_requests(cx)
            }
            Action::ParentUnknown { parent_root } => {
                let peers = lookup.all_available_peers().cloned().collect::<Vec<_>>();
                lookup.set_awaiting_parent(parent_root);
                debug!(self.log, "Marking lookup as awaiting parent"; "lookup" => %block_root, "parent_root" => %parent_root);
                self.search_parent_of_child(parent_root, block_root, &peers, cx);
                Ok(LookupResult::Pending)
            }
            Action::Drop => {
                // Drop with noop
                Err(LookupRequestError::Failed)
            }
            Action::Continue => {
                // Drop this completed lookup only
                Ok(LookupResult::Completed)
            }
        }
    }

    /// Makes progress on the immediate children of `block_root`
    pub fn continue_child_lookups(&mut self, block_root: Hash256, cx: &mut SyncNetworkContext<T>) {
        let mut lookup_results = vec![]; // < need to buffer lookup results to not re-borrow &mut self

        for (id, lookup) in self.single_block_lookups.iter_mut() {
            if lookup.awaiting_parent() == Some(block_root) {
                lookup.resolve_awaiting_parent();
                debug!(self.log, "Continuing child lookup"; "parent_root" => %block_root, "block_root" => %lookup.block_root());
                let result = lookup.continue_requests(cx);
                lookup_results.push((*id, result));
            }
        }

        for (id, result) in lookup_results {
            self.on_lookup_result(id, result, "continue_child_lookups", cx);
        }
    }

    /// Drops `dropped_id` lookup and all its children recursively. Lookups awaiting a parent need
    /// the parent to make progress to resolve, therefore we must drop them if the parent is
    /// dropped.
    pub fn drop_lookup_and_children(&mut self, dropped_id: SingleLookupId) {
        if let Some(dropped_lookup) = self.single_block_lookups.remove(&dropped_id) {
            debug!(self.log, "Dropping child lookup"; "id" => ?dropped_id, "block_root" => %dropped_lookup.block_root());

            let child_lookups = self
                .single_block_lookups
                .iter()
                .filter(|(_, lookup)| lookup.awaiting_parent() == Some(dropped_lookup.block_root()))
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();

            for id in child_lookups {
                self.drop_lookup_and_children(id);
            }
        }
    }

    /// Common handler a lookup request error, drop it and update metrics
    fn on_lookup_result(
        &mut self,
        id: SingleLookupId,
        result: Result<LookupResult, LookupRequestError>,
        source: &str,
        cx: &mut SyncNetworkContext<T>,
    ) {
        match result {
            Ok(LookupResult::Pending) => {} // no action
            Ok(LookupResult::Completed) => {
                if let Some(lookup) = self.single_block_lookups.remove(&id) {
                    debug!(self.log, "Dropping completed lookup"; "block" => %lookup.block_root());
                    metrics::inc_counter(&metrics::SYNC_LOOKUP_COMPLETED);
                    // Block imported, continue the requests of pending child blocks
                    self.continue_child_lookups(lookup.block_root(), cx);
                    self.update_metrics();
                }
            }
            Err(error) => {
                debug!(self.log, "Dropping lookup on request error"; "id" => id, "source" => source, "error" => ?error);
                metrics::inc_counter_vec(&metrics::SYNC_LOOKUP_DROPPED, &[error.into()]);
                self.drop_lookup_and_children(id);
                self.update_metrics();
            }
        }
    }

    /* Helper functions */

    /// Drops all the single block requests and returns how many requests were dropped.
    pub fn drop_single_block_requests(&mut self) -> usize {
        let requests_to_drop = self.single_block_lookups.len();
        self.single_block_lookups.clear();
        requests_to_drop
    }

    pub fn update_metrics(&self) {
        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }
}
