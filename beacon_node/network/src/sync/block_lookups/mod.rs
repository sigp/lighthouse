//! Implements block lookup sync.
//!
//! Block lookup sync is triggered when a peer claims to have imported a block we don't know about.
//! For example, a peer attesting to a head block root that is not in our fork-choice. Lookup sync
//! is recursive in nature, as we may discover that this attested head block root has a parent that
//! is also unknown to us.
//!
//! Block lookup is implemented as an event-driven state machine. It sends events to the network and
//! beacon processor, and expects some set of events back. A discrepancy in the expected event API
//! will result in lookups getting "stuck". A lookup becomes stuck when there is no future event
//! that will trigger the lookup to make progress. There's a fallback mechanism that drops lookups
//! that live for too long, logging the line "Notify the devs a sync lookup is stuck".
//!
//! The expected event API is documented in the code paths that are making assumptions  with the
//! comment prefix "Lookup sync event safety:"
//!
//! Block lookup sync attempts to not re-download or re-process data that we already have. Block
//! components are cached temporarily in multiple places before they are imported into fork-choice.
//! Therefore, block lookup sync must peek these caches correctly to decide when to skip a download
//! or consider a lookup complete. These caches are read from the `SyncNetworkContext` and its state
//! returned to this module as `LookupRequestResult` variants.

use self::parent_chain::{compute_parent_chains, NodeChain};
pub use self::single_block_lookup::DownloadResult;
use self::single_block_lookup::{LookupRequestError, LookupResult, SingleBlockLookup};
use super::manager::{BlockProcessType, BlockProcessingResult, SLOT_IMPORT_TOLERANCE};
use super::network_context::{RpcResponseResult, SyncNetworkContext};
use crate::metrics;
use crate::sync::block_lookups::common::ResponseType;
use crate::sync::block_lookups::parent_chain::find_oldest_fork_ancestor;
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::data_availability_checker::AvailabilityCheckErrorCategory;
use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
pub use common::RequestState;
use fnv::FnvHashMap;
use lighthouse_network::service::api_types::SingleLookupReqId;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
pub use single_block_lookup::{BlobRequestState, BlockRequestState};
use slog::{debug, error, warn, Logger};
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

/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
pub(crate) const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 4;

/// Maximum time we allow a lookup to exist before assuming it is stuck and will never make
/// progress. Assume the worse case processing time per block component set * times max depth.
/// 15 * 2 * 32 = 16 minutes.
const LOOKUP_MAX_DURATION_STUCK_SECS: u64 = 15 * PARENT_DEPTH_TOLERANCE as u64;
/// The most common case of child-lookup without peers is receiving block components before the
/// attestation deadline when the node is lagging behind. Once peers start attesting for the child
/// lookup at most after 4 seconds, the lookup should gain peers.
const LOOKUP_MAX_DURATION_NO_PEERS_SECS: u64 = 10;

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

#[cfg(test)]
use lighthouse_network::service::api_types::Id;

#[cfg(test)]
/// Tuple of `SingleLookupId`, requested block root, awaiting parent block root (if any),
/// and list of peers that claim to have imported this set of block components.
pub(crate) type BlockLookupSummary = (Id, Hash256, Option<Hash256>, Vec<PeerId>);

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
    pub(crate) fn active_single_lookups(&self) -> Vec<BlockLookupSummary> {
        self.single_block_lookups
            .iter()
            .map(|(id, l)| {
                (
                    *id,
                    l.block_root(),
                    l.awaiting_parent(),
                    l.all_peers().copied().collect(),
                )
            })
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
                // On a `UnknownParentBlock` or `UnknownParentBlob` event the peer is not required
                // to have the rest of the block components (refer to decoupled blob gossip). Create
                // the lookup with zero peers to house the block components.
                &[],
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
            // `block_root_to_search` will trigger a new lookup, and it will extend a parent_chain
            // beyond its max length
            let block_would_extend_chain = parent_chain.ancestor() == child_block_root_trigger;
            // `block_root_to_search` already has a lookup, and with the block trigger it extends
            // the parent_chain beyond its length. This can happen because when creating a lookup
            // for a new root we don't do any parent chain length checks
            let trigger_is_chain_tip = parent_chain.tip == child_block_root_trigger;

            if (block_would_extend_chain || trigger_is_chain_tip)
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
                        for &peer_id in lookup.all_peers() {
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
        if let Some((&lookup_id, lookup)) = self
            .single_block_lookups
            .iter_mut()
            .find(|(_id, lookup)| lookup.is_for_block(block_root))
        {
            if let Some(block_component) = block_component {
                let component_type = block_component.get_type();
                let imported = lookup.add_child_components(block_component);
                if !imported {
                    debug!(self.log, "Lookup child component ignored"; "block_root" => ?block_root, "type" => component_type);
                }
            }

            if let Err(e) = self.add_peers_to_lookup_and_ancestors(lookup_id, peers, cx) {
                warn!(self.log, "Error adding peers to ancestor lookup"; "error" => ?e);
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
                warn!(self.log, "Ignoring child lookup parent lookup not found"; "block_root" => ?awaiting_parent);
                return false;
            }
        }

        // If we know that this lookup has unknown parent (is awaiting a parent lookup to resolve),
        // signal here to hold processing downloaded data.
        let mut lookup = SingleBlockLookup::new(block_root, peers, cx.next_id(), awaiting_parent);

        let msg = if block_component.is_some() {
            "Searching for components of a block with unknown parent"
        } else {
            "Searching for block components"
        };
        debug!(
            self.log,
            "{}", msg;
            "peer_ids" => ?peers,
            "block_root" => ?block_root,
            "id" => lookup.id,
        );
        metrics::inc_counter(&metrics::SYNC_LOOKUP_CREATED);

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
        if self.on_lookup_result(id, result, "new_current_lookup", cx) {
            self.update_metrics();
            true
        } else {
            false
        }
    }

    /* Lookup responses */

    /// Process a block or blob response received from a single lookup request.
    pub fn on_download_response<R: RequestState<T>>(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        response: RpcResponseResult<R::VerifiedResponseType>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let result = self.on_download_response_inner::<R>(id, peer_id, response, cx);
        self.on_lookup_result(id.lookup_id, result, "download_response", cx);
    }

    /// Process a block or blob response received from a single lookup request.
    pub fn on_download_response_inner<R: RequestState<T>>(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        response: RpcResponseResult<R::VerifiedResponseType>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        // Note: no need to downscore peers here, already downscored on network context

        let response_type = R::response_type();
        let Some(lookup) = self.single_block_lookups.get_mut(&id.lookup_id) else {
            // We don't have the ability to cancel in-flight RPC requests. So this can happen
            // if we started this RPC request, and later saw the block/blobs via gossip.
            debug!(self.log, "Block returned for single block lookup not present"; "id" => ?id);
            return Err(LookupRequestError::UnknownLookup);
        };

        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(lookup).get_state_mut();

        match response {
            Ok((response, seen_timestamp)) => {
                debug!(self.log,
                    "Received lookup download success";
                    "block_root" => ?block_root,
                    "id" => ?id,
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type,
                );

                // Here we could check if response extends a parent chain beyond its max length.
                // However we defer that check to the handling of a processing error ParentUnknown.
                //
                // Here we could check if there's already a lookup for parent_root of `response`. In
                // that case we know that sending the response for processing will likely result in
                // a `ParentUnknown` error. However, for simplicity we choose to not implement this
                // optimization.

                // Register the download peer here. Once we have received some data over the wire we
                // attribute it to this peer for scoring latter regardless of how the request was
                // done.
                request_state.on_download_success(
                    id.req_id,
                    DownloadResult {
                        value: response,
                        block_root,
                        seen_timestamp,
                        peer_id,
                    },
                )?;
                // continue_request will send for  processing as the request state is AwaitingProcessing
            }
            Err(e) => {
                debug!(self.log,
                    "Received lookup download failure";
                    "block_root" => ?block_root,
                    "id" => ?id,
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type,
                    "error" => %e,
                );

                request_state.on_download_failure(id.req_id)?;
                // continue_request will retry a download as the request state is AwaitingDownload
            }
        }

        lookup.continue_requests(cx)
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId) {
        for (_, lookup) in self.single_block_lookups.iter_mut() {
            lookup.remove_peer(peer_id);
        }
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
        let id = match process_type {
            BlockProcessType::SingleBlock { id } | BlockProcessType::SingleBlob { id } => id,
        };
        self.on_lookup_result(id, lookup_result, "processing_result", cx);
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
            "id" => lookup_id,
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

                if lookup.both_components_processed() {
                    // We don't request for other block components until being sure that the block has
                    // data. If we request blobs / columns to a peer we are sure those must exist.
                    // Therefore if all components are processed and we still receive `MissingComponents`
                    // it indicates an internal bug.
                    return Err(LookupRequestError::MissingComponentsAfterAllProcessed);
                } else {
                    // Continue request, potentially request blobs
                    Action::Retry
                }
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
                            "block_root" => ?block_root,
                            "error" => ?e
                        );
                        Action::Drop
                    }
                    BlockError::AvailabilityCheck(e)
                        if e.category() == AvailabilityCheckErrorCategory::Internal =>
                    {
                        // There errors indicate internal problems and should not downscore the  peer
                        warn!(self.log, "Internal availability check failure"; "block_root" => ?block_root, "error" => ?e);

                        // Here we choose *not* to call `on_processing_failure` because this could result in a bad
                        // lookup state transition. This error invalidates both blob and block requests, and we don't know the
                        // state of both requests. Blobs may have already successfullly processed for example.
                        // We opt to drop the lookup instead.
                        Action::Drop
                    }
                    other => {
                        debug!(self.log, "Invalid lookup component"; "block_root" => ?block_root, "component" => ?R::response_type(), "error" => ?other);

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
                let peers = lookup.all_peers().copied().collect::<Vec<_>>();
                lookup.set_awaiting_parent(parent_root);
                debug!(self.log, "Marking lookup as awaiting parent"; "id" => lookup.id, "block_root" => ?block_root, "parent_root" => ?parent_root);
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

    pub fn on_external_processing_result(
        &mut self,
        block_root: Hash256,
        imported: bool,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some((id, lookup)) = self
            .single_block_lookups
            .iter_mut()
            .find(|(_, lookup)| lookup.is_for_block(block_root))
        else {
            // Ok to ignore gossip process events
            return;
        };

        let lookup_result = if imported {
            Ok(LookupResult::Completed)
        } else {
            lookup.continue_requests(cx)
        };
        let id = *id;
        self.on_lookup_result(id, lookup_result, "external_processing_result", cx);
    }

    /// Makes progress on the immediate children of `block_root`
    pub fn continue_child_lookups(&mut self, block_root: Hash256, cx: &mut SyncNetworkContext<T>) {
        let mut lookup_results = vec![]; // < need to buffer lookup results to not re-borrow &mut self

        for (id, lookup) in self.single_block_lookups.iter_mut() {
            if lookup.awaiting_parent() == Some(block_root) {
                lookup.resolve_awaiting_parent();
                debug!(self.log, "Continuing child lookup"; "parent_root" => ?block_root, "id" => id, "block_root" => ?lookup.block_root());
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
            debug!(self.log, "Dropping lookup";
                "id" => ?dropped_id,
                "block_root" => ?dropped_lookup.block_root(),
                "awaiting_parent" => ?dropped_lookup.awaiting_parent(),
            );

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
    /// Returns true if the lookup is created or already exists
    fn on_lookup_result(
        &mut self,
        id: SingleLookupId,
        result: Result<LookupResult, LookupRequestError>,
        source: &str,
        cx: &mut SyncNetworkContext<T>,
    ) -> bool {
        match result {
            Ok(LookupResult::Pending) => true, // no action
            Ok(LookupResult::Completed) => {
                if let Some(lookup) = self.single_block_lookups.remove(&id) {
                    debug!(self.log, "Dropping completed lookup"; "block" => ?lookup.block_root(), "id" => id);
                    metrics::inc_counter(&metrics::SYNC_LOOKUP_COMPLETED);
                    // Block imported, continue the requests of pending child blocks
                    self.continue_child_lookups(lookup.block_root(), cx);
                    self.update_metrics();
                } else {
                    debug!(self.log, "Attempting to drop non-existent lookup"; "id" => id);
                }
                false
            }
            // If UnknownLookup do not log the request error. No need to drop child lookups nor
            // update metrics because the lookup does not exist.
            Err(LookupRequestError::UnknownLookup) => false,
            Err(error) => {
                debug!(self.log, "Dropping lookup on request error"; "id" => id, "source" => source, "error" => ?error);
                metrics::inc_counter_vec(&metrics::SYNC_LOOKUP_DROPPED, &[error.into()]);
                self.drop_lookup_and_children(id);
                self.update_metrics();
                false
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

    /// Perform some prune operations on lookups on some interval
    pub fn prune_lookups(&mut self) {
        self.drop_lookups_without_peers();
        self.drop_stuck_lookups();
    }

    /// Lookups without peers are allowed to exist for some time. See this common race condition:
    ///
    /// 1. Receive unknown block parent event
    /// 2. Create child lookup with zero peers
    /// 3. Parent is processed, before receiving any attestation for the child block
    /// 4. Child lookup is attempted to make progress but has no peers
    /// 5. We receive an attestion for child block and add a peer to the child block lookup
    ///
    /// On step 4 we could drop the lookup because we attempt to issue a request with no peers
    /// available. This has two issues:
    /// - We may drop the lookup while some other block component is processing, triggering an
    ///   unknown lookup error. This can potentially cause un-related child lookups to also be
    ///   dropped when calling `drop_lookup_and_children`.
    /// - We lose all progress of the lookup, and have to re-download its components that we may
    ///   already have there cached.
    ///
    /// Instead there's no negative for keeping lookups with no peers around for some time. If we
    /// regularly prune them, it should not be a memory concern (TODO: maybe yes!).
    fn drop_lookups_without_peers(&mut self) {
        for (lookup_id, block_root) in self
            .single_block_lookups
            .values()
            .filter(|lookup| {
                // Do not drop lookup that are awaiting events to prevent inconsinstencies. If a
                // lookup gets stuck, it will be eventually pruned by `drop_stuck_lookups`
                lookup.has_no_peers()
                    && lookup.elapsed_since_created()
                        > Duration::from_secs(LOOKUP_MAX_DURATION_NO_PEERS_SECS)
                    && !lookup.is_awaiting_event()
            })
            .map(|lookup| (lookup.id, lookup.block_root()))
            .collect::<Vec<_>>()
        {
            debug!(self.log, "Dropping lookup with no peers";
                "id" => lookup_id,
                "block_root" => ?block_root
            );
            self.drop_lookup_and_children(lookup_id);
        }
    }

    /// Safety mechanism to unstuck lookup sync. Lookup sync if purely event driven and depends on
    /// external components to feed it events to make progress. If there is a bug in network, in
    /// beacon processor, or here internally: lookups can get stuck forever. A stuck lookup can
    /// stall a node indefinitely as other lookup will be awaiting on a parent lookup to make
    /// progress.
    ///
    /// If a lookup lasts more than LOOKUP_MAX_DURATION_SECS this function will find its oldest
    /// ancestor and then drop it and all its children. This action will allow the node to unstuck
    /// itself. Bugs that cause lookups to get stuck may be triggered consistently. So this strategy
    /// is useful for two reasons:
    ///
    /// - One single clear warn level log per stuck incident
    /// - If the original bug is sporadic, it reduces the time a node is stuck from forever to 15 min
    fn drop_stuck_lookups(&mut self) {
        // While loop to find and drop all disjoint trees of potentially stuck lookups.
        while let Some(stuck_lookup) = self.single_block_lookups.values().find(|lookup| {
            lookup.elapsed_since_created() > Duration::from_secs(LOOKUP_MAX_DURATION_STUCK_SECS)
        }) {
            let ancestor_stuck_lookup = match self.find_oldest_ancestor_lookup(stuck_lookup) {
                Ok(lookup) => lookup,
                Err(e) => {
                    warn!(self.log, "Error finding oldest ancestor lookup"; "error" => ?e);
                    // Default to dropping the lookup that exceeds the max duration so at least
                    // eventually sync should be unstuck
                    stuck_lookup
                }
            };

            if stuck_lookup.id == ancestor_stuck_lookup.id {
                warn!(self.log, "Notify the devs a sync lookup is stuck";
                    "block_root" => ?stuck_lookup.block_root(),
                    "lookup" => ?stuck_lookup,
                );
            } else {
                warn!(self.log, "Notify the devs a sync lookup is stuck";
                    "block_root" => ?stuck_lookup.block_root(),
                    "lookup" => ?stuck_lookup,
                    "ancestor_block_root" => ?ancestor_stuck_lookup.block_root(),
                    "ancestor_lookup" => ?ancestor_stuck_lookup,
                );
            }

            metrics::inc_counter(&metrics::SYNC_LOOKUPS_STUCK);
            self.drop_lookup_and_children(ancestor_stuck_lookup.id);
        }
    }

    /// Recursively find the oldest ancestor lookup of another lookup
    fn find_oldest_ancestor_lookup<'a>(
        &'a self,
        lookup: &'a SingleBlockLookup<T>,
    ) -> Result<&'a SingleBlockLookup<T>, String> {
        if let Some(awaiting_parent) = lookup.awaiting_parent() {
            if let Some(lookup) = self
                .single_block_lookups
                .values()
                .find(|l| l.block_root() == awaiting_parent)
            {
                self.find_oldest_ancestor_lookup(lookup)
            } else {
                Err(format!(
                    "Lookup references unknown parent {awaiting_parent:?}"
                ))
            }
        } else {
            Ok(lookup)
        }
    }

    /// Adds peers to a lookup and its ancestors recursively.
    /// Note: Takes a `lookup_id` as argument to allow recursion on mutable lookups, without having
    /// to duplicate the code to add peers to a lookup
    fn add_peers_to_lookup_and_ancestors(
        &mut self,
        lookup_id: SingleLookupId,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), String> {
        let lookup = self
            .single_block_lookups
            .get_mut(&lookup_id)
            .ok_or(format!("Unknown lookup for id {lookup_id}"))?;

        let mut added_some_peer = false;
        for peer in peers {
            if lookup.add_peer(*peer) {
                added_some_peer = true;
                debug!(self.log, "Adding peer to existing single block lookup";
                    "block_root" => ?lookup.block_root(),
                    "peer" => ?peer
                );
            }
        }

        if let Some(parent_root) = lookup.awaiting_parent() {
            if let Some((&child_id, _)) = self
                .single_block_lookups
                .iter()
                .find(|(_, l)| l.block_root() == parent_root)
            {
                self.add_peers_to_lookup_and_ancestors(child_id, peers, cx)
            } else {
                Err(format!("Lookup references unknown parent {parent_root:?}"))
            }
        } else if added_some_peer {
            // If this lookup is not awaiting a parent and we added at least one peer, attempt to
            // make progress. It is possible that a lookup is created with zero peers, attempted to
            // make progress, and then receives peers. After that time the lookup will never be
            // pruned with `drop_lookups_without_peers` because it has peers. This is rare corner
            // case, but it can result in stuck lookups.
            let result = lookup.continue_requests(cx);
            self.on_lookup_result(lookup_id, result, "add_peers", cx);
            Ok(())
        } else {
            Ok(())
        }
    }
}
