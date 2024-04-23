use self::single_block_lookup::{DownloadResult, LookupRequestError, SingleBlockLookup};
use super::manager::{BlockProcessType, BlockProcessingResult};
use super::network_context::LookupVerifyError;
use super::network_context::{RpcProcessingResult, SyncNetworkContext};
use crate::metrics;
use crate::sync::block_lookups::common::PARENT_DEPTH_TOLERANCE;
use crate::sync::manager::Id;
use crate::sync::network_context::LookupFailure;
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::data_availability_checker::{
    AvailabilityCheckErrorCategory, DataAvailabilityChecker,
};
use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
pub use common::RequestState;
use fnv::FnvHashMap;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
pub use single_block_lookup::{BlobRequestState, BlockRequestState};
use slog::{debug, error, trace, warn, Logger};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use types::{BlobSidecar, EthSpec, SignedBeaconBlock, Slot};

pub mod common;
mod single_block_lookup;
#[cfg(test)]
mod tests;

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 3;

pub enum BlockComponent<E: EthSpec> {
    Block(DownloadResult<Arc<SignedBeaconBlock<E>>>),
    Blob(DownloadResult<Arc<BlobSidecar<E>>>),
}

impl<E: EthSpec> BlockComponent<E> {
    fn parent_root(&self) -> Hash256 {
        match self {
            BlockComponent::Block(block) => block.0.parent_root(),
            BlockComponent::Blob(blob) => blob.0.block_parent_root(),
        }
    }
}

pub type SingleLookupId = u32;

enum Action {
    Retry,
    ParentUnknown { parent_root: Hash256, slot: Slot },
    Drop,
    Continue,
}

pub struct BlockLookups<T: BeaconChainTypes> {
    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    single_block_lookups: FnvHashMap<SingleLookupId, SingleBlockLookup<T>>,

    pub(crate) da_checker: Arc<DataAvailabilityChecker<T>>,

    /// The logger for the import manager.
    log: Logger,
}

impl<T: BeaconChainTypes> BlockLookups<T> {
    pub fn new(da_checker: Arc<DataAvailabilityChecker<T>>, log: Logger) -> Self {
        Self {
            failed_chains: LRUTimeCache::new(Duration::from_secs(
                FAILED_CHAINS_CACHE_EXPIRY_SECONDS,
            )),
            single_block_lookups: Default::default(),
            da_checker,
            log,
        }
    }

    #[cfg(test)]
    pub(crate) fn active_single_lookups(&self) -> Vec<(Id, Hash256, Option<Hash256>)> {
        self.single_block_lookups
            .iter()
            .map(|(id, e)| (*id, e.block_root(), e.parent_root()))
            .collect()
    }

    /// Returns a vec of all parent lookup chains by tip, in descending slot order (tip first)
    pub(crate) fn active_parent_lookups(&self) -> Vec<Vec<Hash256>> {
        let mut child_to_parent = HashMap::new();
        let mut parent_to_child = HashMap::<Hash256, Vec<Hash256>>::new();
        for lookup in self.single_block_lookups.values() {
            let block_root = lookup.block_root();
            let parent_root = lookup.parent_root();
            child_to_parent.insert(block_root, parent_root);
            if let Some(parent_root) = parent_root {
                parent_to_child
                    .entry(parent_root)
                    .or_default()
                    .push(block_root);
            }
        }

        let mut parent_chains = vec![];

        // Iterate blocks which no child
        for lookup in self.single_block_lookups.values() {
            let mut block_root = lookup.block_root();
            if parent_to_child.get(&block_root).is_none() {
                let mut chain = vec![];

                // Resolve chain of blocks
                loop {
                    if let Some(parent_root) = child_to_parent.get(&block_root) {
                        // block_root is a known block that may or may not have a parent root
                        chain.push(block_root);
                        if let Some(parent_root) = parent_root {
                            block_root = *parent_root;
                            continue;
                        }
                    }
                    break;
                }

                if chain.len() > 1 {
                    parent_chains.push(chain);
                }
            }
        }

        parent_chains
    }

    #[cfg(test)]
    pub(crate) fn failed_chains_contains(&mut self, chain_hash: &Hash256) -> bool {
        self.failed_chains.contains(chain_hash)
    }

    /* Lookup requests */

    /// Creates a lookup for the block with the given `block_root` and immediately triggers it.
    pub fn search_block(
        &mut self,
        block_root: Hash256,
        block_component: Option<(PeerId, BlockComponent<T::EthSpec>)>,
        peer_source: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.new_current_lookup(block_root, block_component, peer_source, cx)
    }

    /// A block or blob triggers the search of a parent.
    /// Check if this new lookup extends a bad chain:
    /// - `block_root_to_search` is a failed chain
    /// - Extending `child_block_root_trigger` would exceed the max depth
    pub fn search_parent_of_child(
        &mut self,
        block_root_to_search: Hash256,
        child_block_root_trigger: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        for parent_chain in self.active_parent_lookups() {
            if parent_chain.last() == Some(&child_block_root_trigger)
                && parent_chain.len() >= PARENT_DEPTH_TOLERANCE
            {
                debug!(self.log, "Parent lookup chain too long"; "block_root" => ?block_root_to_search);

                // Searching for this parent would extend a parent chain over the max
                // Insert the tip only to failed chains
                let chain_hash = parent_chain.first().expect("has at least one element");
                self.failed_chains.insert(*chain_hash);

                // Drop all lookups descending from the child of the too long parent chain
                if let Some((lookup_id, lookup)) = self
                    .single_block_lookups
                    .iter()
                    .find(|(_, l)| l.block_root() == child_block_root_trigger)
                {
                    for &peer_id in lookup.all_used_peers() {
                        cx.report_peer(peer_id, PeerAction::LowToleranceError, "chain_too_long");
                    }

                    self.drop_lookup_and_childs(*lookup_id);
                }

                return;
            }
        }

        // TODO: implement parent chain checks
        self.new_current_lookup(block_root_to_search, None, peers, cx)
    }

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    fn new_current_lookup(
        &mut self,
        block_root: Hash256,
        block_component: Option<(PeerId, BlockComponent<T::EthSpec>)>,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&block_root) {
            debug!(self.log, "Block is from a past failed chain. Dropping"; "block_root" => ?block_root);
            return;
        }

        // TODO: Should check if parent root is a failed chain too?
        if let Some(parent_root) = block_component.as_ref().map(|(_, b)| b.parent_root()) {
            if self.failed_chains.contains(&parent_root) {
                debug!(self.log, "Parent of block is from a past failed chain. Dropping"; "parent_root" => ?parent_root, "block_root" => ?block_root);
                return;
            }
        }

        // Do not re-request a block that is already being requested
        if let Some((_, lookup)) = self
            .single_block_lookups
            .iter_mut()
            .find(|(_id, lookup)| lookup.is_for_block(block_root))
        {
            trace!(self.log, "Adding peer to existing single block lookup"; "block_root" => %block_root);
            lookup.add_peers(peers);
            if let Some((peer_id, block_component)) = block_component {
                lookup.add_child_components(peer_id, block_component);
            }
            return;
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

        let mut lookup =
            SingleBlockLookup::new(block_root, peers, self.da_checker.clone(), cx.next_id());

        // Add block components to the new request
        if let Some((peer_id, block_component)) = block_component {
            lookup.add_child_components(peer_id, block_component);
        }

        let block_root = lookup.block_root();
        match lookup.continue_requests(cx) {
            Ok(()) => {
                self.single_block_lookups.insert(lookup.id, lookup);
                self.update_metrics();

                metrics::set_gauge(
                    &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
                    self.single_block_lookups.len() as i64,
                );
            }
            Err(e) => {
                debug!(self.log, "Single block lookup failed";
                    "error" => ?e,
                    "block_root" => ?block_root,
                );
            }
        }
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
        // Downscore peer even if lookup is not known
        // Only downscore lookup verify errors. RPC errors are downscored in the network handler.
        if let Err(LookupFailure::LookupVerifyError(e)) = &response {
            // Note: the error is displayed in full debug form on the match below
            cx.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
        }

        let response_type = R::response_type();
        let Some(mut lookup) = self.single_block_lookups.get_mut(&id) else {
            // We don't have the ability to cancel in-flight RPC requests. So this can happen
            // if we started this RPC request, and later saw the block/blobs via gossip.
            debug!(self.log, "Block returned for single block lookup not present"; "id" => id);
            return;
        };

        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup);

        let result = match response {
            Ok((response, seen_timestamp)) => {
                debug!(self.log,
                    "Block lookup download success";
                    "block_root" => %block_root,
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type,
                );

                if let Err(e) = request_state.get_state_mut().on_download_success((
                    response,
                    block_root,
                    seen_timestamp,
                )) {
                    Err(e)
                } else {
                    // TOOD: May choose to delay blobs for sending if we know that their parent is unknown.
                    // However, da_checker does not ever error with unknown parent. Plus we should not request
                    // blobs for blocks that are not rooted on a valid chain, as an attacker can trigger us into
                    // fetching garbage.

                    request_state.continue_request(id, cx)
                }
            }
            Err(e) => {
                debug!(self.log,
                    "Block lookup download failure";
                    "block_root" => %block_root,
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type,
                    "error" => %e,
                );

                if let Err(e) = request_state.get_state_mut().on_download_failure() {
                    Err(e)
                } else {
                    request_state.continue_request(id, cx)
                }
            }
        };

        if let Err(e) = result {
            debug!(self.log, "Dropping single lookup"; "id" => id, "err" => ?e);
            self.drop_lookup_and_childs(id);
            self.update_metrics();
        }
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId, cx: &mut SyncNetworkContext<T>) {
        /* Check disconnection for single lookups */
        self.single_block_lookups.retain(|_, req| {
            let should_drop_lookup =
                req.should_drop_lookup_on_disconnected_peer(peer_id, cx, &self.log);

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
        if let Err(e) = match process_type {
            BlockProcessType::SingleBlock { id } => {
                self.on_processing_result_inner::<BlockRequestState<T::EthSpec>>(id, result, cx)
            }
            BlockProcessType::SingleBlob { id } => {
                self.on_processing_result_inner::<BlobRequestState<T::EthSpec>>(id, result, cx)
            }
        } {
            let id = match process_type {
                BlockProcessType::SingleBlock { id } | BlockProcessType::SingleBlob { id } => id,
            };
            debug!(self.log, "Dropping lookup on request error"; "id" => id, "error" => ?e);
            self.drop_lookup_and_childs(id);
        }
    }

    pub fn on_processing_result_inner<R: RequestState<T>>(
        &mut self,
        lookup_id: SingleLookupId,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        let Some(mut lookup) = self.single_block_lookups.get_mut(&lookup_id) else {
            debug!(self.log, "Unknown single block lookup"; "target_id" => lookup_id);
            return Ok(());
        };

        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup).get_state_mut();

        debug!(
            self.log,
            "Block component processed for lookup";
            "response_type" => ?R::response_type(),
            "block_root" => ?block_root,
            "result" => ?result,
            "id" => lookup_id,
        );

        let action = match result {
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockProcessingResult::Err(BlockError::BlockIsAlreadyKnown(_)) => {
                // Successfully imported
                // TODO: Potentially import child blocks
                trace!(self.log, "Single block processing succeeded"; "block" => %block_root);
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
                    if let Ok(blob_peer) = lookup.blob_request_state.state.on_processing_failure() {
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
                    "Single block processing was ignored, cpu might be overloaded";
                    "action" => "dropping single block request"
                );
                Action::Drop
            }
            BlockProcessingResult::Err(e) => {
                trace!(self.log, "Single block processing failed"; "block_root" => %block_root, "error" => %e);
                match e {
                    BlockError::BeaconChainError(e) => {
                        // Internal error
                        error!(self.log, "Beacon chain error processing single block"; "block_root" => %block_root, "error" => ?e);
                        Action::Drop
                    }
                    BlockError::ParentUnknown(block) => {
                        let slot = block.slot();
                        let parent_root = block.parent_root();

                        // Reverts the status of this request to `AwaitingProcessing` holding the
                        // downloaded data. A future call to `continue_requests` will re-submit it
                        // once there are no pending parent requests.
                        // Note: `BlockError::ParentUnknown` is only returned when processing
                        // blocks, not blobs.
                        request_state.into_awaiting_processing()?;
                        Action::ParentUnknown { parent_root, slot }
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
                        // TODO: This lines represent an improper transition of download states,
                        // which can log errors in the future. If an error here causes the request
                        // to transition into a bad state, a future network message will cause
                        // the request to be dropped
                        //
                        // lookup.block_request_state.state.on_download_failure();
                        // lookup.blob_request_state.state.on_download_failure();
                        Action::Drop
                    }
                    other => {
                        warn!(self.log, "Invalid block in single block lookup"; "block_root" => %block_root, "error" => ?other);
                        let peer_id = request_state.on_processing_failure()?;
                        // TODO: Why is the original code downscoring the block peer regardless of
                        // type of request? Sending a blob for verification can result in an error
                        // attributable to the block peer?
                        cx.report_peer(
                            peer_id,
                            PeerAction::MidToleranceError,
                            "single_block_failure",
                        );

                        Action::Retry
                    }
                }
            }
        };

        match action {
            Action::Retry => {
                // Trigger download
                lookup.continue_requests(cx)?;
            }
            Action::ParentUnknown {
                parent_root,
                slot: _,
            } => {
                let peers = lookup.all_available_peers().cloned().collect::<Vec<_>>();
                self.search_parent_of_child(parent_root, block_root, &peers, cx);
            }
            Action::Drop => {
                // Drop with noop
                self.drop_lookup_and_childs(lookup_id);
                self.update_metrics();
            }
            Action::Continue => {
                // Block imported, continue the requests of pending child blocks
                self.continue_child_lookups(block_root, cx);
            }
        }
        Ok(())
    }

    pub fn continue_child_lookups(&mut self, block_root: Hash256, cx: &mut SyncNetworkContext<T>) {
        let mut failed_lookups = vec![];
        for (id, lookup) in self.single_block_lookups.iter_mut() {
            if lookup.parent_root() == Some(block_root) {
                // Continue lookup
                debug!(self.log, "Continuing child lookup"; "block_root" => %lookup.block_root());
                if let Err(e) = lookup.continue_requests(cx) {
                    debug!(self.log, "Error continuing lookup"; "id" => id, "error" => ?e);
                    failed_lookups.push(*id);
                }
            }
        }

        for id in failed_lookups {
            self.drop_lookup_and_childs(id);
        }
    }

    pub fn drop_lookup_and_childs(&mut self, dropped_id: SingleLookupId) {
        if let Some(dropped_lookup) = self.single_block_lookups.remove(&dropped_id) {
            debug!(self.log, "Dropping child lookup"; "id" => ?dropped_id, "block_root" => %dropped_lookup.block_root());

            let child_lookup_ids = self
                .single_block_lookups
                .iter()
                .filter_map(|(id, lookup)| {
                    if lookup.parent_root() == Some(dropped_lookup.block_root()) {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            for id in child_lookup_ids {
                self.drop_lookup_and_childs(id);
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
