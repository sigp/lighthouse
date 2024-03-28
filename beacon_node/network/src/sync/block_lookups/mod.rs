use self::single_block_lookup::SingleBlockLookup;
use super::manager::BlockProcessingResult;
use super::network_context::SyncNetworkContext;
use crate::metrics;

pub use crate::sync::block_lookups::single_block_lookup::LookupRequestError;
use crate::sync::manager::{Id, SingleLookupReqId};
use beacon_chain::block_verification_types::AsBlock;

use beacon_chain::data_availability_checker::{
    AvailabilityCheckErrorCategory, DataAvailabilityChecker,
};

use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
pub use common::RequestState;
use ethereum_types::H256;
use fnv::FnvHashMap;
use lighthouse_network::rpc::RPCError;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
pub use single_block_lookup::{BlobRequestState, BlockRequestState};
use slog::{debug, error, trace, warn, Logger};
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;

pub mod common;
mod single_block_lookup;
#[cfg(test)]
mod tests;

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 5;

pub struct BlockLookups<T: BeaconChainTypes> {
    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    single_block_lookups: FnvHashMap<Id, SingleBlockLookup<T>>,

    pub(crate) da_checker: Arc<DataAvailabilityChecker<T>>,

    /// The logger for the import manager.
    log: Logger,
}

enum Action {
    Retry,
    ParentUnknown { parent_root: H256 },
    Imported,
    Drop,
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

    /* Lookup requests */

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    pub fn search_block(
        &mut self,
        block_root: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<Id> {
        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&block_root) {
            debug!(self.log, "Block is from a past failed chain. Dropping";
                "block_root" => ?block_root);
            return None;
        }

        // Do not re-request a block that is already being requested
        if let Some((_, lookup)) = self
            .single_block_lookups
            .iter_mut()
            .find(|(_id, lookup)| lookup.is_for_block(block_root))
        {
            lookup.add_peers(peers);
            return Some(lookup.id);
        }

        let mut lookup =
            SingleBlockLookup::new(block_root, peers, self.da_checker.clone(), cx.next_id());
        let lookup_id = lookup.id;

        debug!(
            self.log,
            "Searching for block components";
            "peer_ids" => ?peers,
            "block" => ?block_root,
        );

        // Attempts to trigger the request matching the given `block_root`.
        match lookup.request_block_and_blobs(cx) {
            Ok(()) => {
                self.single_block_lookups.insert(lookup.id, lookup);

                metrics::set_gauge(
                    &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
                    self.single_block_lookups.len() as i64,
                );
            }
            // `request_block_and_blobs` can only fail if (1) too many failed attempts: won't happen
            // since this is the first attempt (2) no peers: won't happen since we just added a peer
            // (3) send to the network fails: its an unbounded channel so when can it happen (TODO)?
            Err(e) => {
                debug!(self.log, "Single block lookup failed";
                    "error" => ?e,
                    "block_root" => ?block_root,
                );
            }
        }

        Some(lookup_id)
    }

    pub fn search_block_from_unknown_parent(
        &mut self,
        parent_root: Hash256,
        _block_root: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<Id> {
        // TODO: Check that all existing searches don't exceed:
        // - Max of 4 tips for unknown block root
        // - Max length of each unknown block root chain

        self.search_block(parent_root, peers, cx)
    }

    /* Lookup responses */

    /// Process a block or blob response received from a single lookup request.
    pub fn single_lookup_response<R: RequestState<T>>(
        &mut self,
        lookup_id: SingleLookupReqId,
        peer_id: PeerId,
        response: Result<Option<R::ResponseType>, RPCError>,
        seen_timestamp: Duration,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let id = lookup_id.id;
        let response_type = R::response_type();

        // Get a single block lookup by its ID. This method additionally ensures the `req_counter`
        // matches the current `req_counter` for the lookup. This ensures any stale responses from requests
        // that have been retried are ignored.
        let lookup = self
            .single_block_lookups
            .get_mut(&lookup_id.id)
            .and_then(|lookup| {
                R::request_state_mut(lookup)
                    .get_state()
                    .is_current_req_counter(lookup_id.req_counter)
                    .then_some(lookup)
            });

        let Some(mut lookup) = lookup else {
            if let Ok(response) = response {
                if response.is_some() {
                    // We don't have the ability to cancel in-flight RPC requests. So this can happen
                    // if we started this RPC request, and later saw the block/blobs via gossip.
                    debug!(
                        self.log,
                        "Block returned for single block lookup not present";
                            "response_type" => ?response_type,
                    );
                }
            }
            return;
        };

        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup);

        let action = match response {
            Ok(response) => {
                match request_state.verify_response(block_root, response, seen_timestamp) {
                    Ok(Some(verified_response)) => {
                        // Now that the block is verified, check if the parent_root in a failed chain
                        // If so, register failure downloading, downscore peer and drop the request
                        // Add the new block root to the failed chains cache
                        let failed_parent_root = R::get_parent_root(&verified_response)
                            .filter(|parent_root| self.failed_chains.contains(&parent_root));

                        if let Some(parent_root) = failed_parent_root {
                            request_state.register_failure_downloading();

                            debug!(
                                self.log,
                                "Lookup ignored due to past failure";
                                "block" => %block_root,
                                "parent_root" => %parent_root,
                            );

                            self.failed_chains.insert(block_root);
                            cx.report_peer(peer_id, PeerAction::MidToleranceError, "failed_chains");

                            Action::Drop
                        } else {
                            // Check if this block is part of chain of blocks that become too long

                            if let Err(e) = R::send_for_processing(
                                id,
                                block_root,
                                verified_response,
                                seen_timestamp,
                                cx,
                            ) {
                                debug!(self.log,
                                    "Single lookup request failed";
                                    "error" => ?e,
                                    "block_root" => ?block_root,
                                );
                                Action::Drop
                            } else {
                                Action::Retry
                            }
                        }
                    }
                    // Downloaded contents are valid, but are not complete to send to the processor.
                    // Wait for the rest of requests to complete, and do nothing now.
                    Ok(None) => return,
                    Err(e) => {
                        debug!(
                            self.log,
                            "Single lookup response verification failed, retrying";
                            "block_root" => ?block_root,
                            "peer_id" => %peer_id,
                            "response_type" => ?response_type,
                            "error" => ?e
                        );
                        cx.report_peer(peer_id, PeerAction::LowToleranceError, e.into());

                        request_state.register_failure_downloading();
                        Action::Retry
                    }
                }
            }
            Err(error) => {
                trace!(self.log,
                    "Single lookup failed";
                    "block_root" => ?block_root,
                    "error" => error.as_static_str(),
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type
                );

                request_state.register_failure_downloading();
                Action::Retry
            }
        };

        match action {
            Action::Retry => {
                if let Err(e) = lookup.request_block_and_blobs(cx) {
                    debug!(self.log, "Single lookup retry failed"; "block_root" => ?block_root, "error" => ?e);
                    self.single_block_lookups.remove(&id);
                }
            }
            Action::Drop => {
                self.single_block_lookups.remove(&id);

                metrics::set_gauge(
                    &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
                    self.single_block_lookups.len() as i64,
                );
            }
            Action::Imported => unreachable!(),
            Action::ParentUnknown { .. } => unreachable!(),
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
    }

    /* Processing responses */

    pub fn single_block_component_processed<R: RequestState<T>>(
        &mut self,
        target_id: Id,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(mut lookup) = self.single_block_lookups.get_mut(&target_id) else {
            return;
        };

        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup);

        let Ok(peer_id) = request_state.get_state().processing_peer() else {
            return;
        };
        debug!(
            self.log,
            "Block component processed for lookup";
            "response_type" => ?R::response_type(),
            "block_root" => ?block_root,
        );

        let action = match result {
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockProcessingResult::Err(BlockError::BlockIsAlreadyKnown { .. }) => {
                // Successfully imported
                trace!(self.log, "Single block processing succeeded"; "block" => %block_root);
                Action::Imported
            }

            BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                _,
                _block_root,
            )) => {
                // Handles a `MissingComponents` block processing error. Handles peer scoring and retries.
                //
                // If this was the result of a block request, we can't determined if the block peer did anything
                // wrong. If we already had both a block and blobs response processed, we should penalize the
                // blobs peer because they did not provide all blobs on the initial request.

                let request_state = R::request_state_mut(&mut lookup);

                request_state.get_state_mut().on_component_processed();
                if lookup.both_components_processed() {
                    lookup.penalize_blob_peer(cx);

                    // Try it again if possible.
                    lookup.blob_request_state.state.on_processing_failure();
                    Action::Retry
                } else {
                    Action::Drop
                }
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
                // Handles peer scoring and retries related to a `BlockError` in response to a single block
                // or blob lookup processing result.
                trace!(self.log, "Single block processing failed"; "block_root" => %block_root, "error" => %e);
                match e {
                    BlockError::BlockIsAlreadyKnown => {
                        // No error here
                        Action::Drop
                    }
                    BlockError::BeaconChainError(e) => {
                        // Internal error
                        error!(self.log, "Beacon chain error processing single block"; "block_root" => %block_root, "error" => ?e);
                        Action::Drop
                    }
                    // Note: blob import will never trigger a ParentUnknown error. Blobs with
                    // unknown parent are just happily imported and stored in the availability cache
                    BlockError::ParentUnknown(block) => {
                        // Cache block on request's state for latter re-processing
                        request_state.get_state_mut().on_unknown_parent();

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
                    BlockError::AvailabilityCheck(e) => match e.category() {
                        AvailabilityCheckErrorCategory::Internal => {
                            warn!(self.log, "Internal availability check failure"; "block_root" => %block_root, "peer_id" => %peer_id, "error" => ?e);
                            lookup.block_request_state.state.on_download_failure();
                            lookup.blob_request_state.state.on_download_failure();
                            // Next step: Retry download with different peer
                            Action::Retry
                        }
                        AvailabilityCheckErrorCategory::Malicious => {
                            warn!(self.log, "Availability check failure"; "block_root" => %block_root, "peer_id" => %peer_id, "error" => ?e);
                            lookup.handle_availability_check_failure(cx);
                            // Next step: Retry download with different peer
                            Action::Retry
                        }
                    },
                    other => {
                        warn!(self.log, "Peer sent invalid block in single block lookup"; "block_root" => %block_root, "error" => ?other, "peer_id" => %peer_id);
                        if let Ok(block_peer) = lookup.block_request_state.state.processing_peer() {
                            cx.report_peer(
                                block_peer,
                                PeerAction::MidToleranceError,
                                "single_block_failure",
                            );

                            // Try it again if possible.
                            lookup.block_request_state.state.on_processing_failure();
                            // Next step: Retry download with different peer
                            Action::Retry
                        } else {
                            // Next step: Retry download with different peer
                            Action::Retry
                        }
                    }
                }
            }
        };

        match action {
            Action::Imported => {
                let block_root = lookup.block_root();
                self.single_block_lookups.remove(&target_id);

                // TODO: Trigger download of pending children that have unknown parent
                for child_lookup in self.single_block_lookups.values_mut() {
                    if let Some(parent_root) = child_lookup.parent_root() {
                        if parent_root == block_root {
                            if let Err(e) = child_lookup.process_block_and_blobs(cx) {
                                warn!(self.log, "Error sending child lookup for processing"; "block_root" => %child_lookup.block_root(), "error" => ?e);
                            }
                        }
                    }
                }
            }
            Action::Retry => {
                if let Err(e) = lookup.request_block_and_blobs(cx) {
                    warn!(self.log, "Single block lookup failed"; "block_root" => %block_root, "error" => ?e);
                    self.single_block_lookups.remove(&target_id);
                }
            }
            Action::ParentUnknown { parent_root } => {
                // Note: Include all peers from the lookup, claiming to know this block, not
                // just the one that sent this specific block
                let all_peers = &lookup.all_peers();
                self.search_block_from_unknown_parent(parent_root, block_root, &all_peers, cx);
            }
            Action::Drop => {
                self.single_block_lookups.remove(&target_id);

                metrics::set_gauge(
                    &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
                    self.single_block_lookups.len() as i64,
                );
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
}
