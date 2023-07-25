use self::parent_lookup::ParentVerifyError;
use self::single_block_lookup::SingleBlockLookup;
use super::manager::BlockProcessingResult;
use super::BatchProcessResult;
use super::{manager::BlockProcessType, network_context::SyncNetworkContext};
use crate::metrics;
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::block_lookups::single_block_lookup::LookupId;
use beacon_chain::block_verification_types::{AsBlock, RpcBlock};
use beacon_chain::data_availability_checker::{AvailabilityCheckError, DataAvailabilityChecker};
use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
use fnv::FnvHashMap;
use lighthouse_network::rpc::RPCError;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
pub use single_block_lookup::UnknownParentComponents;
pub use single_block_lookup::{
    BlobRequestState, BlockRequestState, Current, Lookup, Parent, RequestState,
};
use slog::{debug, error, trace, warn, Logger};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use store::{Hash256, SignedBeaconBlock};
use strum::Display;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{BlobSidecar, EthSpec, Slot};

pub(crate) mod delayed_lookup;
mod parent_lookup;
mod single_block_lookup;
#[cfg(test)]
mod tests;

pub type DownloadedBlocks<T> = (Hash256, RpcBlock<T>);
pub type RootBlockTuple<T> = (Hash256, Arc<SignedBeaconBlock<T>>);
pub type RootBlobsTuple<T> = (Hash256, FixedBlobSidecarList<T>);

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 3;

pub struct BlockLookups<T: BeaconChainTypes> {
    /// Parent chain lookups being downloaded.
    parent_lookups: SmallVec<[ParentLookup<T>; 3]>,

    processing_parent_lookups: HashMap<Hash256, (Vec<Hash256>, SingleBlockLookup<Parent, T>)>,

    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    single_block_lookups: FnvHashMap<Id, SingleBlockLookup<Current, T>>,

    da_checker: Arc<DataAvailabilityChecker<T>>,

    /// The logger for the import manager.
    log: Logger,
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
        cx: &SyncNetworkContext<T>,
    ) {
        let lookup = self.new_current_lookup(block_root, None, &[peer_source], cx);
        if let Some(lookup) = lookup {
            self.trigger_single_lookup(lookup, cx);
        }
    }
    /// Creates a lookup for the block with the given `block_root`.
    ///
    /// The request is not immediately triggered, and should be triggered by a call to
    /// `trigger_lookup_by_root`.
    pub fn search_block_delayed(
        &mut self,
        block_root: Hash256,
        peer_source: PeerShouldHave,
        cx: &SyncNetworkContext<T>,
    ) {
        let lookup = self.new_current_lookup(block_root, None, &[peer_source], cx);
        if let Some(lookup) = lookup {
            self.add_single_lookup(lookup)
        }
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
        parent_components: Option<UnknownParentComponents<T::EthSpec>>,
        peer_source: &[PeerShouldHave],
        cx: &SyncNetworkContext<T>,
    ) {
        let lookup = self.new_current_lookup(block_root, parent_components, peer_source, cx);
        if let Some(lookup) = lookup {
            self.trigger_single_lookup(lookup, cx);
        }
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
        parent_components: Option<UnknownParentComponents<T::EthSpec>>,
        peer_source: &[PeerShouldHave],
        cx: &SyncNetworkContext<T>,
    ) {
        let lookup = self.new_current_lookup(block_root, parent_components, peer_source, cx);
        if let Some(lookup) = lookup {
            self.add_single_lookup(lookup)
        }
    }

    /// Attempts to trigger the request matching the given `block_root`.
    pub fn trigger_single_lookup(
        &mut self,
        mut single_block_lookup: SingleBlockLookup<Current, T>,
        cx: &SyncNetworkContext<T>,
    ) {
        if !single_block_lookup.triggered && single_block_lookup.request_block_and_blobs(cx).is_ok()
        {
            single_block_lookup.triggered = true;
            self.add_single_lookup(single_block_lookup)
        }
    }

    pub fn add_single_lookup(&mut self, single_block_lookup: SingleBlockLookup<Current, T>) {
        self.single_block_lookups
            .insert(single_block_lookup.id, single_block_lookup);

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    pub fn trigger_lookup_by_root(
        &mut self,
        block_root: Hash256,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), ()> {
        for (_, lookup) in self.single_block_lookups.iter_mut() {
            if lookup.block_request_state.requested_block_root == block_root && !lookup.triggered {
                if lookup.request_block_and_blobs(cx).is_ok() {
                    lookup.triggered = true;
                }
            }
        }
        Ok(())
    }

    pub fn remove_lookup_by_root(&mut self, block_root: Hash256) {
        self.single_block_lookups
            .retain(|_id, lookup| lookup.block_request_state.requested_block_root != block_root);
    }

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    pub fn new_current_lookup(
        &mut self,
        block_root: Hash256,
        parent_components: Option<UnknownParentComponents<T::EthSpec>>,
        peers: &[PeerShouldHave],
        cx: &SyncNetworkContext<T>,
    ) -> Option<SingleBlockLookup<Current, T>> {
        // Do not re-request a block that is already being requested
        if let Some((_, lookup)) = self
            .single_block_lookups
            .iter_mut()
            .find(|(id, lookup)| lookup.is_for_block(block_root))
        {
            lookup.add_peers(peers);
            if let Some(components) = parent_components {
                lookup.add_unknown_parent_components(components);
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

        Some(SingleBlockLookup::new(
            block_root,
            parent_components,
            peers,
            self.da_checker.clone(),
            cx,
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
        cx: &SyncNetworkContext<T>,
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
        let mut parent_lookup = ParentLookup::new(
            block_root,
            parent_root,
            peer_source,
            self.da_checker.clone(),
            cx,
        );
        if let Ok(()) = parent_lookup
            .current_parent_request
            .request_block_and_blobs(cx)
        {
            self.parent_lookups.push(parent_lookup);
        }
    }

    /* Lookup responses */

    pub fn single_lookup_response<R: RequestState<Current, T>>(
        &mut self,
        id: Id,
        peer_id: PeerId,
        response: Option<R::ResponseType>,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
    ) {
        let is_stream_terminator = response.is_none();
        let response_type = R::response_type();
        let log = self.log.clone();

        let Some(lookup) = self.single_block_lookups.get_mut(&id) else {
            if !is_stream_terminator {
                warn!(
                    self.log,
                    "Block returned for single block lookup not present";
                        "response_type" => ?response_type,
                );
            }
            return;
        };

        let expected_block_root = lookup.block_request_state.requested_block_root;

        let has_pending_parent_request = self
            .parent_lookups
            .iter()
            .any(|parent_lookup| parent_lookup.chain_hash() == expected_block_root);

        let request_state = R::request_state_mut(lookup);

        match request_state.verify_response(expected_block_root, response) {
            Ok(Some((root, verified_response))) => {
                if let Some(parent_components) = lookup.unknown_parent_components.as_mut() {
                    R::add_to_parent_components(verified_response, parent_components);

                    if !has_pending_parent_request {
                        if let Some(rpc_block) = lookup.get_downloaded_block() {
                            if let Err(()) = self.send_block_for_processing(
                                expected_block_root,
                                rpc_block,
                                seen_timestamp,
                                BlockProcessType::SingleBlock { id },
                                cx,
                            ) {
                                self.single_block_lookups.remove(&id);
                            }
                        }
                    }
                } else {
                    if let Err(()) = R::send_for_processing(
                        id,
                        self,
                        root,
                        R::verified_to_reconstructed(verified_response),
                        seen_timestamp,
                        &cx,
                    ) {
                        self.single_block_lookups.remove(&id);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                let msg = if matches!(e, LookupVerifyError::BenignFailure) {
                    request_state
                        .get_state_mut()
                        .remove_peer_if_useless(&peer_id);
                    "peer could not response to request"
                } else {
                    let msg = e.into();
                    cx.report_peer(peer_id, PeerAction::LowToleranceError, msg);
                    msg
                };

                debug!(log, "Single block lookup failed";
                    "peer_id" => %peer_id,
                    "error" => msg,
                    "block_root" => ?expected_block_root,
                    "response_type" => ?response_type
                );
                if let Err(()) = request_state.retry_request_after_failure(id, cx, &log) {
                    self.single_block_lookups.remove(&id);
                }
            }
        }

        //TODO(sean) move metric to trait to differentiate block and blob
        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /// Process a response received from a parent lookup request.
    pub fn parent_lookup_response<R: RequestState<Parent, T>>(
        &mut self,
        id: Id,
        peer_id: PeerId,
        block: Option<R::ResponseType>,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
    ) {
        let mut parent_lookup = if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.current_parent_request.id == id)
        {
            self.parent_lookups.remove(pos)
        } else {
            if block.is_some() {
                debug!(self.log, "Response for a parent lookup request that was not found"; "peer_id" => %peer_id);
            }
            return;
        };

        match parent_lookup.verify_block::<R>(block, &mut self.failed_chains) {
            Ok(Some((block_root, verified_response))) => {
                if let Some(parent_components) = parent_lookup
                    .current_parent_request
                    .unknown_parent_components
                    .as_mut()
                {
                    R::add_to_parent_components(verified_response, parent_components);
                }
                if let Some(rpc_block) = parent_lookup.current_parent_request.get_downloaded_block()
                {
                    let chain_hash = parent_lookup.chain_hash();
                    if self
                        .send_block_for_processing(
                            block_root,
                            rpc_block,
                            seen_timestamp,
                            BlockProcessType::ParentLookup { chain_hash },
                            cx,
                        )
                        .is_ok()
                    {
                        self.parent_lookups.push(parent_lookup)
                    }
                } else {
                    //TODO(sean) here, we could penalize a peer who previously sent us a blob list
                    // that was incomplete, and trigger a re-request immediately
                    self.parent_lookups.push(parent_lookup)
                }
            }
            Ok(None) => {
                // Request finished successfully, nothing else to do. It will be removed after the
                // processing result arrives.
                self.parent_lookups.push(parent_lookup);
            }
            Err(e) => self.handle_parent_verify_error::<R>(peer_id, parent_lookup, e, cx),
        };

        //TODO(sean) move metric to trait to differentiate block and blob
        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    fn handle_parent_verify_error<R: RequestState<Parent, T>>(
        &mut self,
        peer_id: PeerId,
        mut parent_lookup: ParentLookup<T>,
        e: ParentVerifyError,
        cx: &SyncNetworkContext<T>,
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
                self.request_parent(parent_lookup, cx)
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
                let request_state = R::request_state_mut(&mut parent_lookup.current_parent_request);
                request_state.remove_if_useless(&peer_id);
                self.request_parent(parent_lookup, cx)
            }
        }
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId, cx: &mut SyncNetworkContext<T>) {
        /* Check disconnection for single lookups */
        self.single_block_lookups.retain(|id, req| {
            let should_remove_lookup =
                req.should_remove_disconnected_peer(*id, peer_id, cx, &self.log);

            !should_remove_lookup
        });

        /* Check disconnection for parent lookups */
        while let Some(pos) = self.parent_lookups.iter_mut().position(|req| {
            req.check_block_peer_disconnected(peer_id).is_err()
                || req.check_blob_peer_disconnected(peer_id).is_err()
        }) {
            let parent_lookup = self.parent_lookups.remove(pos);
            trace!(self.log, "Parent lookup's peer disconnected"; &parent_lookup);
            self.request_parent(parent_lookup, cx);
        }
    }

    /// An RPC error has occurred during a parent lookup. This function handles this case.
    pub fn parent_lookup_failed<R: RequestState<Parent, T>>(
        &mut self,
        id: Id,
        peer_id: PeerId,
        cx: &SyncNetworkContext<T>,
        error: RPCError,
    ) {
        let msg = error.as_static_str();
        if let Some(pos) = self
            .parent_lookups
            .iter()
            .position(|request| request.current_parent_request.id == id)
        {
            let mut parent_lookup = self.parent_lookups.remove(pos);
            R::request_state_mut(&mut parent_lookup.current_parent_request)
                .register_failure_downloading();
            trace!(self.log, "Parent lookup block request failed"; &parent_lookup, "error" => msg);

            self.request_parent(parent_lookup, cx);
        } else {
            return debug!(self.log, "RPC failure for a block parent lookup request that was not found"; "peer_id" => %peer_id, "error" => msg);
        };

        metrics::set_gauge(
            &metrics::SYNC_PARENT_BLOCK_LOOKUPS,
            self.parent_lookups.len() as i64,
        );
    }

    pub fn single_block_lookup_failed<R: RequestState<Current, T>>(
        &mut self,
        id: Id,
        peer_id: &PeerId,
        cx: &SyncNetworkContext<T>,
        error: RPCError,
    ) {
        let msg = error.as_static_str();
        let Some(lookup) = self.single_block_lookups.get_mut(&id) else {
            debug!(self.log, "Error response to dropped lookup"; "error" => ?error);
            return;
        };
        let root = lookup.block_request_state.requested_block_root;
        let request_state = R::request_state_mut(lookup);
        request_state.register_failure_downloading();
        let response_type = R::response_type();
        trace!(self.log, "Single lookup failed"; "block_root" => ?root, "error" => msg, "response_type" => ?response_type);
        if let Err(()) = request_state.retry_request_after_failure(id, cx, &self.log) {
            self.single_block_lookups.remove(&id);
        };

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
        cx: &SyncNetworkContext<T>,
    ) {
        let Some(request_ref) = self.single_block_lookups.get_mut(&target_id) else {
           debug!(self.log, "Block component processed for single block lookup not present"    );
           return;
       };

        let root = request_ref.block_request_state.requested_block_root;
        let request_state = R::request_state_mut(request_ref);
        let peer_id = request_state.get_state().processing_peer();
        request_state.get_state_mut().component_processed = true;

        let peer_id = match peer_id {
            Ok(peer) => peer,
            Err(_) => return,
        };

        match result {
            BlockProcessingResult::Ok(status) => match status {
                AvailabilityProcessingStatus::Imported(root) => {
                    trace!(self.log, "Single block processing succeeded"; "block" => %root);
                    self.single_block_lookups.remove(&target_id);
                }
                AvailabilityProcessingStatus::MissingComponents(_, _block_root) => {
                    // if this was the result of a blocks request, the block peer did nothing wrong.
                    // if we already had a blobs resposne, we should penalize the blobs peer because
                    // they did not provide all blobs.
                    if request_ref.both_components_processed() {
                        if let Ok(blob_peer) =
                            request_ref.blob_request_state.state.processing_peer()
                        {
                            if let PeerShouldHave::BlockAndBlobs(blob_peer) = blob_peer {
                                cx.report_peer(
                                    blob_peer,
                                    PeerAction::MidToleranceError,
                                    "single_block_failure",
                                );
                            }
                            request_ref
                                .blob_request_state
                                .state
                                .remove_peer_if_useless(blob_peer.as_peer_id());
                            if !<BlobRequestState<
                                single_block_lookup::Current,
                                <T as BeaconChainTypes>::EthSpec,
                            > as RequestState<single_block_lookup::Current, T>>::downloading(
                                &request_ref.blob_request_state,
                            ) {
                                // Try it again if possible.
                                if let Err(()) = request_ref
                                    .blob_request_state
                                    .retry_request_after_failure(target_id, cx, &self.log)
                                {
                                    self.single_block_lookups.remove(&target_id);
                                };
                            }
                        } else {
                            trace!(self.log, "Dropped blob peer prior to penalizing"; "root" => ?root);
                            self.single_block_lookups.remove(&target_id);
                        };
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
                self.single_block_lookups.remove(&target_id);
            }
            BlockProcessingResult::Err(e) => {
                trace!(self.log, "Single block processing failed"; "block" => %root, "error" => %e);
                match e {
                    BlockError::BlockIsAlreadyKnown => {
                        // No error here
                        self.single_block_lookups.remove(&target_id);
                    }
                    BlockError::BeaconChainError(e) => {
                        // Internal error
                        error!(self.log, "Beacon chain error processing single block"; "block_root" => %root, "error" => ?e);
                        self.single_block_lookups.remove(&target_id);
                    }
                    BlockError::ParentUnknown(block) => {
                        let slot = block.slot();
                        let parent_root = block.parent_root();
                        request_ref.add_unknown_parent_components(block.into());
                        self.search_parent(slot, root, parent_root, peer_id.to_peer_id(), cx);
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
                        self.single_block_lookups.remove(&target_id);
                    }
                    BlockError::AvailabilityCheck(
                        AvailabilityCheckError::KzgVerificationFailed,
                    )
                    | BlockError::AvailabilityCheck(AvailabilityCheckError::Kzg(_))
                    | BlockError::BlobValidation(_) => {
                        warn!(self.log, "Blob validation failure"; "root" => %root, "peer_id" => %peer_id);
                        if let Ok(blob_peer) =
                            request_ref.blob_request_state.state.processing_peer()
                        {
                            cx.report_peer(
                                blob_peer.to_peer_id(),
                                PeerAction::MidToleranceError,
                                "single_blob_failure",
                            );
                            // Try it again if possible.
                            if let Err(()) = request_ref
                                .blob_request_state
                                .retry_request_after_failure(target_id, cx, &self.log)
                            {
                                self.single_block_lookups.remove(&target_id);
                            };
                        }
                    }
                    other => {
                        warn!(self.log, "Peer sent invalid block in single block lookup"; "root" => %root, "error" => ?other, "peer_id" => %peer_id);
                        if let Ok(block_peer) =
                            request_ref.block_request_state.state.processing_peer()
                        {
                            cx.report_peer(
                                block_peer.to_peer_id(),
                                PeerAction::MidToleranceError,
                                "single_block_failure",
                            );

                            // Try it again if possible.
                            if let Err(()) = request_ref
                                .blob_request_state
                                .retry_request_after_failure(target_id, cx, &self.log)
                            {
                                self.single_block_lookups.remove(&target_id);
                            };
                        }
                    }
                }
            }
        };

        //TODO(sean) move metrics to lookup response trait
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
        cx: &SyncNetworkContext<T>,
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

        let Ok(peer_id) =
            parent_lookup.processing_peer() else {
            return
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
                self.request_parent(parent_lookup, cx);
            }
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockProcessingResult::Err(BlockError::BlockIsAlreadyKnown { .. }) => {
                // Check if the beacon processor is available
                let beacon_processor = match cx.beacon_processor_if_enabled() {
                    Some(beacon_processor) => beacon_processor,
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

                // Find the child block that spawned the parent lookup request and add it to the chain
                // to send for processing.
                if let Some(child_lookup_id) =
                    self.single_block_lookups.iter().find_map(|(id, lookup)| {
                        (lookup.block_request_state.requested_block_root == chain_hash).then(|| *id)
                    })
                {
                    let Some(child_lookup) = self.single_block_lookups.get_mut(&child_lookup_id)  else {
                        debug!(self.log, "Missing child for parent lookup request"; "child_root" => ?chain_hash);
                        return;
                    };
                    if let Some(rpc_block) = child_lookup.get_downloaded_block() {
                        blocks.push(rpc_block);
                    } else {
                        trace!(self.log, "Parent lookup chain complete, awaiting child response"; "chain_hash" => ?chain_hash);
                    }
                } else {
                    debug!(self.log, "Missing child for parent lookup request"; "child_root" => ?chain_hash);
                };

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
        cx: &SyncNetworkContext<T>,
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
        parent_lookup.processing_failed();
        self.request_parent(parent_lookup, cx);
    }

    pub fn parent_chain_processed(
        &mut self,
        chain_hash: Hash256,
        result: BatchProcessResult,
        cx: &SyncNetworkContext<T>,
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
                let Some(id) = self
                    .single_block_lookups
                    .iter()
                    .find_map(|(id, req)|
                        (req.block_request_state.requested_block_root == chain_hash).then(|| *id)) else {
                    warn!(self.log, "No id found for single block lookup"; "chain_hash" => %chain_hash);
                    return;
                };

                let Some(lookup) = self
                    .single_block_lookups
                    .get_mut(&id) else {
                    warn!(self.log, "No id found for single block lookup"; "chain_hash" => %chain_hash);
                    return;
                };

                if let Some(rpc_block) = lookup.get_downloaded_block() {
                    // This is the correct block, send it for processing
                    if self
                        .send_block_for_processing(
                            chain_hash,
                            rpc_block,
                            Duration::from_secs(0), //TODO(sean) pipe this through
                            BlockProcessType::SingleBlock { id: id },
                            cx,
                        )
                        .is_err()
                    {
                        // Remove to avoid inconsistencies
                        self.single_block_lookups.remove(&id);
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
        block: RpcBlock<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), ()> {
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
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), ()> {
        let blob_count = blobs.iter().filter(|b| b.is_some()).count();
        if blob_count == 0 {
            return Ok(());
        }
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

    fn request_parent(&mut self, mut parent_lookup: ParentLookup<T>, cx: &SyncNetworkContext<T>) {
        let response = parent_lookup.request_parent(cx);

        match response {
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
                    parent_lookup::RequestError::AlreadyDownloaded => {}
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

#[derive(Debug, Copy, Clone)]
pub enum LookupType {
    Current,
    Parent,
}
