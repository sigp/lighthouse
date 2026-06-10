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

use self::parent_chain::{NodeChain, compute_parent_chains};
pub use self::single_block_lookup::DownloadResult;
use self::single_block_lookup::{LookupRequestError, PeerType, SingleBlockLookup};
use super::manager::{BlockProcessType, SLOT_IMPORT_TOLERANCE};
use super::network_context::{RpcResponseError, SyncNetworkContext};
use crate::metrics;
use crate::network_beacon_processor::BlockProcessingResult;
use crate::sync::SyncMessage;
use crate::sync::block_lookups::parent_chain::find_oldest_fork_ancestor;
use crate::sync::block_lookups::single_block_lookup::{
    AwaitingParent, ImportedParent, LookupResult,
};
use beacon_chain::BeaconChainTypes;
use fnv::FnvHashMap;
use lighthouse_network::PeerId;
use lighthouse_network::service::api_types::SingleLookupReqId;
use lru_cache::LRUTimeCache;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use tracing::{debug, error, warn};
use types::{
    DataColumnSidecarList, EthSpec, ExecutionBlockHash, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope,
};

pub mod parent_chain;
mod single_block_lookup;

/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
///
/// Have the same value as range's sync tolerance to consider a peer synced. Once sync lookup
/// reaches the maximum depth it will force trigger range sync.
pub(crate) const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE;

const IGNORED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 4;

/// Maximum time we allow a lookup to exist before assuming it is stuck and will never make
/// progress. Assume the worse case processing time per block component set * times max depth.
/// 15 * 2 * 32 = 16 minutes.
const LOOKUP_MAX_DURATION_STUCK_SECS: u64 = 15 * PARENT_DEPTH_TOLERANCE as u64;
/// The most common case of child-lookup without peers is receiving block components before the
/// attestation deadline when the node is lagging behind. Once peers start attesting for the child
/// lookup at most after 4 seconds, the lookup should gain peers.
const LOOKUP_MAX_DURATION_NO_PEERS_SECS: u64 = 10;

/// Lookups contain untrusted data, including blocks that have not yet been validated. In case of
/// bugs or malicious activity we want to bound how much memory these lookups can consume. Aprox the
/// max size of a lookup is ~ 10 MB (current max size of gossip and RPC blocks). 200 lookups can
/// take at most 2 GB. 200 lookups allow 3 parallel chains of depth 64 (current maximum).
const MAX_LOOKUPS: usize = 200;

type BlockDownloadResponse<E> = Result<DownloadResult<Arc<SignedBeaconBlock<E>>>, RpcResponseError>;
type CustodyDownloadResponse<E> =
    Result<DownloadResult<DataColumnSidecarList<E>>, RpcResponseError>;
type PayloadDownloadResponse<E> =
    Result<DownloadResult<Arc<SignedExecutionPayloadEnvelope<E>>>, RpcResponseError>;

pub enum BlockComponent<E: EthSpec> {
    Block(DownloadResult<Arc<SignedBeaconBlock<E>>>),
    Sidecar,
}

pub type SingleLookupId = u32;

pub struct BlockLookups<T: BeaconChainTypes> {
    /// A cache of block roots that must be ignored for some time to prevent useless searches. For
    /// example if a chain is too long, its lookup chain is dropped, and range sync is expected to
    /// eventually sync those blocks
    ignored_chains: LRUTimeCache<Hash256>,

    // TODO: Why not index lookups by block_root?
    single_block_lookups: FnvHashMap<SingleLookupId, SingleBlockLookup<T>>,

    /// Used for testing assertions
    metrics: BlockLookupsMetrics,
}

#[cfg(test)]
use lighthouse_network::service::api_types::Id;

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct BlockLookupSummary {
    /// Lookup ID
    pub id: Id,
    /// Requested block root
    pub block_root: Hash256,
    /// List of peers that claim to have imported this set of block components.
    pub peers: Vec<PeerId>,
}

impl<T: BeaconChainTypes> BlockLookups<T> {
    pub fn new() -> Self {
        Self {
            ignored_chains: LRUTimeCache::new(Duration::from_secs(
                IGNORED_CHAINS_CACHE_EXPIRY_SECONDS,
            )),
            single_block_lookups: Default::default(),
            metrics: <_>::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn metrics(&self) -> &BlockLookupsMetrics {
        &self.metrics
    }

    #[cfg(test)]
    pub(crate) fn insert_ignored_chain(&mut self, block_root: Hash256) {
        self.ignored_chains.insert(block_root);
    }

    #[cfg(test)]
    pub(crate) fn get_ignored_chains(&mut self) -> Vec<Hash256> {
        self.ignored_chains.keys().cloned().collect()
    }

    #[cfg(test)]
    pub(crate) fn active_single_lookups(&self) -> Vec<BlockLookupSummary> {
        self.single_block_lookups
            .iter()
            .map(|(id, l)| BlockLookupSummary {
                id: *id,
                block_root: l.block_root(),
                peers: l.all_peers(),
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
    ///
    /// Returns true if the lookup is created or already exists
    #[must_use = "only reference the new lookup if returns true"]
    pub fn search_child_and_parent(
        &mut self,
        block_root: Hash256,
        block_component: BlockComponent<T::EthSpec>,
        parent_root: Hash256,
        parent_block_hash: Option<ExecutionBlockHash>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) -> bool {
        let parent_lookup_exists = self.search_parent_of_child(
            parent_root,
            &PeerType::new(parent_block_hash),
            block_root,
            &[peer_id],
            cx,
        );
        // Only create the child lookup if the parent exists
        if parent_lookup_exists {
            // `search_parent_of_child` ensures that the parent lookup exists so we can safely wait for it
            self.new_current_lookup(
                block_root,
                Some(block_component),
                Some(AwaitingParent::new(parent_root, parent_block_hash)),
                // On a `UnknownParentBlock` or `UnknownParentSidecarHeader` event the peer is not
                // required to have the rest of the block components. Create the lookup with zero
                // peers to house the block components.
                &[],
                &PeerType::Block,
                cx,
            )
        } else {
            false
        }
    }

    /// Search a block whose parent root is unknown.
    ///
    /// Returns true if the lookup is created or already exists
    #[must_use = "only reference the new lookup if returns true"]
    pub fn search_unknown_block(
        &mut self,
        block_root: Hash256,
        peer_source: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> bool {
        self.new_current_lookup(block_root, None, None, peer_source, &PeerType::Block, cx)
    }

    /// A block or blob triggers the search of a parent.
    /// Check if this new lookup extends a bad chain:
    /// - Extending `child_block_root_trigger` would exceed the max depth
    /// - `block_root_to_search` is a failed chain
    ///
    /// Returns true if the lookup is created or already exists
    #[must_use = "only reference the new lookup if returns true"]
    pub fn search_parent_of_child(
        &mut self,
        block_root_to_search: Hash256,
        peer_type: &PeerType,
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
                debug!(block_root = ?block_root_to_search, "Parent lookup chain too long");

                // Searching for this parent would extend a parent chain over the max
                // Insert the tip only to chains to ignore
                self.ignored_chains.insert(parent_chain.tip);

                // Note: Drop only the chain that's too long until it merges with another chain
                // that's not too long. Consider this attack: there's a chain of valid unknown
                // blocks A -> B. A malicious peer builds `PARENT_DEPTH_TOLERANCE` garbage
                // blocks on top of A forming A -> C. The malicious peer forces us to fetch C
                // from it, which will result in parent A hitting the chain_too_long error. Then
                // the valid chain A -> B is dropped too.
                //
                // `find_oldest_fork_ancestor` should never return Err, unwrapping to tip for
                // complete-ness
                let parent_chain_tip = parent_chain.tip;
                let block_to_drop =
                    find_oldest_fork_ancestor(parent_chains, chain_idx).unwrap_or(parent_chain_tip);
                // Drop all lookups descending from the child of the too long parent chain
                if let Some((lookup_id, lookup)) = self
                    .single_block_lookups
                    .iter()
                    .find(|(_, l)| l.block_root() == block_to_drop)
                {
                    // If a lookup chain is too long, we can't distinguish a valid chain from a
                    // malicious one. We must attempt to sync this chain to not lose liveness. If
                    // the chain grows too long, we stop lookup sync and transition this head to
                    // forward range sync. We need to tell range sync which head to sync to, and
                    // from which peers. The lookup of the very tip of this chain may contain zero
                    // peers if it's the parent-child lookup. So we do a bit of a trick here:
                    // - Tell range sync to sync to the tip's root (if available, else its ancestor)
                    // - But use all peers in the ancestor lookup, which should have at least one
                    //   peer, and its peer set is a strict superset of the tip's lookup.
                    if let Some((_, tip_lookup)) = self
                        .single_block_lookups
                        .iter()
                        .find(|(_, l)| l.block_root() == parent_chain_tip)
                    {
                        cx.send_sync_message(SyncMessage::AddPeersForceRangeSync {
                            peers: lookup.all_peers(),
                            head_slot: tip_lookup.peek_downloaded_block_slot(),
                            head_root: parent_chain_tip,
                        });
                    } else {
                        // Should never happen, log error and continue the lookup drop
                        error!(
                            error = "Parent chain tip lookup not found",
                            block_root = ?parent_chain_tip,
                            "Unable to transition lookup to range sync"
                        );
                    }

                    // Do not downscore peers here. Because we can't distinguish a valid chain from
                    // a malicious one we may penalize honest peers for attempting to discover us a
                    // valid chain. Until blocks_by_range allows to specify a tip, for example with
                    // https://github.com/ethereum/consensus-specs/pull/3845 we will have poor
                    // attributability. A peer can send us garbage blocks over blocks_by_root, and
                    // then correct blocks via blocks_by_range.

                    self.drop_lookup_and_children(*lookup_id, "chain_too_long");
                } else {
                    // Should never happen
                    error!(
                        error = "Block to drop lookup not found",
                        block_root = ?block_to_drop,
                        "Unable to transition lookup to range sync"
                    );
                }

                return false;
            }
        }

        // `block_root_to_search` is a failed chain check happens inside new_current_lookup
        self.new_current_lookup(block_root_to_search, None, None, peers, peer_type, cx)
    }

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    /// Returns true if the lookup is created or already exists
    #[must_use = "only reference the new lookup if returns true"]
    fn new_current_lookup(
        &mut self,
        block_root: Hash256,
        block_component: Option<BlockComponent<T::EthSpec>>,
        awaiting_parent: Option<AwaitingParent>,
        peers: &[PeerId],
        peer_type: &PeerType,
        cx: &mut SyncNetworkContext<T>,
    ) -> bool {
        // If this block or it's parent is part of a known ignored chain, ignore it.
        if self.ignored_chains.contains(&block_root) {
            debug!(?block_root, "Dropping lookup for block marked ignored");
            return false;
        }

        // Do not re-request a block that is already being requested
        if let Some((&lookup_id, lookup)) = self
            .single_block_lookups
            .iter_mut()
            .find(|(_id, lookup)| lookup.is_for_block(block_root))
        {
            if let Some(block_component) = block_component {
                let imported = lookup.add_child_components(block_component);
                if !imported {
                    debug!(?block_root, "Lookup child component ignored");
                }
            }

            if let Err(e) = self.add_peers_to_lookup_and_ancestors(lookup_id, peers, peer_type, cx)
            {
                warn!(error = ?e, "Error adding peers to ancestor lookup");
            }

            return true;
        }

        // Ensure that awaiting parent exists, otherwise this lookup won't be able to make progress
        if let Some(awaiting_parent) = awaiting_parent
            && !self
                .single_block_lookups
                .iter()
                .any(|(_, lookup)| lookup.block_root() == awaiting_parent.parent_root())
        {
            warn!(block_root = ?awaiting_parent, "Ignoring child lookup parent lookup not found");
            return false;
        }

        // Lookups contain untrusted data, bound the total count of lookups hold in memory to reduce
        // the risk of OOM in case of bugs of malicious activity.
        if self.single_block_lookups.len() >= MAX_LOOKUPS {
            warn!(?block_root, "Dropping lookup reached max");
            return false;
        }

        // If we know that this lookup has unknown parent (is awaiting a parent lookup to resolve),
        // signal here to hold processing downloaded data.
        let mut lookup =
            SingleBlockLookup::new(block_root, peers, peer_type, cx.next_id(), awaiting_parent);
        let _guard = lookup.span.clone().entered();

        // Add block components to the new request
        if let Some(block_component) = block_component {
            lookup.add_child_components(block_component);
        }

        let id = lookup.id;
        let lookup = match self.single_block_lookups.entry(id) {
            Entry::Vacant(entry) => entry.insert(lookup),
            Entry::Occupied(_) => {
                // Should never happen
                warn!(id, "Lookup exists with same id");
                return false;
            }
        };

        debug!(
            ?peers,
            ?block_root,
            ?awaiting_parent,
            id = lookup.id,
            "Created block lookup"
        );
        metrics::inc_counter(&metrics::SYNC_LOOKUP_CREATED);
        self.metrics.created_lookups += 1;

        let result = lookup.continue_requests(cx);
        if self.on_lookup_result(id, result, "new_current_lookup", cx) {
            self.update_metrics();
            true
        } else {
            false
        }
    }

    /* Lookup responses */

    /// Process a block response received from a single lookup request.
    pub fn on_block_download_response(
        &mut self,
        id: SingleLookupReqId,
        response: BlockDownloadResponse<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(lookup) = self.single_block_lookups.get_mut(&id.lookup_id) else {
            debug!(?id, "Block returned for single block lookup not present");
            return;
        };
        let result = lookup.on_block_download_response(id.req_id, response, cx);
        self.on_lookup_result(id.lookup_id, result, "block_download_response", cx);
    }

    pub fn on_custody_download_response(
        &mut self,
        id: SingleLookupReqId,
        response: CustodyDownloadResponse<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(lookup) = self.single_block_lookups.get_mut(&id.lookup_id) else {
            debug!(?id, "Custody returned for single block lookup not present");
            return;
        };
        let result = lookup.on_custody_download_response(id.req_id, response, cx);
        self.on_lookup_result(id.lookup_id, result, "custody_download_response", cx);
    }

    pub fn on_payload_download_response(
        &mut self,
        id: SingleLookupReqId,
        response: PayloadDownloadResponse<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(lookup) = self.single_block_lookups.get_mut(&id.lookup_id) else {
            debug!(
                ?id,
                "Payload envelope returned for a lookup id that doesn't exist"
            );
            return;
        };
        let result = lookup.on_payload_download_response(id.req_id, response, cx);
        self.on_lookup_result(id.lookup_id, result, "payload_download_response", cx);
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId) {
        for (id, lookup) in self.single_block_lookups.iter_mut() {
            lookup.remove_peer(peer_id);
            if lookup.has_no_peers() {
                debug!(%id, "Lookup has no peers");
            }
        }
    }

    /* Processing responses */

    pub fn on_processing_result(
        &mut self,
        process_type: BlockProcessType,
        result: BlockProcessingResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let lookup_id = process_type.id();
        let Some(lookup) = self.single_block_lookups.get_mut(&lookup_id) else {
            debug!(id = lookup_id, "Unknown single block lookup");
            return;
        };

        debug!(
            block_root = ?lookup.block_root(),
            id = lookup_id,
            ?process_type,
            ?result,
            "Received lookup processing result"
        );

        let lookup_result = match process_type {
            BlockProcessType::SingleBlock { .. } => {
                // Update the result of the lookup first, here we may start the download of Gloas
                // payload, which may error.
                let lookup_result = lookup.on_block_processing_result(result.clone(), cx);
                let lookup_is_awaiting_event = lookup.is_awaiting_event();
                let block_root = lookup.block_root();
                // Then, as a side-effect continue the EMPTY children of this lookup. Only if the
                // block just imported which ensures we just do it once per lookup.
                if let BlockProcessingResult::Imported(..) = result
                    && let Some(bid_block_hash) = lookup.peek_downloaded_bid_block_hash()
                {
                    self.continue_child_lookups(
                        block_root,
                        ImportedParent::OnlyGloasBlock(bid_block_hash),
                        cx,
                    );
                }
                // Then if this lookup happens to have only empty children we can remove it now. We
                // must make sure that no other lookup is awaiting this one, and that no requests
                // are on-going.
                if !lookup_is_awaiting_event && !self.has_any_awaiting_children(block_root) {
                    Ok(LookupResult::Completed)
                } else {
                    lookup_result
                }
            }
            BlockProcessType::SingleCustodyColumn(_) => {
                lookup.on_data_processing_result(result, cx)
            }
            BlockProcessType::SinglePayloadEnvelope(_) => {
                lookup.on_payload_processing_result(result, cx)
            }
        };
        self.on_lookup_result(lookup_id, lookup_result, "processing_result", cx);
    }

    pub fn has_any_awaiting_children(&self, block_root: Hash256) -> bool {
        self.single_block_lookups
            .iter()
            .any(|(_, lookup)| lookup.is_awaiting_block(block_root))
    }

    /// Makes progress on the immediate children of `block_root`
    pub fn continue_child_lookups(
        &mut self,
        parent_root: Hash256,
        imported_parent: ImportedParent,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let mut lookup_results = vec![]; // < need to buffer lookup results to not re-borrow &mut self

        for (id, lookup) in self.single_block_lookups.iter_mut() {
            if lookup.is_awaiting_parent(parent_root, imported_parent) {
                lookup.resolve_awaiting_parent();
                debug!(
                    ?imported_parent,
                    id,
                    block_root = ?lookup.block_root(),
                    "Continuing child lookup"
                );
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
    pub fn drop_lookup_and_children(&mut self, dropped_id: SingleLookupId, reason: &'static str) {
        if let Some(dropped_lookup) = self.single_block_lookups.remove(&dropped_id) {
            debug!(
                id = ?dropped_id,
                block_root = ?dropped_lookup.block_root(),
                awaiting_parent = ?dropped_lookup.awaiting_parent(),
                reason,
                "Dropping lookup"
            );
            metrics::inc_counter_vec(&metrics::SYNC_LOOKUP_DROPPED, &[reason]);
            self.metrics.dropped_lookups += 1;

            let child_lookups = self
                .single_block_lookups
                .iter()
                .filter(|(_, lookup)| lookup.is_awaiting_block(dropped_lookup.block_root()))
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();

            for id in child_lookups {
                self.drop_lookup_and_children(id, reason);
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
            Ok(LookupResult::Pending) => true,
            Ok(LookupResult::ParentUnknown {
                parent_root,
                parent_block_hash,
                block_root,
                peers,
            }) => {
                if self.search_parent_of_child(
                    parent_root,
                    &PeerType::new(parent_block_hash),
                    block_root,
                    &peers,
                    cx,
                ) {
                    true
                } else {
                    self.drop_lookup_and_children(id, "Failed");
                    self.update_metrics();
                    false
                }
            }
            Ok(LookupResult::Completed) => {
                if let Some(lookup) = self.single_block_lookups.remove(&id) {
                    debug!(
                        block = ?lookup.block_root(),
                        id,
                        "Dropping completed lookup"
                    );
                    metrics::inc_counter(&metrics::SYNC_LOOKUP_COMPLETED);
                    self.metrics.completed_lookups += 1;
                    // Block imported, continue the requests of pending child blocks
                    self.continue_child_lookups(
                        lookup.block_root(),
                        ImportedParent::LookupComplete,
                        cx,
                    );
                    self.update_metrics();
                } else {
                    debug!(id, "Attempting to drop non-existent lookup");
                }
                false
            }
            Err(error) => {
                debug!(id, source, ?error, "Dropping lookup on request error");
                self.drop_lookup_and_children(id, error.into());
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
            debug!(
                id = lookup_id,
                %block_root,
                "Dropping lookup with no peers"
            );
            self.drop_lookup_and_children(lookup_id, "no_peers");
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
                    warn!(error = ?e,"Error finding oldest ancestor lookup");
                    // Default to dropping the lookup that exceeds the max duration so at least
                    // eventually sync should be unstuck
                    stuck_lookup
                }
            };

            if stuck_lookup.id == ancestor_stuck_lookup.id {
                warn!(
                    block_root = ?stuck_lookup.block_root(),
                    lookup = ?stuck_lookup,
                    "Notify the devs a sync lookup is stuck"
                );
            } else {
                warn!(
                    block_root = ?stuck_lookup.block_root(),
                    lookup = ?stuck_lookup,
                    ancestor_block_root = ?ancestor_stuck_lookup.block_root(),
                    ancestor_lookup = ?ancestor_stuck_lookup,
                    "Notify the devs a sync lookup is stuck"
                );
            }

            metrics::inc_counter(&metrics::SYNC_LOOKUPS_STUCK);
            self.drop_lookup_and_children(ancestor_stuck_lookup.id, "lookup_stuck");
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
                .find(|l| l.block_root() == awaiting_parent.parent_root())
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
    ///
    /// Note: Takes a `lookup_id` as argument to allow recursion on mutable lookups, without having
    /// to duplicate the code to add peers to a lookup
    fn add_peers_to_lookup_and_ancestors(
        &mut self,
        lookup_id: SingleLookupId,
        peers: &[PeerId],
        peer_type: &PeerType,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), String> {
        let lookup = self
            .single_block_lookups
            .get_mut(&lookup_id)
            .ok_or(format!("Unknown lookup for id {lookup_id}"))?;

        let mut added_some_peer = false;
        for peer in peers {
            if lookup.add_peer(*peer, peer_type) {
                added_some_peer = true;
                debug!(
                    block_root = ?lookup.block_root(),
                    ?peer,
                    "Adding peer to existing single block lookup"
                );
            }
        }

        if let Some(&awaiting_parent) = lookup.awaiting_parent() {
            // Regardless of gloas full/empty the lookup to add peers to is keyed by block_root
            if let Some((&parent_id, _)) = self
                .single_block_lookups
                .iter()
                .find(|(_, l)| l.block_root() == awaiting_parent.parent_root())
            {
                self.add_peers_to_lookup_and_ancestors(
                    parent_id,
                    peers,
                    &awaiting_parent.into_peer_type(),
                    cx,
                )
            } else {
                Err(format!("Lookup references unknown {awaiting_parent:?}"))
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

#[derive(Default, Clone, Debug)]
pub(crate) struct BlockLookupsMetrics {
    pub created_lookups: usize,
    pub dropped_lookups: usize,
    pub completed_lookups: usize,
}
