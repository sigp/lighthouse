use std::collections::{hash_map::Entry, HashSet};

use beacon_chain::{BeaconChainTypes, BlockError};
use fnv::FnvHashMap;
use lighthouse_network::{rpc::BlocksByRootRequest, PeerAction, PeerId};
use lru_cache::LRUCache;
use slog::{crit, debug, error, warn, Logger};
use smallvec::SmallVec;
use ssz_types::VariableList;
use store::{Hash256, SignedBeaconBlock};
use tokio::sync::mpsc;

use crate::beacon_processor::{ChainSegmentProcessId, WorkEvent};

use self::{
    parent_lookup::{ParentLookup, VerifyError},
    single_block_lookup::SingleBlockRequest,
};

use super::{
    manager::{BlockProcessType, Id},
    network_context::SyncNetworkContext,
};

mod parent_lookup;
mod single_block_lookup;
#[cfg(test)]
mod tests;

const FAILED_CHAINS_CACHE_SIZE: usize = 500;

struct BlockLookups<T: BeaconChainTypes> {
    /// A collection of parent block lookups.
    parent_queue: SmallVec<[ParentLookup<T::EthSpec>; 3]>,

    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUCache<Hash256>,

    /// A collection of block hashes being searched for and a flag indicating if a result has been
    /// received or not.
    ///
    /// The flag allows us to determine if the peer returned data or sent us nothing.
    single_block_lookups: FnvHashMap<Id, SingleBlockRequest>,

    /// Block being requested from parent requests.
    // active_block_lookups: HashSet<Hash256>,

    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<WorkEvent<T>>,

    /// The logger for the import manager.
    log: Logger,
}

impl<T: BeaconChainTypes> BlockLookups<T> {
    pub fn new(beacon_processor_send: mpsc::Sender<WorkEvent<T>>, log: Logger) -> Self {
        Self {
            parent_queue: Default::default(),
            failed_chains: LRUCache::new(FAILED_CHAINS_CACHE_SIZE),
            single_block_lookups: Default::default(),
            beacon_processor_send,
            log,
        }
    }

    /* Lookup requests */

    pub fn search_block(
        &mut self,
        hash: Hash256,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        // Do not re-request a block that is already being requested
        if self
            .single_block_lookups
            .values()
            .any(|single_block_request| single_block_request.hash == hash)
        {
            return;
        }

        debug!(
            self.log,
            "Searching for block";
            "peer_id" => %peer_id,
            "block" => %hash
        );

        let request = BlocksByRootRequest {
            block_roots: VariableList::from(vec![hash]),
        };

        if let Ok(request_id) = cx.single_block_lookup_request(peer_id, request) {
            self.single_block_lookups
                .insert(request_id, SingleBlockRequest::new(hash));
        }
    }

    pub fn search_parent(
        &mut self,
        block: Box<SignedBeaconBlock<T::EthSpec>>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        let block_root = block.canonical_root();
        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&block.message().parent_root())
            || self.failed_chains.contains(&block_root)
        {
            debug!(self.log, "Block is from a past failed chain. Dropping";
                "block_root" => ?block_root, "block_slot" => block.slot());
            return;
        }

        // Make sure this block is not already being searched for
        // NOTE: Potentially store a hashset of blocks for O(1) lookups
        if self
            .parent_queue
            .iter()
            .any(|parent_req| parent_req.contains_block(&block))
        {
            // we are already searching for this block, ignore it
            return;
        }

        debug!(self.log, "Block with unknown parent received. Starting a parent lookup";
            "block_slot" => block.slot(), "block_hash" => %block_root, "parent_root" => %block.parent_root() );

        let mut parent_req = ParentLookup::new(*block, peer_id);
        if parent_req.request_parent(cx, &self.log).is_ok() {
            self.parent_queue.push(parent_req);
        }
    }

    /* Lookup responses */

    pub fn single_block_lookup_response(
        &mut self,
        id: Id,
        peer_id: PeerId,
        block: Option<Box<SignedBeaconBlock<T::EthSpec>>>,
        cx: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        match self.single_block_lookups.entry(id) {
            Entry::Occupied(mut req) => match req.get_mut().verify_block(block) {
                Ok(Some(block)) => {
                    // This is the corrrect block, send it for processing
                    // TODO: fix the seen timestamp
                    self.send_block_for_processing(
                        block,
                        peer_id,
                        BlockProcessType::SingleBlock {
                            seen_timestamp: std::time::Duration::from_secs(1),
                        },
                    )
                }
                Ok(None) => {
                    // request finished correctly, we can remove it.
                    req.remove();
                }
                Err(msg) => {
                    debug!(self.log, "Single block lookup failed"; "peer_id" => %peer_id, "error" => msg);
                    cx.report_peer(peer_id, PeerAction::LowToleranceError, msg);
                    req.remove();
                }
            },
            Entry::Vacant(_) => {
                if block.is_some() {
                    crit!(
                        self.log,
                        "Block returned for single block lookup not present"
                    );
                    #[cfg(debug_assertions)]
                    panic!("block returned for single block lookup not present");
                }
                return;
            }
        };
    }

    pub fn parent_lookup_response(
        &mut self,
        id: Id,
        peer_id: PeerId,
        block: Option<Box<SignedBeaconBlock<T::EthSpec>>>,
        cx: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        let pos = if let Some(pos) = self
            .parent_queue
            .iter()
            .position(|request| request.pending_response(id))
        {
            pos
        } else {
            if block.is_some() {
                debug!(self.log, "Response for a parent lookup request that was not found"; "peer_id" => %peer_id);
            }
            return;
        };

        let parent_lookup = self
            .parent_queue
            .get_mut(pos)
            .expect("Parent request was found");
        match parent_lookup.verify_block(id, block, &self.failed_chains) {
            Ok(Some(block)) => {
                // Block is correct, send to the beacon processor.
                let chain_hash = parent_lookup.chain_hash();
                self.send_block_for_processing(
                    block,
                    peer_id,
                    BlockProcessType::ParentLookup { chain_hash },
                )
            }
            Ok(None) => {
                // Request finished successfully, nothing else to do.
            }
            Err(e) => match e {
                VerifyError::Failed(e) => {
                    warn!(self.log, "Peer sent invalid response to parent request.";
                        "peer_id" => %peer_id,
                        "reason" => e
                    );

                    // We do not tolerate these kinds of errors. We will accept a few but these are signs
                    // of a faulty peer.
                    cx.report_peer(
                        peer_id,
                        PeerAction::LowToleranceError,
                        "parent_request_bad_hash",
                    );

                    // We try again, but downvote the peer.
                    if parent_lookup.request_parent(cx, &self.log).is_err() {
                        self.failed_chains.insert(parent_lookup.chain_hash());
                        self.parent_queue.remove(pos);
                    }
                }
                VerifyError::PreviousFailure { parent_root } => {
                    self.failed_chains.insert(parent_lookup.chain_hash());
                    debug!(
                        self.log,
                        "Parent chain ignored due to past failure";
                        "block" => %parent_root,
                    );
                    // Add the root block to failed chains
                    self.failed_chains.insert(parent_lookup.chain_hash());

                    return cx.report_peer(
                        peer_id,
                        PeerAction::MidToleranceError,
                        "bbroot_failed_chains",
                    );
                }
                #[cfg(not(debug_assertions))]
                WrongRequest => {
                    crit!(self.log, "Block response assigned to wrong parent request")
                }
            },
        };
    }

    pub fn parent_lookup_failed(
        &mut self,
        id: Id,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        if let Some(pos) = self
            .parent_queue
            .iter()
            .position(|request| request.pending_response(id))
        {
            let parent_lookup = self
                .parent_queue
                .get_mut(pos)
                .expect("Parent lookup was found");
            parent_lookup.download_failed();
            if parent_lookup.request_parent(cx, &self.log).is_err() {
                self.failed_chains.insert(parent_lookup.chain_hash());
                self.parent_queue.remove(pos);
            }
        } else {
            return debug!(self.log, "RPC failure for a parent lookup request that was not found"; "peer_id" => %peer_id);
        };
    }

    pub fn single_block_lookup_failed(&mut self, id: Id) {
        self.single_block_lookups.remove(&id);
    }

    /* Processing responses */

    pub fn parent_block_processed(
        &mut self,
        chain_hash: Hash256,
        result: Result<(), BlockError<T::EthSpec>>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        let mut parent_lookup = if let Some(pos) = self
            .parent_queue
            .iter()
            .position(|request| request.pending_block_processing(chain_hash))
        {
            self.parent_queue.remove(pos)
        } else {
            return debug!(self.log, "Process response for a parent lookup request that was not found"; "peer_id" => %peer_id);
        };

        match result {
            Err(BlockError::ParentUnknown(block)) => {
                // need to keep looking for parents
                // add the block back to the queue and continue the search
                parent_lookup.append_block(*block);
                if parent_lookup.request_parent(cx, &self.log).is_ok() {
                    self.parent_queue.push(parent_lookup);
                } else {
                    self.failed_chains.insert(parent_lookup.chain_hash());
                }
            }
            Ok(_) | Err(BlockError::BlockIsAlreadyKnown { .. }) => {
                let process_id = ChainSegmentProcessId::ParentLookup(
                    parent_lookup.last_submitted_peer(),
                    parent_lookup.chain_hash(),
                );
                let blocks = parent_lookup.downloaded_blocks;

                match self
                    .beacon_processor_send
                    .try_send(WorkEvent::chain_segment(process_id, blocks))
                {
                    Ok(_) => {}
                    Err(e) => {
                        error!(
                            self.log,
                            "Failed to send chain segment to processor";
                            "error" => ?e
                        );
                    }
                }
            }
            Err(outcome) => {
                // all else we consider the chain a failure and downvote the peer that sent
                // us the last block
                warn!(
                    self.log, "Invalid parent chain";
                    "score_adjustment" => %PeerAction::MidToleranceError,
                    "outcome" => ?outcome,
                    "last_peer" => %parent_lookup.last_submitted_peer(),
                );

                // Add this chain to cache of failed chains
                self.failed_chains.insert(chain_hash);

                // This currently can be a host of errors. We permit this due to the partial
                // ambiguity.
                cx.report_peer(
                    parent_lookup.last_submitted_peer(),
                    PeerAction::MidToleranceError,
                    "parent_request_err",
                );
            }
        }
    }

    pub fn parent_chain_processing_failed(&mut self, chain_hash: Hash256) {
        self.failed_chains.insert(chain_hash);
    }

    /* Helper functions */

    fn send_block_for_processing(
        &mut self,
        block: Box<SignedBeaconBlock<T::EthSpec>>,
        peer_id: PeerId,
        process_type: BlockProcessType,
    ) {
        let event = WorkEvent::rpc_beacon_block(block, peer_id, process_type);
        if let Err(e) = self.beacon_processor_send.try_send(event) {
            error!(
                self.log,
                "Failed to send sync block to processor";
                "error" => ?e
            );
        }
    }
}
