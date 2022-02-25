use std::collections::{hash_map::Entry, HashSet};

use beacon_chain::{BeaconChainTypes, BlockError};
use fnv::FnvHashMap;
use lighthouse_network::{rpc::BlocksByRootRequest, PeerAction, PeerId};
use lru_cache::LRUCache;
use slog::{crit, debug, error, Logger};
use smallvec::SmallVec;
use ssz_types::VariableList;
use store::{Hash256, SignedBeaconBlock};
use tokio::sync::mpsc;

use crate::beacon_processor::WorkEvent;

use self::{parent_lookup::ParentLookup, single_block_lookup::SingleBlockRequest};

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
        block: Box<SignedBeaconBlock<T::EthSpec>>,
        cx: &mut SyncNetworkContext<T::EthSpec>,
    ) {
    }

    pub fn parent_lookup_failed(&mut self, id: Id, peer_id: PeerId) {}

    pub fn single_block_lookup_failed(&mut self, id: Id) {
        self.single_block_lookups.remove(&id);
    }

    /* Processing responses */

    pub fn parent_block_processed(
        &mut self,
        chain_hash: Hash256,
        result: Result<Hash256, BlockError<T::EthSpec>>,
        peer_id: PeerId,
    ) {
    }

    pub fn parent_chain_processed(
        &mut self,
        chain_hash: Hash256,
        result: Result<Hash256, BlockError<T::EthSpec>>,
    ) {
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
