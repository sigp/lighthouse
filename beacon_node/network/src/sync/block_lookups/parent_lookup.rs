use lighthouse_network::{rpc::BlocksByRootRequest, PeerAction, PeerId};
use slog::warn;
use ssz_types::VariableList;
use store::{EthSpec, Hash256, SignedBeaconBlock};

use crate::sync::{
    manager::{Id, SLOT_IMPORT_TOLERANCE},
    network_context::SyncNetworkContext,
};

use super::single_block_lookup::SingleBlockRequest;

/// How many attempts we try to find a parent of a block before we give up trying .
pub(crate) const PARENT_FAIL_TOLERANCE: u8 = 5;
/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
pub(crate) const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

/// Maintains a sequential list of parents to lookup and the lookup's current state.
pub(crate) struct ParentLookup<T: EthSpec> {
    /// The root of the block triggering this parent request.
    chain_hash: Hash256,

    /// The blocks that have currently been downloaded.
    downloaded_blocks: Vec<SignedBeaconBlock<T>>,

    /// The block lookup for the latest parent.
    current_parent_lookup: SingleBlockRequest<PARENT_FAIL_TOLERANCE>,
}

pub enum VerifyError {
    #[cfg(not(debug_assertions))]
    WrongRequest,
    Failed(&'static str),
    PreviousFailure {
        parent_root: Hash256,
    },
}

impl<T: EthSpec> ParentLookup<T> {
    pub fn new(block: SignedBeaconBlock<T>, peer_id: PeerId) -> Self {
        Self {
            chain_hash: block.canonical_root(),
            downloaded_blocks: vec![block],
            current_parent_lookup: SingleBlockRequest::new(block.parent_root(), peer_id),
        }
    }

    pub fn contains_block(&self, block: &SignedBeaconBlock<T>) -> bool {
        self.downloaded_blocks
            .iter()
            .any(|d_block| d_block == block)
    }

    pub fn add_peer(&mut self, block_root: &Hash256, peer_id: &PeerId) -> bool {
        return self.current_parent_lookup.add_peer(block_root, peer_id);
    }

    /// Attempts to request the next unknown parent. If the request fails, it should be removed.
    pub fn request_parent(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
        log: &slog::Logger,
    ) -> Result<(), ()> {
        if self.downloaded_blocks.len() >= PARENT_DEPTH_TOLERANCE {
            warn!(log, "Parent request reached max chain depth";
                "chain_hash" => %self.chain_hash,
                "downloaded_blocks" => self.downloaded_blocks.len()
            );
            cx.report_peer(
                *self.current_parent_lookup.current_peer(),
                PeerAction::MidToleranceError,
                "failed_parent_request",
            );
            return Err(());
        }
        match self.current_parent_lookup.request_block() {

        }

        let request = self.current_parent_lookup.request_block();

        let parent_hash = self.current_parent_lookup.hash;

        let request = BlocksByRootRequest {
            block_roots: VariableList::from(vec![parent_hash]),
        };

        if let Some(peer_id) = self.current_parent_lookup.next_peer() {}

        match cx.parent_lookup_request(peer_id, request) {
            Ok(request_id) => {
                self.state =
                    State::Downloading(request_id, SingleBlockRequest::new(parent_hash, peer_id));
            }
            Err(reason) => {
                warn!(log, "Send parent request failed"; "chain_hash" => %self.chain_hash, "reason" => reason);
                return Err(());
            }
        }

        Ok(())
    }

    pub fn pending_response(&self, req_id: Id) -> bool {
        match &self.state {
            State::Downloading(id, _) => req_id == *id,
            _ => false,
        }
    }

    /// Get the parent lookup's chain hash.
    pub fn chain_hash(&self) -> Hash256 {
        self.chain_hash
    }

    pub fn download_failed(&mut self) {
        self.state = State::AwaitingDownload;
        self.failed_attempts += 1;
    }

    pub fn destructure(self) -> (Hash256, Vec<SignedBeaconBlock<T>>, PeerId) {
        let ParentLookup {
            chain_hash,
            downloaded_blocks,
            last_submitted_peer,
            ..
        } = self;
        (chain_hash, downloaded_blocks, last_submitted_peer)
    }

    /// Verifies that the received block is what we requested. If so, parent lookup now waits for
    /// the processing result of the block.
    pub fn verify_block(
        &mut self,
        id: Id,
        block: Option<Box<SignedBeaconBlock<T>>>,
        failed_chains: &lru_cache::LRUCache<Hash256>,
    ) -> Result<Option<Box<SignedBeaconBlock<T>>>, VerifyError> {
        let block = match &mut self.state {
            State::Downloading(req_id, single_block_request) if *req_id == id => {
                // register the block as received and verify that it matches what we expected
                match single_block_request.verify_block(block) {
                    Ok(block) => block,
                    Err(e) => {
                        // If verification failed the block should be downloaded again
                        self.failed_attempts += 1;
                        self.state = State::AwaitingDownload;
                        return Err(VerifyError::Failed(e));
                    }
                }
            }
            _ => {
                #[cfg(not(debug_assertions))]
                return Err(VerifyError::WrongRequest);
                #[cfg(debug_assertions)]
                panic!("verifying block for wrong parent request") // Should never happen
            }
        };

        // check if the parent of this block isn't in the failed cache. If it is, this chain should
        // be dropped and the peer downscored.
        if let Some(parent_root) = block.as_ref().map(|block| block.message().parent_root()) {
            if failed_chains.contains(&parent_root) {
                self.state = State::AwaitingDownload;
                return Err(VerifyError::PreviousFailure { parent_root });
            }
        }

        self.state = State::Processing;
        Ok(block)
    }

    pub fn pending_block_processing(&self, chain_hash: Hash256) -> bool {
        matches!(self.state, State::Processing) && self.chain_hash == chain_hash
    }

    pub fn append_block(&mut self, block: SignedBeaconBlock<T>) {
        self.downloaded_blocks.push(block)
    }

    pub fn last_submitted_peer(&self) -> PeerId {
        self.last_submitted_peer
    }

    #[cfg(test)]
    pub fn failed_attempts(&self) -> usize {
        self.failed_attempts
    }
}
