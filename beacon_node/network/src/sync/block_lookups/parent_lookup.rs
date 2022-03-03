use std::collections::HashSet;

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
    /// Request of the last parent.
    current_parent_request: SingleBlockRequest,
    /// Id of the last parent request.
    current_id: Id,
    /// Peers that should have these blocks.
    available_peers: HashSet<PeerId>,
    /// Number of times we have sent a request for this chain to retry a block.
    failed_attempts: u8,
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
    pub fn contains_block(&self, block: &SignedBeaconBlock<T>) -> bool {
        self.downloaded_blocks
            .iter()
            .any(|d_block| d_block == block)
    }

    pub fn new(
        block: SignedBeaconBlock<T>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Self, &'static str> {
        let current_parent_request = SingleBlockRequest::new(block.parent_root(), peer_id);
        let (peer, request) = current_parent_request.block_request();
        let current_id = cx.parent_lookup_request(peer_id, request)?;

        Ok(Self {
            chain_hash: block.canonical_root(),
            downloaded_blocks: vec![block],
            current_parent_request,
            current_id,
            available_peers: HashSet::from([peer_id]),
            failed_attempts: 0,
        })
    }

    /// Attempts to request the next unknown parent. If the request fails, it should be removed.
    pub fn request_parent(mut self, cx: &mut SyncNetworkContext<T>) -> Result<Self, ()> {
        // check to make sure this request hasn't failed
        if self.failed_attempts >= PARENT_FAIL_TOLERANCE {
            warn!(log, "Parent request failed";
                "chain_hash" => %self.chain_hash,
                "downloaded_blocks" => self.downloaded_blocks.len()
            );
            cx.report_peer(
                self.last_submitted_peer,
                PeerAction::MidToleranceError,
                "failed_parent_request",
            );
            return Err(());
        }
        if self.downloaded_blocks.len() >= PARENT_DEPTH_TOLERANCE {
            warn!(log, "Parent request reached max chain depth";
                "chain_hash" => %self.chain_hash,
                "downloaded_blocks" => self.downloaded_blocks.len()
            );
            cx.report_peer(
                self.last_submitted_peer,
                PeerAction::MidToleranceError,
                "failed_parent_request",
            );
            return Err(());
        }

        let parent_hash = self
            .downloaded_blocks
            .last()
            .expect("Parent requests are never empty")
            .parent_root();

        let request = BlocksByRootRequest {
            block_roots: VariableList::from(vec![parent_hash]),
        };

        // We continue to search for the chain of blocks from the same peer. Other peers are not
        // guaranteed to have this chain of blocks.
        let peer_id = self.last_submitted_peer;

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
