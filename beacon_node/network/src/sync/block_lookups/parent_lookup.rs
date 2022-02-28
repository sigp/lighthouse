use lighthouse_network::{rpc::BlocksByRootRequest, PeerId};
use ssz_types::VariableList;
use store::{EthSpec, Hash256, SignedBeaconBlock};

use crate::sync::{
    manager::{Id, SLOT_IMPORT_TOLERANCE},
    network_context::SyncNetworkContext,
};

use super::single_block_lookup::SingleBlockRequest;

/// How many attempts we try to find a parent of a block before we give up trying .
const PARENT_FAIL_TOLERANCE: usize = 5;
/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

/// Maintains a sequential list of parents to lookup and the lookup's current state.
pub(crate) struct ParentLookup<T: EthSpec> {
    /// The root of the block triggering this parent request.
    chain_hash: Hash256,

    /// The blocks that have currently been downloaded.
    downloaded_blocks: Vec<SignedBeaconBlock<T>>,

    /// The number of failed attempts to retrieve a parent block. If too many attempts occur, this
    /// lookup is failed and rejected.
    failed_attempts: usize,

    /// The peer who last submitted a block. If the chain ends or fails, this is the peer that is
    /// penalized.
    last_submitted_peer: PeerId,

    /// The state of the parent lookup.
    state: State,
}

enum State {
    AwaitingDownload,
    Downloading(Id, SingleBlockRequest),
    Processing,
}

pub enum RequestError {
    TooManyFailures,
    ChainTooLong,
    SendRequestFailed(&'static str),
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

    pub fn new(block: SignedBeaconBlock<T>, peer_id: PeerId) -> Self {
        Self {
            chain_hash: block.canonical_root(),
            downloaded_blocks: vec![block],
            failed_attempts: 0,
            last_submitted_peer: peer_id,
            state: State::AwaitingDownload,
        }
    }

    pub fn request_parent(&mut self, cx: &mut SyncNetworkContext<T>) -> Result<(), RequestError> {
        // check to make sure this request hasn't failed
        if self.failed_attempts >= PARENT_FAIL_TOLERANCE {
            return Err(RequestError::TooManyFailures);
        }
        if self.downloaded_blocks.len() >= PARENT_DEPTH_TOLERANCE {
            return Err(RequestError::ChainTooLong);
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
                self.state = State::Downloading(request_id, SingleBlockRequest::new(parent_hash));
            }
            Err(reason) => return Err(RequestError::SendRequestFailed(reason)),
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
            other => {
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
}
