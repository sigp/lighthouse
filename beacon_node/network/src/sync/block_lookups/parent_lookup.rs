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
    /// Id of the last parent request. TODO: docs
    state: State,
    /// Peers that should have these blocks.
    available_peers: HashSet<PeerId>,
    /// Number of times we have sent a request for this chain to retry a block.
    failed_attempts: u8,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    AwaitingDownload,
    Downloading(Id),
    Processing,
}
pub enum VerifyError {
    RootMismatch,
    NoBlockReturned,
    ExtraBlocksReturned,
    PreviousFailure { parent_root: Hash256 },
}

impl From<super::single_block_lookup::VerifyError> for VerifyError {
    fn from(e: super::single_block_lookup::VerifyError) -> Self {
        use super::single_block_lookup::VerifyError as E;
        match e {
            E::RootMismatch => VerifyError::RootMismatch,
            E::NoBlockReturned => VerifyError::NoBlockReturned,
            E::ExtraBlocksReturned => VerifyError::ExtraBlocksReturned,
        }
    }
}

enum RequestError {
    SendFailed(&'static str),
    ChainTooLong,
    TooManyAttempts,
}

impl<T: EthSpec> ParentLookup<T> {
    pub fn contains_block(&self, block: &SignedBeaconBlock<T>) -> bool {
        self.downloaded_blocks
            .iter()
            .any(|d_block| d_block == block)
    }

    pub fn new(block: SignedBeaconBlock<T>, peer_id: PeerId) -> Self {
        let current_parent_request = SingleBlockRequest::new(block.parent_root(), peer_id);

        Self {
            chain_hash: block.canonical_root(),
            downloaded_blocks: vec![block],
            current_parent_request,
            state: State::AwaitingDownload,
            available_peers: HashSet::from([peer_id]),
            failed_attempts: 0,
        }
    }

    /// Attempts to request the next unknown parent. If the request fails, it should be removed.
    pub fn request_parent(&mut self, cx: &mut SyncNetworkContext<T>) -> Result<Id, RequestError> {
        // check to make sure this request hasn't failed
        if self.failed_attempts >= PARENT_FAIL_TOLERANCE {
            return Err(RequestError::TooManyAttempts);
        }
        if self.downloaded_blocks.len() >= PARENT_DEPTH_TOLERANCE {
            return Err(RequestError::ChainTooLong);
        }

        debug_assert_eq!(self.state, State::AwaitingDownload);

        let (peer_id, request) = self.current_parent_request.block_request();

        match cx.parent_lookup_request(peer_id, request) {
            Ok(request_id) => {
                self.state = State::Downloading(request_id);
                Ok(request_id)
            }
            Err(reason) => {
                self.failed_attempts += 1;
                Err(RequestError::SendFailed(reason))
            }
        }
    }

    pub fn add_block(&mut self, block: SignedBeaconBlock<T>) {
        let next_parent = block.parent_root();
        self.downloaded_blocks.push(block);
        self.state =  State::AwaitingDownload;
        self.current_parent_request.hash = next_parent;
        self.current_par

    }

    pub fn pending_response(&self, req_id: Id) -> bool {
        match &self.state {
            State::Downloading(id) => req_id == *id,
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
        block: Option<Box<SignedBeaconBlock<T>>>,
        failed_chains: &lru_cache::LRUCache<Hash256>,
    ) -> Result<Option<Box<SignedBeaconBlock<T>>>, VerifyError> {
        debug_assert!(matches!(self.state, State::Downloading { .. }));

        let block = match self.current_parent_request.verify_block(block) {
            Ok(block) => block,
            Err(e) => {
                self.failed_attempts += 1;
                self.state = State::AwaitingDownload;
                return Err(e.into());
            }
        };

        // check if the parent of this block isn't in the failed cache. If it is, this chain should
        // be dropped and the peer downscored.
        if let Some(parent_root) = block.as_ref().map(|block| block.parent_root()) {
            if failed_chains.contains(&parent_root) {
                self.failed_attempts += 1;
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
    pub fn failed_attempts(&self) -> u8 {
        self.failed_attempts
    }
}
