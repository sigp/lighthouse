use lighthouse_network::PeerId;
use store::{EthSpec, Hash256, SignedBeaconBlock};
use strum::AsStaticStr;

use crate::sync::{
    manager::{Id, SLOT_IMPORT_TOLERANCE},
    network_context::SyncNetworkContext,
};

use super::single_block_lookup::{self, SingleBlockRequest};

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
    current_parent_request: SingleBlockRequest<PARENT_FAIL_TOLERANCE>,
    /// Id of the last parent request.
    current_parent_request_id: Option<Id>,
}

#[derive(Debug, PartialEq, Eq, AsStaticStr)]
pub enum VerifyError {
    RootMismatch,
    NoBlockReturned,
    ExtraBlocksReturned,
    PreviousFailure { parent_root: Hash256 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    SendFailed(&'static str),
    ChainTooLong,
    TooManyAttempts,
    NoPeers,
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
            current_parent_request_id: None,
        }
    }

    /// Attempts to request the next unknown parent. If the request fails, it should be removed.
    pub fn request_parent(&mut self, cx: &mut SyncNetworkContext<T>) -> Result<(), RequestError> {
        // check to make sure this request hasn't failed
        if self.downloaded_blocks.len() >= PARENT_DEPTH_TOLERANCE {
            return Err(RequestError::ChainTooLong);
        }

        let (peer_id, request) = self.current_parent_request.request_block()?;
        match cx.parent_lookup_request(peer_id, request) {
            Ok(request_id) => {
                self.current_parent_request_id = Some(request_id);
                Ok(())
            }
            Err(reason) => {
                self.current_parent_request_id = None;
                Err(RequestError::SendFailed(reason))
            }
        }
    }

    pub fn check_peer_disconnected(&mut self, peer_id: &PeerId) -> Result<(), ()> {
        self.current_parent_request.check_peer_disconnected(peer_id)
    }

    pub fn add_block(&mut self, block: SignedBeaconBlock<T>) {
        let next_parent = block.parent_root();
        self.downloaded_blocks.push(block);
        self.current_parent_request.hash = next_parent;
        self.current_parent_request.state = single_block_lookup::State::AwaitingDownload;
        self.current_parent_request_id = None;
    }

    pub fn pending_response(&self, req_id: Id) -> bool {
        self.current_parent_request_id == Some(req_id)
    }

    /// Get the parent lookup's chain hash.
    pub fn chain_hash(&self) -> Hash256 {
        self.chain_hash
    }

    pub fn download_failed(&mut self) {
        self.current_parent_request.register_failure();
        self.current_parent_request_id = None;
    }

    pub fn chain_blocks(&mut self) -> Vec<SignedBeaconBlock<T>> {
        std::mem::take(&mut self.downloaded_blocks)
    }

    /// Verifies that the received block is what we requested. If so, parent lookup now waits for
    /// the processing result of the block.
    pub fn verify_block(
        &mut self,
        block: Option<Box<SignedBeaconBlock<T>>>,
        failed_chains: &lru_cache::LRUCache<Hash256>,
    ) -> Result<Option<Box<SignedBeaconBlock<T>>>, VerifyError> {
        let block = self.current_parent_request.verify_block(block)?;

        // check if the parent of this block isn't in the failed cache. If it is, this chain should
        // be dropped and the peer downscored.
        if let Some(parent_root) = block.as_ref().map(|block| block.parent_root()) {
            if failed_chains.contains(&parent_root) {
                self.current_parent_request.register_failure();
                self.current_parent_request_id = None;
                return Err(VerifyError::PreviousFailure { parent_root });
            }
        }

        Ok(block)
    }

    pub fn get_processing_peer(&self, chain_hash: Hash256) -> Option<PeerId> {
        if self.chain_hash == chain_hash {
            return self.current_parent_request.processing_peer().ok();
        }
        None
    }

    #[cfg(test)]
    pub fn failed_attempts(&self) -> u8 {
        self.current_parent_request.failed_attempts
    }

    pub fn add_peer(&mut self, block_root: &Hash256, peer_id: &PeerId) -> bool {
        self.current_parent_request.add_peer(block_root, peer_id)
    }

    pub fn used_peers(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.current_parent_request.used_peers.iter()
    }
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

impl From<super::single_block_lookup::LookupRequestError> for RequestError {
    fn from(e: super::single_block_lookup::LookupRequestError) -> Self {
        use super::single_block_lookup::LookupRequestError as E;
        match e {
            E::TooManyAttempts => RequestError::TooManyAttempts,
            E::NoPeers => RequestError::NoPeers,
        }
    }
}

impl<T: EthSpec> slog::KV for ParentLookup<T> {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_arguments("chain_hash", &format_args!("{}", self.chain_hash))?;
        slog::Value::serialize(&self.current_parent_request, record, "parent", serializer)?;
        serializer.emit_usize("downloaded_blocks", self.downloaded_blocks.len())?;
        slog::Result::Ok(())
    }
}

impl RequestError {
    pub fn as_static(&self) -> &'static str {
        match self {
            RequestError::SendFailed(e) => e,
            RequestError::ChainTooLong => "chain_too_long",
            RequestError::TooManyAttempts => "too_many_attempts",
            RequestError::NoPeers => "no_peers",
        }
    }
}
