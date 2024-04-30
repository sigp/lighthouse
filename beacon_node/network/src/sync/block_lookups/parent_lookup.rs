use super::common::LookupType;
use super::single_block_lookup::{LookupRequestError, SingleBlockLookup};
use super::{DownloadedBlock, PeerId};
use crate::sync::{manager::SLOT_IMPORT_TOLERANCE, network_context::SyncNetworkContext};
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::data_availability_checker::{ChildComponents, DataAvailabilityChecker};
use beacon_chain::BeaconChainTypes;
use std::collections::VecDeque;
use std::sync::Arc;
use store::Hash256;

/// How many attempts we try to find a parent of a block before we give up trying.
pub(crate) const PARENT_FAIL_TOLERANCE: u8 = 5;
/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
pub(crate) const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

/// Maintains a sequential list of parents to lookup and the lookup's current state.
pub(crate) struct ParentLookup<T: BeaconChainTypes> {
    /// The root of the block triggering this parent request.
    chain_hash: Hash256,
    /// The blocks that have currently been downloaded.
    downloaded_blocks: Vec<DownloadedBlock<T::EthSpec>>,
    /// Request of the last parent.
    pub current_parent_request: SingleBlockLookup<T>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RequestError {
    SendFailed(&'static str),
    ChainTooLong,
    /// We witnessed too many failures trying to complete this parent lookup.
    TooManyAttempts {
        /// We received more failures trying to process the blocks than downloading them
        /// from peers.
        cannot_process: bool,
    },
    NoPeers,
    BadState(String),
}

impl<T: BeaconChainTypes> ParentLookup<T> {
    pub fn new(
        block_root: Hash256,
        parent_root: Hash256,
        peer_id: PeerId,
        da_checker: Arc<DataAvailabilityChecker<T>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Self {
        let current_parent_request = SingleBlockLookup::new(
            parent_root,
            Some(ChildComponents::empty(block_root)),
            &[peer_id],
            da_checker,
            cx.next_id(),
            LookupType::Parent,
        );

        Self {
            chain_hash: block_root,
            downloaded_blocks: vec![],
            current_parent_request,
        }
    }

    pub fn contains_block(&self, block_root: &Hash256) -> bool {
        self.downloaded_blocks
            .iter()
            .any(|(root, _d_block)| root == block_root)
    }

    pub fn is_for_block(&self, block_root: Hash256) -> bool {
        self.current_parent_request.is_for_block(block_root)
    }

    /// Attempts to request the next unknown parent. If the request fails, it should be removed.
    pub fn request_parent(&mut self, cx: &mut SyncNetworkContext<T>) -> Result<(), RequestError> {
        // check to make sure this request hasn't failed
        if self.downloaded_blocks.len() + 1 >= PARENT_DEPTH_TOLERANCE {
            return Err(RequestError::ChainTooLong);
        }

        self.current_parent_request
            .request_block_and_blobs(cx)
            .map_err(Into::into)
    }

    pub fn check_peer_disconnected(&mut self, peer_id: &PeerId) -> Result<(), ()> {
        self.current_parent_request
            .block_request_state
            .state
            .check_peer_disconnected(peer_id)
            .and_then(|()| {
                self.current_parent_request
                    .blob_request_state
                    .state
                    .check_peer_disconnected(peer_id)
            })
    }

    pub fn add_unknown_parent_block(&mut self, block: RpcBlock<T::EthSpec>) {
        let next_parent = block.parent_root();
        // Cache the block.
        let current_root = self.current_parent_request.block_root();
        self.downloaded_blocks.push((current_root, block));

        // Update the parent request.
        self.current_parent_request
            .update_requested_parent_block(next_parent)
    }

    pub fn block_processing_peer(&self) -> Result<PeerId, String> {
        self.current_parent_request
            .block_request_state
            .state
            .processing_peer()
    }

    pub fn blob_processing_peer(&self) -> Result<PeerId, String> {
        self.current_parent_request
            .blob_request_state
            .state
            .processing_peer()
    }

    /// Consumes the parent request and destructures it into it's parts.
    #[allow(clippy::type_complexity)]
    pub fn parts_for_processing(
        self,
    ) -> (
        Hash256,
        VecDeque<RpcBlock<T::EthSpec>>,
        Vec<Hash256>,
        SingleBlockLookup<T>,
    ) {
        let ParentLookup {
            chain_hash,
            downloaded_blocks,
            current_parent_request,
        } = self;
        let block_count = downloaded_blocks.len();
        let mut blocks = VecDeque::with_capacity(block_count);
        let mut hashes = Vec::with_capacity(block_count);
        for (hash, block) in downloaded_blocks.into_iter() {
            blocks.push_back(block);
            hashes.push(hash);
        }
        (chain_hash, blocks, hashes, current_parent_request)
    }

    /// Get the parent lookup's chain hash.
    pub fn chain_hash(&self) -> Hash256 {
        self.chain_hash
    }

    pub fn processing_failed(&mut self) {
        self.current_parent_request
            .block_request_state
            .state
            .on_processing_failure();
        self.current_parent_request
            .blob_request_state
            .state
            .on_processing_failure();
        if let Some(components) = self.current_parent_request.child_components.as_mut() {
            components.downloaded_block = None;
            components.downloaded_blobs = <_>::default();
        }
    }

    pub fn add_peer(&mut self, peer: PeerId) {
        self.current_parent_request.add_peer(peer)
    }

    /// Adds a list of peers to the parent request.
    pub fn add_peers(&mut self, peers: &[PeerId]) {
        self.current_parent_request.add_peers(peers)
    }

    pub fn all_used_peers(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.current_parent_request.all_used_peers()
    }
}

impl From<LookupRequestError> for RequestError {
    fn from(e: LookupRequestError) -> Self {
        use LookupRequestError as E;
        match e {
            E::TooManyAttempts { cannot_process } => {
                RequestError::TooManyAttempts { cannot_process }
            }
            E::NoPeers => RequestError::NoPeers,
            E::SendFailed(msg) => RequestError::SendFailed(msg),
            E::BadState(msg) => RequestError::BadState(msg),
        }
    }
}

impl<T: BeaconChainTypes> slog::KV for ParentLookup<T> {
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
            RequestError::TooManyAttempts { cannot_process } if *cannot_process => {
                "too_many_processing_attempts"
            }
            RequestError::TooManyAttempts { cannot_process: _ } => "too_many_downloading_attempts",
            RequestError::NoPeers => "no_peers",
            RequestError::BadState(..) => "bad_state",
        }
    }
}
