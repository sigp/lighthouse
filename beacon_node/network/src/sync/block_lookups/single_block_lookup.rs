use super::{PeerShouldHave, ResponseType};
use crate::sync::block_lookups::parent_lookup::RequestError::SendFailed;
use crate::sync::block_lookups::parent_lookup::PARENT_FAIL_TOLERANCE;
use crate::sync::block_lookups::{
    BlockLookups, Id, LookupType, RootBlobsTuple, RootBlockTuple, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS,
};
use crate::sync::manager::BlockProcessType;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::data_availability_checker::DataAvailabilityChecker;
use beacon_chain::{get_block_root, BeaconChainTypes};
use itertools::Itertools;
use lighthouse_network::rpc::methods::BlobsByRootRequest;
use lighthouse_network::{rpc::BlocksByRootRequest, PeerId};
use rand::seq::IteratorRandom;
use slog::{debug, trace, Logger};
use ssz_types::VariableList;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::ops::IndexMut;
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use strum::IntoStaticStr;
use types::blob_sidecar::{BlobIdentifier, FixedBlobSidecarList};
use types::{BlobSidecar, EthSpec, SignedBeaconBlock};

pub trait Lookup {
    const MAX_ATTEMPTS: u8;
    fn lookup_type() -> LookupType;
    fn max_attempts() -> u8 {
        Self::MAX_ATTEMPTS
    }
}

pub struct Parent;
pub struct Current;

impl Lookup for Parent {
    const MAX_ATTEMPTS: u8 = PARENT_FAIL_TOLERANCE;
    fn lookup_type() -> LookupType {
        LookupType::Parent
    }
}

impl Lookup for Current {
    const MAX_ATTEMPTS: u8 = SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS;
    fn lookup_type() -> LookupType {
        LookupType::Current
    }
}

pub struct SingleBlockLookup<L: Lookup, T: BeaconChainTypes> {
    pub id: Id,
    pub block_request_state: BlockRequestState<L>,
    pub blob_request_state: BlobRequestState<L, T::EthSpec>,
    pub da_checker: Arc<DataAvailabilityChecker<T>>,
    /// Only necessary for requests triggered by an `UnknownBlockParent` or `UnknownBlockParent` because any
    /// blocks or blobs without parents won't hit the data availability cache.
    pub unknown_parent_components: Option<UnknownParentComponents<T::EthSpec>>,
    /// We may want to delay the actual request trigger to give us a chance to receive all block
    /// components over gossip.
    pub triggered: bool,
}

// generic across block + blob
pub trait RequestState<L: Lookup, T: BeaconChainTypes> {
    type RequestType;
    type ResponseType;
    type ReconstructedResponseType;
    type VerifiedResponseType;

    // response verify
    fn response_type() -> ResponseType;
    fn get_parent_root(verified_response: &Self::VerifiedResponseType) -> Option<Hash256>;
    fn request_state_mut(request: &mut SingleBlockLookup<L, T>) -> &mut Self;
    fn add_to_parent_components(
        verified_response: Self::VerifiedResponseType,
        components: &mut UnknownParentComponents<T::EthSpec>,
    );
    fn verified_to_reconstructed(
        verified: Self::VerifiedResponseType,
    ) -> Self::ReconstructedResponseType;
    fn send_for_processing(
        id: Id,
        bl: &mut BlockLookups<T>,
        block_root: Hash256,
        verified: Self::ReconstructedResponseType,
        duration: Duration,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), ()>;

    fn get_state(&self) -> &SingleLookupRequestState;
    fn get_state_mut(&mut self) -> &mut SingleLookupRequestState;
    fn processing_peer(&self) -> Result<PeerShouldHave, ()> {
        self.get_state().processing_peer()
    }
    fn downloading_peer(&self) -> Result<PeerShouldHave, ()> {
        self.get_state().peer()
    }
    fn set_component_processed(&mut self) {
        self.get_state_mut().component_processed = true;
    }
    fn new_request(&self) -> Self::RequestType;
    fn max_attempts() -> u8;
    fn retry_request(
        id: Id,
        cx: &SyncNetworkContext<T>,
        peer_id: PeerId,
        request: Self::RequestType,
    ) -> Result<(), &'static str>;
    fn verify_response(
        &mut self,
        expected_block_root: Hash256,
        response: Option<Self::ResponseType>,
    ) -> Result<Option<(Hash256, Self::VerifiedResponseType)>, LookupVerifyError> {
        let request_state = self.get_state_mut();
        match request_state.state {
            State::AwaitingDownload => {
                request_state.register_failure_downloading();
                Err(LookupVerifyError::ExtraBlocksReturned)
            }
            State::Downloading { peer_id } => {
                self.verify_response_inner(expected_block_root, response, peer_id)
            }
            State::Processing { peer_id: _ } => match response {
                Some(_) => {
                    // We sent the block for processing and received an extra block.
                    request_state.register_failure_downloading();
                    Err(LookupVerifyError::ExtraBlocksReturned)
                }
                None => {
                    // This is simply the stream termination and we are already processing the
                    // block
                    Ok(None)
                }
            },
        }
    }
    fn verify_response_inner(
        &mut self,
        expected_block_root: Hash256,
        response: Option<Self::ResponseType>,
        peer_id: PeerShouldHave,
    ) -> Result<Option<(Hash256, Self::VerifiedResponseType)>, LookupVerifyError>;

    fn retry_request_after_failure(
        &mut self,
        id: Id,
        cx: &SyncNetworkContext<T>,
        log: &Logger,
    ) -> Result<(), ()> {
        if let Err(e) = self
            .build_request()
            .map_err(Into::into)
            .and_then(|(peer_id, request)| Self::retry_request(id, cx, peer_id, request))
        {
            //TODO(sean) pass this error up? check downloaded contents prior to retry-ing?
            debug!(log, "Single block lookup failed";
                    "error" => ?e,
            );
            return Err(());
        }
        Ok(())
    }
    fn build_request(&mut self) -> Result<(PeerId, Self::RequestType), LookupRequestError> {
        debug_assert!(matches!(self.get_state().state, State::AwaitingDownload));
        self.too_many_attempts()?;
        let peer = self.get_peer()?;
        let request = self.new_request();
        Ok((peer, request))
    }
    fn too_many_attempts(&self) -> Result<(), LookupRequestError> {
        let max_attempts = Self::max_attempts();
        if self.get_state().failed_attempts() >= max_attempts {
            Err(LookupRequestError::TooManyAttempts {
                cannot_process: self.cannot_process(),
            })
        } else {
            Ok(())
        }
    }
    fn cannot_process(&self) -> bool {
        let request_state = self.get_state();
        request_state.failed_processing >= request_state.failed_downloading
    }
    fn get_peer(&mut self) -> Result<PeerId, LookupRequestError> {
        let mut request_state = self.get_state_mut();
        let Some(peer_id) =         request_state
            .available_peers
            .iter()
            .choose(&mut rand::thread_rng())
            .copied()
            .map(PeerShouldHave::BlockAndBlobs).or(request_state
            .potential_peers
            .iter()
            .choose(&mut rand::thread_rng())
            .copied()
            .map(PeerShouldHave::Neither)) else {
           return Err(LookupRequestError::NoPeers);
        };
        request_state.used_peers.insert(peer_id.to_peer_id());
        request_state.state = State::Downloading { peer_id };
        Ok(peer_id.to_peer_id())
    }
    fn check_peer_disconnected(&mut self, peer: &PeerId) -> Result<(), ()> {
        self.get_state_mut().check_peer_disconnected(peer)
    }
    fn remove_if_useless(&mut self, peer: &PeerId) {
        self.get_state_mut().remove_peer_if_useless(peer)
    }
    fn downloading(&self) -> bool {
        matches!(self.get_state().state, State::Downloading { .. })
    }
    fn register_failure_downloading(&mut self) {
        self.get_state_mut().register_failure_downloading()
    }
}

impl<L: Lookup, T: BeaconChainTypes> RequestState<L, T> for BlockRequestState<L> {
    type RequestType = BlocksByRootRequest;
    type ResponseType = Arc<SignedBeaconBlock<T::EthSpec>>;
    type ReconstructedResponseType = RpcBlock<T::EthSpec>;
    type VerifiedResponseType = Arc<SignedBeaconBlock<T::EthSpec>>;

    // response verify
    fn response_type() -> ResponseType {
        ResponseType::Block
    }

    fn get_parent_root(verified_response: &Arc<SignedBeaconBlock<T::EthSpec>>) -> Option<Hash256> {
        Some(verified_response.parent_root())
    }
    fn request_state_mut(request: &mut SingleBlockLookup<L, T>) -> &mut Self {
        &mut request.block_request_state
    }
    fn add_to_parent_components(
        verified_response: Arc<SignedBeaconBlock<T::EthSpec>>,
        components: &mut UnknownParentComponents<T::EthSpec>,
    ) {
        components.add_unknown_parent_block(verified_response);
    }

    fn verified_to_reconstructed(
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> RpcBlock<T::EthSpec> {
        RpcBlock::new_without_blobs(block)
    }

    fn send_for_processing(
        id: Id,
        bl: &mut BlockLookups<T>,
        block_root: Hash256,
        constructed: RpcBlock<T::EthSpec>,
        duration: Duration,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), ()> {
        bl.send_block_for_processing(
            block_root,
            constructed,
            duration,
            BlockProcessType::SingleBlock { id },
            cx,
        )
    }

    fn get_state(&self) -> &SingleLookupRequestState {
        &self.state
    }
    fn get_state_mut(&mut self) -> &mut SingleLookupRequestState {
        &mut self.state
    }
    fn new_request(&self) -> BlocksByRootRequest {
        BlocksByRootRequest::new(VariableList::from(vec![self.requested_block_root]))
    }
    fn max_attempts() -> u8 {
        L::MAX_ATTEMPTS
    }
    fn retry_request(
        id: Id,
        cx: &SyncNetworkContext<T>,
        peer_id: PeerId,
        request: Self::RequestType,
    ) -> Result<(), &'static str> {
        cx.single_block_lookup_request_retry(id, peer_id, request, L::lookup_type())
    }

    fn verify_response_inner(
        &mut self,
        expected_block_root: Hash256,
        response: Option<Self::ResponseType>,
        peer_id: PeerShouldHave,
    ) -> Result<Option<RootBlockTuple<T::EthSpec>>, LookupVerifyError> {
        match response {
            Some(block) => {
                // Compute the block root using this specific function so that we can get timing
                // metrics.
                let block_root = get_block_root(&block);
                if block_root != expected_block_root {
                    // return an error and drop the block
                    // NOTE: we take this is as a download failure to prevent counting the
                    // attempt as a chain failure, but simply a peer failure.
                    self.state.register_failure_downloading();
                    Err(LookupVerifyError::RootMismatch)
                } else {
                    // Return the block for processing.
                    self.state.state = State::Processing { peer_id };
                    Ok(Some((block_root, block)))
                }
            }
            None => {
                if peer_id.should_have_block() {
                    self.state.register_failure_downloading();
                    Err(LookupVerifyError::NoBlockReturned)
                } else {
                    self.state.state = State::AwaitingDownload;
                    Err(LookupVerifyError::BenignFailure)
                }
            }
        }
    }
}

impl<L: Lookup, T: BeaconChainTypes> RequestState<L, T> for BlobRequestState<L, T::EthSpec> {
    type RequestType = BlobsByRootRequest;
    type ResponseType = Arc<BlobSidecar<T::EthSpec>>;
    type ReconstructedResponseType = FixedBlobSidecarList<T::EthSpec>;
    type VerifiedResponseType = FixedBlobSidecarList<T::EthSpec>;

    // response verify
    fn response_type() -> ResponseType {
        ResponseType::Blob
    }

    fn get_parent_root(verified_response: &FixedBlobSidecarList<T::EthSpec>) -> Option<Hash256> {
        verified_response
            .into_iter()
            .filter_map(|blob| blob.as_ref())
            .map(|blob| blob.block_parent_root)
            .next()
    }
    fn request_state_mut(request: &mut SingleBlockLookup<L, T>) -> &mut Self {
        &mut request.blob_request_state
    }
    fn add_to_parent_components(
        verified_response: FixedBlobSidecarList<T::EthSpec>,
        components: &mut UnknownParentComponents<T::EthSpec>,
    ) {
        components.add_unknown_parent_blobs(verified_response);
    }
    fn verified_to_reconstructed(
        blobs: FixedBlobSidecarList<T::EthSpec>,
    ) -> FixedBlobSidecarList<T::EthSpec> {
        blobs
    }

    fn send_for_processing(
        id: Id,
        bl: &mut BlockLookups<T>,
        block_root: Hash256,
        verified: FixedBlobSidecarList<T::EthSpec>,
        duration: Duration,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), ()> {
        bl.send_blobs_for_processing(
            block_root,
            verified,
            duration,
            BlockProcessType::SingleBlob { id },
            cx,
        )
    }

    fn get_state(&self) -> &SingleLookupRequestState {
        &self.state
    }
    fn get_state_mut(&mut self) -> &mut SingleLookupRequestState {
        &mut self.state
    }
    fn new_request(&self) -> BlobsByRootRequest {
        BlobsByRootRequest {
            blob_ids: VariableList::from(self.requested_ids.clone()),
        }
    }
    fn max_attempts() -> u8 {
        L::MAX_ATTEMPTS
    }
    fn retry_request(
        id: Id,
        cx: &SyncNetworkContext<T>,
        peer_id: PeerId,
        request: Self::RequestType,
    ) -> Result<(), &'static str> {
        cx.single_blob_lookup_request_retry(id, peer_id, request, L::lookup_type())
    }

    fn verify_response_inner(
        &mut self,
        expected_block_root: Hash256,
        blob: Option<Self::ResponseType>,
        peer_id: PeerShouldHave,
    ) -> Result<Option<RootBlobsTuple<T::EthSpec>>, LookupVerifyError> {
        match blob {
            Some(blob) => {
                let received_id = blob.id();
                if !self.requested_ids.contains(&received_id) {
                    self.state.register_failure_downloading();
                    Err(LookupVerifyError::UnrequestedBlobId)
                } else {
                    // State should remain downloading until we receive the stream terminator.
                    self.requested_ids.retain(|id| *id != received_id);
                    let blob_index = blob.index;

                    if blob_index >= T::EthSpec::max_blobs_per_block() as u64 {
                        return Err(LookupVerifyError::InvalidIndex(blob.index));
                    }
                    *self.blob_download_queue.index_mut(blob_index as usize) = Some(blob);
                    Ok(None)
                }
            }
            None => {
                self.state.state = State::Processing { peer_id };
                let blobs = std::mem::take(&mut self.blob_download_queue);
                Ok(Some((expected_block_root, blobs)))
            }
        }
    }
}

pub struct BlobRequestState<L: Lookup, T: EthSpec> {
    pub requested_ids: Vec<BlobIdentifier>,
    /// Where we store blobs until we receive the stream terminator.
    pub blob_download_queue: FixedBlobSidecarList<T>,
    pub state: SingleLookupRequestState,
    _phantom: PhantomData<L>,
}

impl<L: Lookup, T: EthSpec> BlobRequestState<L, T> {
    pub fn new(peer_source: &[PeerShouldHave]) -> Self {
        Self {
            requested_ids: <_>::default(),
            blob_download_queue: <_>::default(),
            state: SingleLookupRequestState::new(peer_source),
            _phantom: PhantomData::default(),
        }
    }
}

pub struct BlockRequestState<L: Lookup> {
    pub requested_block_root: Hash256,
    pub state: SingleLookupRequestState,
    _phantom: PhantomData<L>,
}

impl<L: Lookup> BlockRequestState<L> {
    pub fn new(block_root: Hash256, peers: &[PeerShouldHave]) -> Self {
        Self {
            requested_block_root: block_root,
            state: SingleLookupRequestState::new(peers),
            _phantom: PhantomData::default(),
        }
    }
}

impl<L: Lookup, T: BeaconChainTypes> SingleBlockLookup<L, T> {
    pub(crate) fn block_already_downloaded(&self) -> bool {
        if let Some(components) = self.unknown_parent_components.as_ref() {
            components.downloaded_block.is_some()
        } else {
            self.da_checker
                .has_block(&self.block_request_state.requested_block_root)
        }
    }

    pub(crate) fn blobs_already_downloaded(&mut self) -> bool {
        self.update_blobs_request();
        self.blob_request_state.requested_ids.is_empty()
    }
}

/// For requests triggered by an `UnknownBlockParent` or `UnknownBlockParent`, this struct
/// is used to cache components as they are sent to the networking layer. We can't use the
/// data availability cache currently because any blocks or blobs without parents won't hit
/// won't pass validation and therefore won't make it into the cache.
#[derive(Default)]
pub struct UnknownParentComponents<E: EthSpec> {
    pub downloaded_block: Option<Arc<SignedBeaconBlock<E>>>,
    pub downloaded_blobs: FixedBlobSidecarList<E>,
}

impl<E: EthSpec> From<RpcBlock<E>> for UnknownParentComponents<E> {
    fn from(value: RpcBlock<E>) -> Self {
        let (block, blobs) = value.deconstruct();
        let fixed_blobs = blobs.map(|blobs| {
            FixedBlobSidecarList::from(blobs.into_iter().map(Some).collect::<Vec<_>>())
        });
        Self::new(Some(block), fixed_blobs)
    }
}

impl<E: EthSpec> UnknownParentComponents<E> {
    pub fn new(
        block: Option<Arc<SignedBeaconBlock<E>>>,
        blobs: Option<FixedBlobSidecarList<E>>,
    ) -> Self {
        Self {
            downloaded_block: block,
            downloaded_blobs: blobs.unwrap_or_default(),
        }
    }
    pub fn add_unknown_parent_block(&mut self, block: Arc<SignedBeaconBlock<E>>) {
        self.downloaded_block = Some(block);
    }
    pub fn add_unknown_parent_blobs(&mut self, blobs: FixedBlobSidecarList<E>) {
        for (index, blob_opt) in self.downloaded_blobs.iter_mut().enumerate() {
            if let Some(Some(downloaded_blob)) = blobs.get(index) {
                *blob_opt = Some(downloaded_blob.clone());
            }
        }
    }
    pub fn downloaded_indices(&self) -> HashSet<usize> {
        self.downloaded_blobs
            .iter()
            .enumerate()
            .filter_map(|(i, blob_opt)| blob_opt.as_ref().map(|_| i))
            .collect::<HashSet<_>>()
    }
}

/// Object representing the state of a single block or blob lookup request.
#[derive(PartialEq, Eq, Debug)]
pub struct SingleLookupRequestState {
    /// State of this request.
    pub state: State,
    /// Peers that should have this block or blob.
    pub available_peers: HashSet<PeerId>,
    /// Peers that mar or may not have this block or blob.
    pub potential_peers: HashSet<PeerId>,
    /// Peers from which we have requested this block.
    pub used_peers: HashSet<PeerId>,
    /// How many times have we attempted to process this block or blob.
    failed_processing: u8,
    /// How many times have we attempted to download this block or blob.
    failed_downloading: u8,
    pub component_processed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    AwaitingDownload,
    Downloading { peer_id: PeerShouldHave },
    Processing { peer_id: PeerShouldHave },
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupVerifyError {
    RootMismatch,
    NoBlockReturned,
    ExtraBlocksReturned,
    UnrequestedBlobId,
    ExtraBlobsReturned,
    NotEnoughBlobsReturned,
    InvalidIndex(u64),
    /// We don't have enough information to know
    /// whether the peer is at fault or simply missed
    /// what was requested on gossip.
    BenignFailure,
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupRequestError {
    /// Too many failed attempts
    TooManyAttempts {
        /// The failed attempts were primarily due to processing failures.
        cannot_process: bool,
    },
    NoPeers,
    SendFailed(&'static str),
    AlreadyDownloaded,
}

impl<L: Lookup, T: BeaconChainTypes> SingleBlockLookup<L, T> {
    pub fn new(
        requested_block_root: Hash256,
        unknown_parent_components: Option<UnknownParentComponents<T::EthSpec>>,
        peers: &[PeerShouldHave],
        da_checker: Arc<DataAvailabilityChecker<T>>,
        cx: &SyncNetworkContext<T>,
    ) -> Self {
        Self {
            id: cx.next_id(),
            block_request_state: BlockRequestState::new(requested_block_root, peers),
            blob_request_state: BlobRequestState::new(peers),
            da_checker,
            unknown_parent_components,
            triggered: false,
        }
    }

    pub fn is_for_block(&self, block_root: Hash256) -> bool {
        self.block_request_state.requested_block_root == block_root
    }

    /// Send the necessary request for blobs and blocks and update `self.id` with the latest
    /// request `Id`s. This will return `Err(())` if neither the block nor blob request could be made
    /// or are no longer required.
    pub fn request_block_and_blobs(
        &mut self,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        let block_root = self.block_request_state.requested_block_root;
        if self.block_already_downloaded() && self.blobs_already_downloaded() {
            // drop lookup
            trace!(cx.log, "Lookup request already completed"; "block_root"=> ?block_root);
            return Err(LookupRequestError::AlreadyDownloaded);
        }

        let (block_peer_id, block_request) =
            match <BlockRequestState<L> as RequestState<L, T>>::build_request(
                &mut self.block_request_state,
            ) {
                Ok(opt) => opt,
                Err(e) => {
                    // drop lookup
                    debug!(cx.log,
                        "Lookup request block error, dropping lookup";
                        "block_root"=> ?block_root,
                        "error"=> ?e
                    );
                    return Err(e);
                }
            };

        let (blob_peer_id, blob_request) = match <BlobRequestState<
            L,
            <T as BeaconChainTypes>::EthSpec,
        > as RequestState<L, T>>::build_request(
            &mut self.blob_request_state
        ) {
            Ok(opt) => opt,
            Err(e) => {
                // drop lookup
                debug!(cx.log,
                    "Lookup request blob error, dropping lookup";
                    "block_root"=> ?block_root,
                    "error"=> ?e
                );
                return Err(e);
            }
        };

        cx.single_lookup_request(
            self.id,
            block_peer_id,
            block_request,
            blob_peer_id,
            blob_request,
            L::lookup_type(),
        )
        .map_err(LookupRequestError::SendFailed)?;
        Ok(())
    }

    pub fn update_blobs_request(&mut self) {
        self.blob_request_state.requested_ids = if let Some(components) =
            self.unknown_parent_components.as_ref()
        {
            let blobs = components.downloaded_indices();
            self.da_checker
                .get_missing_blob_ids(
                    self.block_request_state.requested_block_root,
                    components.downloaded_block.as_ref(),
                    Some(blobs),
                )
                .unwrap_or_default()
        } else {
            self.da_checker
                .get_missing_blob_ids_checking_cache(self.block_request_state.requested_block_root)
                .unwrap_or_default()
        };
    }

    pub fn get_downloaded_block(&mut self) -> Option<RpcBlock<T::EthSpec>> {
        self.unknown_parent_components
            .as_mut()
            .and_then(|components| {
                let downloaded_block = components.downloaded_block.as_ref();
                let downloaded_indices = components.downloaded_indices();
                let missing_ids = self.da_checker.get_missing_blob_ids(
                    self.block_request_state.requested_block_root,
                    downloaded_block,
                    Some(downloaded_indices),
                );
                let download_complete =
                    missing_ids.map_or(true, |missing_ids| missing_ids.is_empty());
                if download_complete {
                    let UnknownParentComponents {
                        downloaded_block,
                        downloaded_blobs,
                    } = components;
                    downloaded_block.as_ref().and_then(|block| {
                        //TODO(sean) figure out how to properly deal with a consistency error here,
                        // should we downscore the peer sending blobs?
                        let blobs = std::mem::take(downloaded_blobs);
                        let filtered = blobs
                            .into_iter()
                            .filter_map(|b| b.clone())
                            .collect::<Vec<_>>();
                        let blobs = VariableList::from(filtered);
                        RpcBlock::new(block.clone(), Some(blobs)).ok()
                    })
                } else {
                    None
                }
            })
    }

    pub fn add_unknown_parent_components(
        &mut self,
        components: UnknownParentComponents<T::EthSpec>,
    ) {
        if let Some(ref mut existing_components) = self.unknown_parent_components {
            let UnknownParentComponents {
                downloaded_block,
                downloaded_blobs,
            } = components;
            if let Some(block) = downloaded_block {
                existing_components.add_unknown_parent_block(block);
            }
            existing_components.add_unknown_parent_blobs(downloaded_blobs);
        } else {
            self.unknown_parent_components = Some(components);
        }
    }
    pub fn add_unknown_parent_block(&mut self, block: Arc<SignedBeaconBlock<T::EthSpec>>) {
        if let Some(ref mut components) = self.unknown_parent_components {
            components.add_unknown_parent_block(block)
        } else {
            self.unknown_parent_components = Some(UnknownParentComponents {
                downloaded_block: Some(block),
                downloaded_blobs: FixedBlobSidecarList::default(),
            })
        }
    }

    pub fn add_unknown_parent_blobs(&mut self, blobs: FixedBlobSidecarList<T::EthSpec>) {
        if let Some(ref mut components) = self.unknown_parent_components {
            components.add_unknown_parent_blobs(blobs)
        } else {
            self.unknown_parent_components = Some(UnknownParentComponents {
                downloaded_block: None,
                downloaded_blobs: blobs,
            })
        }
    }

    pub fn add_peers(&mut self, peers: &[PeerShouldHave]) {
        for peer in peers {
            match peer {
                PeerShouldHave::BlockAndBlobs(peer_id) => {
                    self.block_request_state.state.add_peer(peer_id);
                    self.blob_request_state.state.add_peer(peer_id);
                }
                PeerShouldHave::Neither(peer_id) => {
                    self.block_request_state.state.add_potential_peer(peer_id);
                    self.blob_request_state.state.add_potential_peer(peer_id);
                }
            }
        }
    }

    pub fn both_components_processed(&self) -> bool {
        self.block_request_state.state.component_processed
            && self.blob_request_state.state.component_processed
    }

    pub fn should_remove_disconnected_peer(
        &mut self,
        id: Id,
        peer_id: &PeerId,
        cx: &SyncNetworkContext<T>,
        log: &Logger,
    ) -> bool {
        let useless_block_peer =
            if <BlockRequestState<L> as RequestState<L, T>>::check_peer_disconnected(
                &mut self.block_request_state,
                peer_id,
            )
            .is_err()
            {
                trace!(log, "Single lookup failed on peer disconnection"; "block_root" => ?self.block_request_state.requested_block_root, "response_type" => ?ResponseType::Block);
                self.block_request_state
                    .retry_request_after_failure(id, cx, log)
                    .is_err()
            } else {
                false
            };
        let useless_blob_peer = if <BlobRequestState<L, <T as BeaconChainTypes>::EthSpec> as RequestState<L, T>>::check_peer_disconnected(&mut self
                                                                                                                                                      .blob_request_state, peer_id)
            .is_err()
        {
            trace!(log, "Single lookup failed on peer disconnection"; "block_root" => ?self.block_request_state.requested_block_root, "response_type" => ?ResponseType::Blob);
            self.blob_request_state
                .retry_request_after_failure(id, cx, log)
                .is_err()
        } else {
            false
        };
        useless_block_peer && useless_blob_peer
    }
}

impl SingleLookupRequestState {
    pub fn new(peers: &[PeerShouldHave]) -> Self {
        let mut available_peers = HashSet::default();
        let mut potential_peers = HashSet::default();
        for peer in peers {
            match peer {
                PeerShouldHave::BlockAndBlobs(peer_id) => {
                    available_peers.insert(*peer_id);
                }
                PeerShouldHave::Neither(peer_id) => {
                    potential_peers.insert(*peer_id);
                }
            }
        }
        Self {
            state: State::AwaitingDownload,
            available_peers,
            potential_peers,
            used_peers: HashSet::default(),
            failed_processing: 0,
            failed_downloading: 0,
            component_processed: false,
        }
    }

    /// Registers a failure in processing a block.
    pub fn register_failure_processing(&mut self) {
        self.failed_processing = self.failed_processing.saturating_add(1);
        self.state = State::AwaitingDownload;
    }

    /// Registers a failure in downloading a block. This might be a peer disconnection or a wrong
    /// block.
    pub fn register_failure_downloading(&mut self) {
        self.failed_downloading = self.failed_downloading.saturating_add(1);
        self.state = State::AwaitingDownload;
    }

    /// The total number of failures, whether it be processing or downloading.
    pub fn failed_attempts(&self) -> u8 {
        self.failed_processing + self.failed_downloading
    }

    pub fn add_peer(&mut self, peer_id: &PeerId) {
        self.potential_peers.remove(peer_id);
        self.available_peers.insert(*peer_id);
    }

    pub fn add_potential_peer(&mut self, peer_id: &PeerId) {
        if !self.available_peers.contains(peer_id) {
            self.potential_peers.insert(*peer_id);
        }
    }

    /// If a peer disconnects, this request could be failed. If so, an error is returned
    pub fn check_peer_disconnected(&mut self, dc_peer_id: &PeerId) -> Result<(), ()> {
        self.available_peers.remove(dc_peer_id);
        self.potential_peers.remove(dc_peer_id);
        if let State::Downloading { peer_id } = &self.state {
            if peer_id.as_peer_id() == dc_peer_id {
                // Peer disconnected before providing a block
                self.register_failure_downloading();
                return Err(());
            }
        }
        Ok(())
    }

    pub fn processing_peer(&self) -> Result<PeerShouldHave, ()> {
        if let State::Processing { peer_id } = &self.state {
            Ok(*peer_id)
        } else {
            Err(())
        }
    }

    pub fn peer(&self) -> Result<PeerShouldHave, ()> {
        match &self.state {
            State::Processing { peer_id } => Ok(*peer_id),
            State::Downloading { peer_id } => Ok(*peer_id),
            _ => Err(()),
        }
    }

    pub fn remove_peer_if_useless(&mut self, peer_id: &PeerId) {
        if !self.available_peers.is_empty() || self.potential_peers.len() > 1 {
            self.potential_peers.remove(peer_id);
        }
    }
}

impl<L: Lookup, T: BeaconChainTypes> slog::Value for SingleBlockLookup<L, T> {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("request", key)?;
        serializer.emit_arguments("lookup_type", &format_args!("{:?}", L::lookup_type()))?;
        serializer.emit_arguments(
            "hash",
            &format_args!("{}", self.block_request_state.requested_block_root),
        )?;
        serializer.emit_arguments(
            "blob_ids",
            &format_args!("{:?}", self.blob_request_state.requested_ids),
        )?;
        serializer.emit_arguments(
            "block_request_state.state",
            &format_args!("{:?}", self.block_request_state.state),
        )?;
        serializer.emit_arguments(
            "blob_request_state.state",
            &format_args!("{:?}", self.blob_request_state.state),
        )?;
        slog::Result::Ok(())
    }
}

impl slog::Value for SingleLookupRequestState {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("request_state", key)?;
        match &self.state {
            State::AwaitingDownload => {
                "awaiting_download".serialize(record, "state", serializer)?
            }
            State::Downloading { peer_id } => {
                serializer.emit_arguments("downloading_peer", &format_args!("{}", peer_id))?
            }
            State::Processing { peer_id } => {
                serializer.emit_arguments("processing_peer", &format_args!("{}", peer_id))?
            }
        }
        serializer.emit_u8("failed_downloads", self.failed_downloading)?;
        serializer.emit_u8("failed_processing", self.failed_processing)?;
        slog::Result::Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::builder::Witness;
    use beacon_chain::eth1_chain::CachingEth1Backend;
    use sloggers::null::NullLoggerBuilder;
    use sloggers::Build;
    use slot_clock::{SlotClock, TestingSlotClock};
    use std::time::Duration;
    use store::{HotColdDB, MemoryStore, StoreConfig};
    use types::{
        test_utils::{SeedableRng, TestRandom, XorShiftRng},
        ChainSpec, EthSpec, MinimalEthSpec as E, SignedBeaconBlock, Slot,
    };

    fn rand_block() -> SignedBeaconBlock<E> {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        SignedBeaconBlock::from_block(
            types::BeaconBlock::Base(types::BeaconBlockBase {
                ..<_>::random_for_test(&mut rng)
            }),
            types::Signature::random_for_test(&mut rng),
        )
    }
    type T = Witness<TestingSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

    #[test]
    fn test_happy_path() {
        let peer_id = PeerShouldHave::BlockAndBlobs(PeerId::random());
        let block = rand_block();
        let spec = E::default_spec();
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_secs(spec.seconds_per_slot),
        );
        let log = NullLoggerBuilder.build().expect("logger should build");
        let store = HotColdDB::open_ephemeral(StoreConfig::default(), ChainSpec::minimal(), log)
            .expect("store");
        let da_checker = Arc::new(
            DataAvailabilityChecker::new(slot_clock, None, store.into(), spec)
                .expect("data availability checker"),
        );
        let mut sl =
            SingleBlockLookup::<4, T>::new(block.canonical_root(), None, &[peer_id], da_checker);
        sl.request_block().unwrap();
        sl.verify_block(Some(block.into())).unwrap().unwrap();
    }

    #[test]
    fn test_block_lookup_failures() {
        const FAILURES: u8 = 3;
        let peer_id = PeerShouldHave::BlockAndBlobs(PeerId::random());
        let block = rand_block();
        let spec = E::default_spec();
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_secs(spec.seconds_per_slot),
        );
        let log = NullLoggerBuilder.build().expect("logger should build");
        let store = HotColdDB::open_ephemeral(StoreConfig::default(), ChainSpec::minimal(), log)
            .expect("store");

        let da_checker = Arc::new(
            DataAvailabilityChecker::new(slot_clock, None, store.into(), spec)
                .expect("data availability checker"),
        );

        let mut sl = SingleBlockLookup::<FAILURES, T>::new(
            block.canonical_root(),
            None,
            &[peer_id],
            da_checker,
        );
        for _ in 1..FAILURES {
            sl.request_block().unwrap();
            sl.block_request_state.state.register_failure_downloading();
        }

        // Now we receive the block and send it for processing
        sl.request_block().unwrap();
        sl.verify_block(Some(block.into())).unwrap().unwrap();

        // One processing failure maxes the available attempts
        sl.block_request_state.state.register_failure_processing();
        assert_eq!(
            sl.request_block(),
            Err(LookupRequestError::TooManyAttempts {
                cannot_process: false
            })
        )
    }
}
