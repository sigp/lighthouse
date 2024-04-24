use crate::sync::block_lookups::parent_lookup::PARENT_FAIL_TOLERANCE;
use crate::sync::block_lookups::single_block_lookup::{
    LookupRequestError, SingleBlockLookup, SingleLookupRequestState,
};
use crate::sync::block_lookups::{
    BlobRequestState, BlockLookups, BlockRequestState, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS,
};
use crate::sync::manager::{BlockProcessType, Id, SingleLookupReqId};
use crate::sync::network_context::{
    BlobsByRootSingleBlockRequest, BlocksByRootSingleRequest, SyncNetworkContext,
};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::data_availability_checker::ChildComponents;
use beacon_chain::BeaconChainTypes;
use std::sync::Arc;
use std::time::Duration;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{Hash256, SignedBeaconBlock};

#[derive(Debug, Copy, Clone)]
pub enum ResponseType {
    Block,
    Blob,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum LookupType {
    Current,
    Parent,
}

impl LookupType {
    fn max_attempts(&self) -> u8 {
        match self {
            LookupType::Current => SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS,
            LookupType::Parent => PARENT_FAIL_TOLERANCE,
        }
    }
}

/// This trait unifies common single block lookup functionality across blocks and blobs. This
/// includes making requests, verifying responses, and handling processing results. A
/// `SingleBlockLookup` includes both a `BlockRequestState` and a `BlobRequestState`, this trait is
/// implemented for each.
///
/// The use of the `ResponseType` associated type gives us a degree of type
/// safety when handling a block/blob response ensuring we only mutate the correct corresponding
/// state.
pub trait RequestState<T: BeaconChainTypes> {
    /// The type of the request .
    type RequestType;

    /// The type created after validation.
    type VerifiedResponseType: Clone;

    /// We convert a `VerifiedResponseType` to this type prior to sending it to the beacon processor.
    type ReconstructedResponseType;

    /* Request building methods */

    /// Construct a new request.
    fn build_request(
        &mut self,
        lookup_type: LookupType,
    ) -> Result<(PeerId, Self::RequestType), LookupRequestError> {
        // Verify and construct request.
        self.too_many_attempts(lookup_type)?;
        let peer = self.get_peer()?;
        let request = self.new_request();
        Ok((peer, request))
    }

    /// Construct a new request and send it.
    fn build_request_and_send(
        &mut self,
        id: Id,
        lookup_type: LookupType,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        // Check if request is necessary.
        if !self.get_state().is_awaiting_download() {
            return Ok(());
        }

        // Construct request.
        let (peer_id, request) = self.build_request(lookup_type)?;

        // Update request state.
        let req_counter = self.get_state_mut().on_download_start(peer_id);

        // Make request
        let id = SingleLookupReqId {
            id,
            req_counter,
            lookup_type,
        };
        Self::make_request(id, peer_id, request, cx)
    }

    /// Verify the current request has not exceeded the maximum number of attempts.
    fn too_many_attempts(&self, lookup_type: LookupType) -> Result<(), LookupRequestError> {
        let request_state = self.get_state();

        if request_state.failed_attempts() >= lookup_type.max_attempts() {
            let cannot_process = request_state.more_failed_processing_attempts();
            Err(LookupRequestError::TooManyAttempts { cannot_process })
        } else {
            Ok(())
        }
    }

    /// Get the next peer to request. Draws from the set of peers we think should have both the
    /// block and blob first. If that fails, we draw from the set of peers that may have either.
    fn get_peer(&mut self) -> Result<PeerId, LookupRequestError> {
        self.get_state_mut()
            .use_rand_available_peer()
            .ok_or(LookupRequestError::NoPeers)
    }

    /// Initialize `Self::RequestType`.
    fn new_request(&self) -> Self::RequestType;

    /// Send the request to the network service.
    fn make_request(
        id: SingleLookupReqId,
        peer_id: PeerId,
        request: Self::RequestType,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError>;

    /* Response handling methods */

    /// A getter for the parent root of the response. Returns an `Option` because we won't know
    /// the blob parent if we don't end up getting any blobs in the response.
    fn get_parent_root(verified_response: &Self::VerifiedResponseType) -> Option<Hash256>;

    /// Caches the verified response in the lookup if necessary. This is only necessary for lookups
    /// triggered by `UnknownParent` errors.
    fn add_to_child_components(
        verified_response: Self::VerifiedResponseType,
        components: &mut ChildComponents<T::EthSpec>,
    );

    /// Convert a verified response to the type we send to the beacon processor.
    fn verified_to_reconstructed(
        block_root: Hash256,
        verified: Self::VerifiedResponseType,
    ) -> Self::ReconstructedResponseType;

    /// Send the response to the beacon processor.
    fn send_reconstructed_for_processing(
        id: Id,
        bl: &BlockLookups<T>,
        block_root: Hash256,
        verified: Self::ReconstructedResponseType,
        duration: Duration,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError>;

    /// Register a failure to process the block or blob.
    fn register_failure_downloading(&mut self) {
        self.get_state_mut().on_download_failure()
    }

    /* Utility methods */

    /// Returns the `ResponseType` associated with this trait implementation. Useful in logging.
    fn response_type() -> ResponseType;

    /// A getter for the `BlockRequestState` or `BlobRequestState` associated with this trait.
    fn request_state_mut(request: &mut SingleBlockLookup<T>) -> &mut Self;

    /// A getter for a reference to the `SingleLookupRequestState` associated with this trait.
    fn get_state(&self) -> &SingleLookupRequestState;

    /// A getter for a mutable reference to the SingleLookupRequestState associated with this trait.
    fn get_state_mut(&mut self) -> &mut SingleLookupRequestState;
}

impl<T: BeaconChainTypes> RequestState<T> for BlockRequestState {
    type RequestType = BlocksByRootSingleRequest;
    type VerifiedResponseType = Arc<SignedBeaconBlock<T::EthSpec>>;
    type ReconstructedResponseType = RpcBlock<T::EthSpec>;

    fn new_request(&self) -> Self::RequestType {
        BlocksByRootSingleRequest(self.requested_block_root)
    }

    fn make_request(
        id: SingleLookupReqId,
        peer_id: PeerId,
        request: Self::RequestType,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        cx.block_lookup_request(id, peer_id, request)
            .map_err(LookupRequestError::SendFailed)
    }

    fn get_parent_root(verified_response: &Arc<SignedBeaconBlock<T::EthSpec>>) -> Option<Hash256> {
        Some(verified_response.parent_root())
    }

    fn add_to_child_components(
        verified_response: Arc<SignedBeaconBlock<T::EthSpec>>,
        components: &mut ChildComponents<T::EthSpec>,
    ) {
        components.merge_block(verified_response);
    }

    fn verified_to_reconstructed(
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> RpcBlock<T::EthSpec> {
        RpcBlock::new_without_blobs(Some(block_root), block)
    }

    fn send_reconstructed_for_processing(
        id: Id,
        bl: &BlockLookups<T>,
        block_root: Hash256,
        constructed: RpcBlock<T::EthSpec>,
        duration: Duration,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        bl.send_block_for_processing(
            block_root,
            constructed,
            duration,
            BlockProcessType::SingleBlock { id },
            cx,
        )
    }

    fn response_type() -> ResponseType {
        ResponseType::Block
    }
    fn request_state_mut(request: &mut SingleBlockLookup<T>) -> &mut Self {
        &mut request.block_request_state
    }
    fn get_state(&self) -> &SingleLookupRequestState {
        &self.state
    }
    fn get_state_mut(&mut self) -> &mut SingleLookupRequestState {
        &mut self.state
    }
}

impl<T: BeaconChainTypes> RequestState<T> for BlobRequestState<T::EthSpec> {
    type RequestType = BlobsByRootSingleBlockRequest;
    type VerifiedResponseType = FixedBlobSidecarList<T::EthSpec>;
    type ReconstructedResponseType = FixedBlobSidecarList<T::EthSpec>;

    fn new_request(&self) -> Self::RequestType {
        BlobsByRootSingleBlockRequest {
            block_root: self.block_root,
            indices: self.requested_ids.indices(),
        }
    }

    fn make_request(
        id: SingleLookupReqId,
        peer_id: PeerId,
        request: Self::RequestType,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        cx.blob_lookup_request(id, peer_id, request)
            .map_err(LookupRequestError::SendFailed)
    }

    fn get_parent_root(verified_response: &FixedBlobSidecarList<T::EthSpec>) -> Option<Hash256> {
        verified_response
            .into_iter()
            .filter_map(|blob| blob.as_ref())
            .map(|blob| blob.block_parent_root())
            .next()
    }

    fn add_to_child_components(
        verified_response: FixedBlobSidecarList<T::EthSpec>,
        components: &mut ChildComponents<T::EthSpec>,
    ) {
        components.merge_blobs(verified_response);
    }

    fn verified_to_reconstructed(
        _block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
    ) -> FixedBlobSidecarList<T::EthSpec> {
        blobs
    }

    fn send_reconstructed_for_processing(
        id: Id,
        bl: &BlockLookups<T>,
        block_root: Hash256,
        verified: FixedBlobSidecarList<T::EthSpec>,
        duration: Duration,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        bl.send_blobs_for_processing(
            block_root,
            verified,
            duration,
            BlockProcessType::SingleBlob { id },
            cx,
        )
    }

    fn response_type() -> ResponseType {
        ResponseType::Blob
    }
    fn request_state_mut(request: &mut SingleBlockLookup<T>) -> &mut Self {
        &mut request.blob_request_state
    }
    fn get_state(&self) -> &SingleLookupRequestState {
        &self.state
    }
    fn get_state_mut(&mut self) -> &mut SingleLookupRequestState {
        &mut self.state
    }
}
