use crate::sync::block_lookups::single_block_lookup::{
    LookupRequestError, LookupVerifyError, SingleBlockLookup, SingleLookupRequestState,
};
use crate::sync::block_lookups::{BlobRequestState, BlockRequestState, PeerId};
use crate::sync::manager::{BlockProcessType, Id, SingleLookupReqId};
use crate::sync::network_context::SyncNetworkContext;

use beacon_chain::{get_block_root, BeaconChainTypes};
use lighthouse_network::rpc::methods::BlobsByRootRequest;
use lighthouse_network::rpc::BlocksByRootRequest;
use rand::prelude::IteratorRandom;
use std::ops::IndexMut;
use std::sync::Arc;
use std::time::Duration;
use types::blob_sidecar::{BlobIdentifier, FixedBlobSidecarList};
use types::{BlobSidecar, ChainSpec, EthSpec, Hash256, SignedBeaconBlock};

use super::SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS;

#[derive(Debug, Copy, Clone)]
pub enum ResponseType {
    Block,
    Blob,
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

    /// A block or blob response.
    type ResponseType;

    /// The type created after validation.
    type VerifiedResponseType: Clone;

    /* Request building methods */

    /// Construct a new request.
    fn build_request(
        &mut self,
        spec: &ChainSpec,
    ) -> Result<(PeerId, Self::RequestType), LookupRequestError> {
        // Verify and construct request.
        self.too_many_attempts()?;
        let peer = self.get_peer()?;
        let request = self.new_request(spec);
        Ok((peer, request))
    }

    /// Construct a new request and send it.
    fn build_request_and_send(
        &mut self,
        id: Id,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        // Check if request is necessary.
        if !self.get_state().is_awaiting_download() {
            return Ok(());
        }

        // Construct request.
        let (peer_id, request) = self.build_request(&cx.chain.spec)?;

        // Update request state.
        let req_counter = self.get_state_mut().on_download_start(peer_id);

        // Make request
        let id = SingleLookupReqId { id, req_counter };
        Self::make_request(id, peer_id, request, cx)
    }

    /// Verify the current request has not exceeded the maximum number of attempts.
    fn too_many_attempts(&self) -> Result<(), LookupRequestError> {
        // TODO: If it's necessary to have difference tolerance between parent and regular
        // lookups, add an argument here to track if the parent of this lookup is known or
        // not.
        let max_attempts = SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS;
        let request_state = self.get_state();

        if request_state.failed_attempts() >= max_attempts {
            let cannot_process = request_state.more_failed_processing();
            Err(LookupRequestError::TooManyAttempts { cannot_process })
        } else {
            Ok(())
        }
    }

    /// Get the next peer to request. Draws from the set of peers we think should have both the
    /// block and blob first. If that fails, we draw from the set of peers that may have either.
    fn get_peer(&mut self) -> Result<PeerId, LookupRequestError> {
        let request_state = self.get_state_mut();
        let peer_id = request_state
            .available_peers
            .iter()
            .choose(&mut rand::thread_rng())
            .copied()
            .ok_or(LookupRequestError::NoPeers)?;
        request_state.used_peers.insert(peer_id);
        Ok(peer_id)
    }

    /// Initialize `Self::RequestType`.
    fn new_request(&self, spec: &ChainSpec) -> Self::RequestType;

    /// Send the request to the network service.
    fn make_request(
        id: SingleLookupReqId,
        peer_id: PeerId,
        request: Self::RequestType,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError>;

    /* Response handling methods */

    /// Verify the response is valid based on what we requested.
    fn verify_response(
        &mut self,
        expected_block_root: Hash256,
        response: Option<Self::ResponseType>,
        seen_timestamp: Duration,
    ) -> Result<Option<Self::VerifiedResponseType>, LookupVerifyError> {
        match self.get_state().get_downloading_peer() {
            Some(peer_id) => match self.verify_response_inner(expected_block_root, response) {
                Ok(Some(verified_response)) => {
                    let parent_root = Self::get_parent_root(&verified_response);
                    self.get_state_mut().on_download_success(
                        peer_id,
                        parent_root,
                        verified_response.clone(),
                        seen_timestamp,
                    );
                    Ok(Some(verified_response))
                }
                Ok(None) => Ok(None),
                Err(e) => {
                    self.get_state_mut().on_download_failure();
                    Err(e)
                }
            },
            None => match response {
                Some(_) => {
                    // We sent the block for processing and received an extra block.
                    self.get_state_mut().on_download_failure();
                    Err(LookupVerifyError::ExtraBlocksReturned)
                }
                None => {
                    // TODO: Is it okay to ignore a stream termination during State::AwaitingDownload?
                    // This is simply the stream termination and we are already processing the
                    // block
                    Ok(None)
                }
            },
        }
    }

    fn send_cached_for_processing(
        &mut self,
        id: Id,
        block_root: Hash256,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        if let Some((verified_response, seen_timestamp)) =
            self.get_state_mut().resolve_unknown_parent()
        {
            <Self as RequestState<T>>::send_for_processing(
                id,
                block_root,
                verified_response,
                seen_timestamp,
                cx,
            )
        } else {
            Ok(())
        }
    }

    /// The response verification unique to block or blobs.
    fn verify_response_inner(
        &mut self,
        expected_block_root: Hash256,
        response: Option<Self::ResponseType>,
    ) -> Result<Option<Self::VerifiedResponseType>, LookupVerifyError>;

    /// A getter for the parent root of the response. Returns an `Option` because we won't know
    /// the blob parent if we don't end up getting any blobs in the response.
    fn get_parent_root(verified_response: &Self::VerifiedResponseType) -> Option<Hash256>;

    /// Send the response to the beacon processor.
    fn send_for_processing(
        id: Id,
        block_root: Hash256,
        verified: Self::VerifiedResponseType,
        seen_timestamp: Duration,
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
    fn get_state(&self) -> &SingleLookupRequestState<Self::VerifiedResponseType>;

    /// A getter for a mutable reference to the SingleLookupRequestState associated with this trait.
    fn get_state_mut(&mut self) -> &mut SingleLookupRequestState<Self::VerifiedResponseType>;
}

impl<T: BeaconChainTypes> RequestState<T> for BlockRequestState<T::EthSpec> {
    type RequestType = BlocksByRootRequest;
    type ResponseType = Arc<SignedBeaconBlock<T::EthSpec>>;
    type VerifiedResponseType = Arc<SignedBeaconBlock<T::EthSpec>>;

    fn new_request(&self, spec: &ChainSpec) -> BlocksByRootRequest {
        BlocksByRootRequest::new(vec![self.requested_block_root], spec)
    }

    fn make_request(
        id: SingleLookupReqId,
        peer_id: PeerId,
        request: Self::RequestType,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        cx.block_lookup_request(id, peer_id, request)
            .map_err(LookupRequestError::SendFailed)
    }

    fn verify_response_inner(
        &mut self,
        expected_block_root: Hash256,
        response: Option<Self::ResponseType>,
    ) -> Result<Option<Arc<SignedBeaconBlock<T::EthSpec>>>, LookupVerifyError> {
        match response {
            Some(block) => {
                // Compute the block root using this specific function so that we can get timing
                // metrics.
                let block_root = get_block_root(&block);
                if block_root != expected_block_root {
                    // return an error and drop the block
                    // NOTE: we take this is as a download failure to prevent counting the
                    // attempt as a chain failure, but simply a peer failure.
                    Err(LookupVerifyError::RootMismatch)
                } else {
                    // Return the block for processing.
                    Ok(Some(block))
                }
            }
            None => Err(LookupVerifyError::NoBlockReturned),
        }
    }

    fn get_parent_root(verified_response: &Arc<SignedBeaconBlock<T::EthSpec>>) -> Option<Hash256> {
        Some(verified_response.parent_root())
    }

    fn send_for_processing(
        id: Id,
        block_root: Hash256,
        verified_response: Self::VerifiedResponseType,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        cx.send_block_for_processing(
            block_root,
            verified_response,
            seen_timestamp,
            BlockProcessType::SingleBlock { id },
        )
    }

    fn response_type() -> ResponseType {
        ResponseType::Block
    }
    fn request_state_mut(request: &mut SingleBlockLookup<T>) -> &mut Self {
        &mut request.block_request_state
    }
    fn get_state(&self) -> &SingleLookupRequestState<Self::VerifiedResponseType> {
        &self.state
    }
    fn get_state_mut(&mut self) -> &mut SingleLookupRequestState<Self::VerifiedResponseType> {
        &mut self.state
    }
}

impl<T: BeaconChainTypes> RequestState<T> for BlobRequestState<T::EthSpec> {
    type RequestType = BlobsByRootRequest;
    type ResponseType = Arc<BlobSidecar<T::EthSpec>>;
    type VerifiedResponseType = FixedBlobSidecarList<T::EthSpec>;

    fn new_request(&self, spec: &ChainSpec) -> BlobsByRootRequest {
        let blob_id_vec: Vec<BlobIdentifier> = self.requested_ids.clone().into();
        BlobsByRootRequest::new(blob_id_vec, spec)
    }

    fn make_request(
        id: SingleLookupReqId,
        peer_id: PeerId,
        request: Self::RequestType,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        cx.blob_lookup_request(id, peer_id, request)
            .map_err(LookupRequestError::SendFailed)
    }

    fn verify_response_inner(
        &mut self,
        _expected_block_root: Hash256,
        blob: Option<Self::ResponseType>,
    ) -> Result<Option<FixedBlobSidecarList<T::EthSpec>>, LookupVerifyError> {
        match blob {
            Some(blob) => {
                let received_id = blob.id();
                if !self.requested_ids.contains(&received_id) {
                    Err(LookupVerifyError::UnrequestedBlobId)
                } else {
                    // State should remain downloading until we receive the stream terminator.
                    self.requested_ids.remove(&received_id);
                    let blob_index = blob.index;

                    if blob_index >= T::EthSpec::max_blobs_per_block() as u64 {
                        return Err(LookupVerifyError::InvalidIndex(blob.index));
                    }
                    *self.blob_download_queue.index_mut(blob_index as usize) = Some(blob);
                    Ok(None)
                }
            }
            None => {
                let blobs = std::mem::take(&mut self.blob_download_queue);
                Ok(Some(blobs))
            }
        }
    }

    fn get_parent_root(verified_response: &FixedBlobSidecarList<T::EthSpec>) -> Option<Hash256> {
        verified_response
            .into_iter()
            .filter_map(|blob| blob.as_ref())
            .map(|blob| blob.block_parent_root())
            .next()
    }

    fn send_for_processing(
        id: Id,
        block_root: Hash256,
        verified: FixedBlobSidecarList<T::EthSpec>,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        cx.send_blobs_for_processing(
            block_root,
            verified,
            seen_timestamp,
            BlockProcessType::SingleBlob { id },
        )
    }

    fn response_type() -> ResponseType {
        ResponseType::Blob
    }
    fn request_state_mut(request: &mut SingleBlockLookup<T>) -> &mut Self {
        &mut request.blob_request_state
    }
    fn get_state(&self) -> &SingleLookupRequestState<Self::VerifiedResponseType> {
        &self.state
    }
    fn get_state_mut(&mut self) -> &mut SingleLookupRequestState<Self::VerifiedResponseType> {
        &mut self.state
    }
}
