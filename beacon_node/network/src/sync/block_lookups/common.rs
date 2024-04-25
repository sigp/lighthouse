use crate::sync::block_lookups::single_block_lookup::{
    LookupRequestError, SingleBlockLookup, SingleLookupRequestState,
};
use crate::sync::block_lookups::{
    BlobRequestState, BlockRequestState, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS,
};
use crate::sync::manager::{BlockProcessType, Id, SLOT_IMPORT_TOLERANCE};
use crate::sync::network_context::{
    BlobsByRootSingleBlockRequest, BlocksByRootSingleRequest, SyncNetworkContext,
};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::BeaconChainTypes;
use std::sync::Arc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{Hash256, SignedBeaconBlock};

use super::single_block_lookup::DownloadResult;
use super::SingleLookupId;

#[derive(Debug, Copy, Clone)]
pub enum ResponseType {
    Block,
    Blob,
}

/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
pub(crate) const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

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

    /// Potentially makes progress on this request if it's in a progress-able state
    fn continue_request(
        &mut self,
        id: Id,
        awaiting_parent: bool,
        downloaded_block_expected_blobs: Option<usize>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        // Attempt to progress awaiting downloads
        if self.get_state().is_awaiting_download() {
            // Verify the current request has not exceeded the maximum number of attempts.
            // TODO: Okay to use `SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS` for both current and parent
            // lookups now? It not trivial to identify what is a "parent lookup" now.
            let request_state = self.get_state();
            if request_state.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                let cannot_process = request_state.more_failed_processing_attempts();
                return Err(LookupRequestError::TooManyAttempts { cannot_process });
            }

            let peer_id = self
                .get_state_mut()
                .use_rand_available_peer()
                .ok_or(LookupRequestError::NoPeers)?;

            // make_request returns true only if a request was made
            if self.make_request(id, peer_id, downloaded_block_expected_blobs, cx)? {
                self.get_state_mut().on_download_start()?;
            }

        // Otherwise, attempt to progress awaiting processing
        // If this request is awaiting a parent lookup to be processed, do not send for processing.
        // The request will be rejected with unknown parent error.
        } else if !awaiting_parent {
            // maybe_start_processing returns Some if state == AwaitingProcess. This pattern is
            // useful to conditionally access the result data.
            if let Some(result) = self.get_state_mut().maybe_start_processing() {
                return Self::send_for_processing(id, result, cx);
            }
        }

        Ok(())
    }

    /// Send the request to the network service.
    fn make_request(
        &self,
        id: Id,
        peer_id: PeerId,
        downloaded_block_expected_blobs: Option<usize>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<bool, LookupRequestError>;

    /* Response handling methods */

    /// A getter for the parent root of the response. Returns an `Option` because we won't know
    /// the blob parent if we don't end up getting any blobs in the response.
    fn get_parent_root(verified_response: &Self::VerifiedResponseType) -> Option<Hash256>;

    /// Send the response to the beacon processor.
    fn send_for_processing(
        id: Id,
        result: DownloadResult<Self::VerifiedResponseType>,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError>;

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
    type RequestType = BlocksByRootSingleRequest;
    type VerifiedResponseType = Arc<SignedBeaconBlock<T::EthSpec>>;

    fn make_request(
        &self,
        id: SingleLookupId,
        peer_id: PeerId,
        _: Option<usize>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<bool, LookupRequestError> {
        cx.block_lookup_request(
            id,
            peer_id,
            BlocksByRootSingleRequest(self.requested_block_root),
        )
        .map_err(LookupRequestError::SendFailed)
    }

    fn get_parent_root(verified_response: &Arc<SignedBeaconBlock<T::EthSpec>>) -> Option<Hash256> {
        Some(verified_response.parent_root())
    }

    fn send_for_processing(
        id: SingleLookupId,
        (block, block_root, seen_timestamp, _): DownloadResult<Self::VerifiedResponseType>,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        cx.send_block_for_processing(
            block_root,
            RpcBlock::new_without_blobs(Some(block_root), block),
            seen_timestamp,
            BlockProcessType::SingleBlock { id },
        )
        .map_err(LookupRequestError::SendFailed)
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
    type RequestType = BlobsByRootSingleBlockRequest;
    type VerifiedResponseType = FixedBlobSidecarList<T::EthSpec>;

    fn make_request(
        &self,
        id: Id,
        peer_id: PeerId,
        downloaded_block_expected_blobs: Option<usize>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<bool, LookupRequestError> {
        cx.blob_lookup_request(
            id,
            peer_id,
            self.block_root,
            downloaded_block_expected_blobs,
        )
        .map_err(LookupRequestError::SendFailed)
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
        (verified, block_root, seen_timestamp, _): DownloadResult<Self::VerifiedResponseType>,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        cx.send_blobs_for_processing(
            block_root,
            verified,
            seen_timestamp,
            BlockProcessType::SingleBlob { id },
        )
        .map_err(LookupRequestError::SendFailed)
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
