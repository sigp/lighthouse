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

/// How many attempts we try to find a parent of a block before we give up trying.
pub(crate) const PARENT_FAIL_TOLERANCE: u8 = 5;
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

    fn continue_request(
        &mut self,
        id: Id,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        if let Some(peer_id) = Self::get_state_mut(self).maybe_start_download()? {
            // Verify the current request has not exceeded the maximum number of attempts.
            let request_state = self.get_state();
            // TODO: Okay to use `SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS` for both current and parent
            // lookups now? It not trivial to identify what is a "parent lookup" now.
            if request_state.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                let cannot_process = request_state.more_failed_processing_attempts();
                return Err(LookupRequestError::TooManyAttempts { cannot_process });
            }

            // Make request
            return self.make_request(id, peer_id, cx);
        }
        if let Some(result) = Self::get_state_mut(self).maybe_start_processing() {
            return Self::send_for_processing(id, result, cx);
        }
        Ok(())
    }

    /// Send the request to the network service.
    fn make_request(
        &self,
        id: Id,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError>;

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
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
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
        (block, block_root, seen_timestamp): DownloadResult<Self::VerifiedResponseType>,
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
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        // TODO: Use cx to figure out which blobs are still to be downloaded
        // - Check against the current cached block in the blocks response the required num of blobs
        // - Check against da checker if there's a blob how many we need
        // - Check against da checker if there are some blobs already downloaded

        cx.blob_lookup_request(
            id,
            peer_id,
            BlobsByRootSingleBlockRequest {
                block_root: self.block_root,
                indices: self.requested_ids.indices(),
            },
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
        (verified, block_root, seen_timestamp): DownloadResult<Self::VerifiedResponseType>,
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
