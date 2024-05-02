use crate::sync::block_lookups::single_block_lookup::{
    LookupRequestError, SingleBlockLookup, SingleLookupRequestState,
};
use crate::sync::block_lookups::{
    BlobRequestState, BlockRequestState, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS,
};
use crate::sync::manager::{BlockProcessType, Id, SLOT_IMPORT_TOLERANCE};
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::BeaconChainTypes;
use std::sync::Arc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::SignedBeaconBlock;

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

/// Wrapper around bool to prevent mixing this argument with `BlockIsProcessed`
pub(crate) struct AwaitingParent(pub bool);
/// Wrapper around bool to prevent mixing this argument with `AwaitingParent`
pub(crate) struct BlockIsProcessed(pub bool);

/// This trait unifies common single block lookup functionality across blocks and blobs. This
/// includes making requests, verifying responses, and handling processing results. A
/// `SingleBlockLookup` includes both a `BlockRequestState` and a `BlobRequestState`, this trait is
/// implemented for each.
///
/// The use of the `ResponseType` associated type gives us a degree of type
/// safety when handling a block/blob response ensuring we only mutate the correct corresponding
/// state.
pub trait RequestState<T: BeaconChainTypes> {
    /// The type created after validation.
    type VerifiedResponseType: Clone;

    /// Potentially makes progress on this request if it's in a progress-able state
    fn continue_request(
        &mut self,
        id: Id,
        awaiting_parent: AwaitingParent,
        downloaded_block_expected_blobs: Option<usize>,
        block_is_processed: BlockIsProcessed,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        // Attempt to progress awaiting downloads
        if self.get_state().is_awaiting_download() {
            // Verify the current request has not exceeded the maximum number of attempts.
            let request_state = self.get_state();
            if request_state.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                let cannot_process = request_state.more_failed_processing_attempts();
                return Err(LookupRequestError::TooManyAttempts { cannot_process });
            }

            let peer_id = self
                .get_state_mut()
                .use_rand_available_peer()
                .ok_or(LookupRequestError::NoPeers)?;

            // make_request returns true only if a request needs to be made
            if self.make_request(id, peer_id, downloaded_block_expected_blobs, cx)? {
                self.get_state_mut().on_download_start()?;
            } else {
                self.get_state_mut().on_completed_request()?;
            }

        // Otherwise, attempt to progress awaiting processing
        // If this request is awaiting a parent lookup to be processed, do not send for processing.
        // The request will be rejected with unknown parent error.
        } else if !awaiting_parent.0
            && (block_is_processed.0 || matches!(Self::response_type(), ResponseType::Block))
        {
            // maybe_start_processing returns Some if state == AwaitingProcess. This pattern is
            // useful to conditionally access the result data.
            if let Some(result) = self.get_state_mut().maybe_start_processing() {
                return Self::send_for_processing(id, result, cx);
            }
        }

        Ok(())
    }

    /// Request the network context to prepare a request of a component of `block_root`. If the
    /// request is not necessary because the component is already known / processed, return false.
    /// Return true if it sent a request and we can expect an event back from the network.
    fn make_request(
        &self,
        id: Id,
        peer_id: PeerId,
        downloaded_block_expected_blobs: Option<usize>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<bool, LookupRequestError>;

    /* Response handling methods */

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
    type VerifiedResponseType = Arc<SignedBeaconBlock<T::EthSpec>>;

    fn make_request(
        &self,
        id: SingleLookupId,
        peer_id: PeerId,
        _: Option<usize>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<bool, LookupRequestError> {
        cx.block_lookup_request(id, peer_id, self.requested_block_root)
            .map_err(LookupRequestError::SendFailed)
    }

    fn send_for_processing(
        id: SingleLookupId,
        download_result: DownloadResult<Self::VerifiedResponseType>,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        let DownloadResult {
            value,
            block_root,
            seen_timestamp,
            peer_id: _,
        } = download_result;
        cx.send_block_for_processing(
            block_root,
            RpcBlock::new_without_blobs(Some(block_root), value),
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

    fn send_for_processing(
        id: Id,
        download_result: DownloadResult<Self::VerifiedResponseType>,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        let DownloadResult {
            value,
            block_root,
            seen_timestamp,
            peer_id: _,
        } = download_result;
        cx.send_blobs_for_processing(
            block_root,
            value,
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
