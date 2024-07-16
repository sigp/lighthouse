use crate::sync::block_lookups::single_block_lookup::{
    LookupRequestError, SingleBlockLookup, SingleLookupRequestState,
};
use crate::sync::block_lookups::{BlobRequestState, BlockRequestState, PeerId};
use crate::sync::network_context::{LookupRequestResult, SyncNetworkContext};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::BeaconChainTypes;
use lighthouse_network::service::api_types::Id;
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

    /// Request the network context to prepare a request of a component of `block_root`. If the
    /// request is not necessary because the component is already known / processed, return false.
    /// Return true if it sent a request and we can expect an event back from the network.
    fn make_request(
        &self,
        id: Id,
        peer_id: PeerId,
        downloaded_block_expected_blobs: Option<usize>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupRequestResult, LookupRequestError>;

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
    ) -> Result<LookupRequestResult, LookupRequestError> {
        cx.block_lookup_request(id, peer_id, self.requested_block_root)
            .map_err(LookupRequestError::SendFailedNetwork)
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
            id,
            block_root,
            RpcBlock::new_without_blobs(Some(block_root), value),
            seen_timestamp,
        )
        .map_err(LookupRequestError::SendFailedProcessor)
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
    ) -> Result<LookupRequestResult, LookupRequestError> {
        cx.blob_lookup_request(
            id,
            peer_id,
            self.block_root,
            downloaded_block_expected_blobs,
        )
        .map_err(LookupRequestError::SendFailedNetwork)
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
        cx.send_blobs_for_processing(id, block_root, value, seen_timestamp)
            .map_err(LookupRequestError::SendFailedProcessor)
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
