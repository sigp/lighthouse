use beacon_chain::blob_sidecar_cache::BlobSidecarsCache;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{info, Logger};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use types::{SignedBlindedBlobSidecar, SignedBlobSidecar};
use warp::Rejection;

/// Handles a request from the HTTP API for blobs.
pub async fn publish_blob<T: BeaconChainTypes>(
    blinded_blob_sidecar: SignedBlindedBlobSidecar,
    _chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
) -> Result<(), Rejection> {
    // FIXME(jimmy) replace fake impl with the real one
    let blob_cache = BlobSidecarsCache::default();

    // TODO check for fork
    let (block_root, blob_index) = (
        &blinded_blob_sidecar.message.blob_root,
        blinded_blob_sidecar.message.index,
    );

    if let Some(full_sidecar) = blob_cache.pop(block_root, blob_index) {
        let signed_blob_sidecar = SignedBlobSidecar {
            message: full_sidecar,
            signature: blinded_blob_sidecar.signature,
        };

        info!(
            log,
            "Publishing signed blob sidecar";
            "block_root" => format!("{}", block_root),
            "blob_index" => blob_index,
        );

        crate::publish_pubsub_message(
            network_tx,
            PubsubMessage::BlobSidecar((blob_index, Box::new(signed_blob_sidecar))),
        )?;
        Ok(())
    } else {
        //FIXME(sean): This should probably return a specific no-blob-cached error code, beacon API coordination required
        return Err(warp_utils::reject::broadcast_without_import(format!(
            "no blob cached for block"
        )));
    }
}
