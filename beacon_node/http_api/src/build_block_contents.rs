use beacon_chain::blob_sidecar_cache::{BlobSidecarsCache, DEFAULT_BLOB_CACHE_SIZE};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lru::LruCache;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio_stream::StreamExt;
use types::block_contents::{BeaconBlockAndBlindedBlobSidecars, BlockContents};
use types::{
    AbstractExecPayload, BeaconBlock, BlindedBlobSidecar, EthSpec, ForkName, MainnetEthSpec,
    VariableList,
};

type Error = warp::reject::Rejection;

pub fn build_block_contents<T: BeaconChainTypes, Payload: AbstractExecPayload<T::EthSpec>>(
    fork_name: ForkName,
    _chain: Arc<BeaconChain<T>>,
    block: BeaconBlock<T::EthSpec, Payload>,
) -> Result<BlockContents<T::EthSpec, Payload>, Error> {
    // FIXME(jimmy): to be replaced with `chain.blob_cache`
    let mock_blob_cache = BlobSidecarsCache::<T::EthSpec>::default();

    if matches!(fork_name, ForkName::Eip4844) {
        let block_root = &block.canonical_root();

        if let Some(blob_sidecars) = mock_blob_cache.pop(block_root) {
            let blinded_block_sidecars: Vec<BlindedBlobSidecar> = blob_sidecars
                .into_iter()
                .map(|sidecar| sidecar.into())
                .collect();

            let block_and_blobs = BeaconBlockAndBlindedBlobSidecars {
                block,
                blinded_block_sidecars: VariableList::from(blinded_block_sidecars),
            };

            Ok(BlockContents::BlockAndBlobSidecars(block_and_blobs))
        } else {
            //FIXME(sean): This should probably return a specific no-blob-cached error code, beacon API coordination required
            return Err(warp_utils::reject::broadcast_without_import(format!(
                "no blob cached for block"
            )));
        }
    } else {
        Ok(BlockContents::Block(block))
    }
}
