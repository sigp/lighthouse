use beacon_chain::blob_cache::BlobCache;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use std::sync::Arc;
use types::block_contents::{BeaconBlockAndBlindedBlobSidecars, BlockContents};
use types::{AbstractExecPayload, BeaconBlock, BlindedBlobSidecar, ForkName, VariableList};

type Error = warp::reject::Rejection;

pub fn build_block_contents<T: BeaconChainTypes, Payload: AbstractExecPayload<T::EthSpec>>(
    fork_name: ForkName,
    _chain: Arc<BeaconChain<T>>,
    block: BeaconBlock<T::EthSpec, Payload>,
) -> Result<BlockContents<T::EthSpec, Payload>, Error> {
    // FIXME(jimmy): to be replaced with `chain.blob_cache`
    let mock_blob_cache = BlobCache::<T::EthSpec>::default();

    if matches!(fork_name, ForkName::Eip4844) {
        let block_root = &block.canonical_root();
        let kzg_commitments = block.body().blob_kzg_commitments().map_err(|_| {
            return warp_utils::reject::broadcast_without_import(format!(
                "EIP4844 block does not contain kzg commitments"
            ));
        })?;

        if let Ok(blob_sidecars) =
            mock_blob_cache.peek_blobs_for_block(block_root, kzg_commitments.len())
        {
            let blinded_block_sidecars: Vec<BlindedBlobSidecar> = blob_sidecars
                .into_iter()
                .map(|sidecar| sidecar.into())
                .collect();

            let block_and_blobs = BeaconBlockAndBlindedBlobSidecars {
                block,
                blinded_blob_sidecars: VariableList::from(blinded_block_sidecars),
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
