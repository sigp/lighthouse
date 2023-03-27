use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProductionError};
use eth2::types::{BeaconBlockAndBlobSidecars, BlockContents};
use std::sync::Arc;
use types::{AbstractExecPayload, BeaconBlock, ForkName};

type Error = warp::reject::Rejection;

pub fn build_block_contents<T: BeaconChainTypes, Payload: AbstractExecPayload<T::EthSpec>>(
    fork_name: ForkName,
    chain: Arc<BeaconChain<T>>,
    block: BeaconBlock<T::EthSpec, Payload>,
) -> Result<BlockContents<T::EthSpec, Payload>, Error> {
    match fork_name {
        ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
            Ok(BlockContents::Block(block))
        }
        ForkName::Deneb => {
            let block_root = &block.canonical_root();
            if let Some(blob_sidecars) = chain.proposal_blob_cache.pop(block_root) {
                let block_and_blobs = BeaconBlockAndBlobSidecars {
                    block,
                    blob_sidecars,
                };

                Ok(BlockContents::BlockAndBlobSidecars(block_and_blobs))
            } else {
                Err(warp_utils::reject::block_production_error(
                    BlockProductionError::NoBlobsCached,
                ))
            }
        }
    }
}
