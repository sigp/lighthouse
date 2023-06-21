use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProductionError};
use eth2::types::{BeaconBlockAndBlobSidecars, BlindedBeaconBlockAndBlobSidecars, BlockContents};
use std::sync::Arc;
use types::deneb_types::BlindedBlobSidecar;
use types::{BeaconBlock, BlindedPayload, BlobSidecar, ForkName, FullPayload};

type Error = warp::reject::Rejection;

pub fn build_block_contents<T: BeaconChainTypes>(
    fork_name: ForkName,
    chain: Arc<BeaconChain<T>>,
    block: BeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>,
) -> Result<BlockContents<T::EthSpec, FullPayload<T::EthSpec>, BlobSidecar<T::EthSpec>>, Error> {
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

pub fn build_blinded_block_contents<T: BeaconChainTypes>(
    fork_name: ForkName,
    chain: Arc<BeaconChain<T>>,
    block: BeaconBlock<T::EthSpec, BlindedPayload<T::EthSpec>>,
) -> Result<BlockContents<T::EthSpec, BlindedPayload<T::EthSpec>, BlindedBlobSidecar>, Error> {
    match fork_name {
        ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
            Ok(BlockContents::Block(block))
        }
        ForkName::Deneb => {
            let block_root = &block.canonical_root();
            if let Some(blob_sidecars) = chain.proposal_blinded_blob_cache.pop(block_root) {
                let block_and_blobs = BlindedBeaconBlockAndBlobSidecars {
                    blinded_block: block,
                    blinded_blob_sidecars: blob_sidecars,
                };

                Ok(BlockContents::BlindedBlockAndBlobSidecars(block_and_blobs))
            } else {
                Err(warp_utils::reject::block_production_error(
                    BlockProductionError::NoBlobsCached,
                ))
            }
        }
    }
}
