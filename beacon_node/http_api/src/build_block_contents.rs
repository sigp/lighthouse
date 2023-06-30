use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProductionError};
use eth2::types::{
    BeaconBlockAndBlobSidecars, BlindedBeaconBlockAndBlobSidecars, BlindedBlockProposal,
    BlockContents, FullBlockProposal,
};
use std::sync::Arc;
use types::{BeaconBlock, BlindedPayload, ForkName, FullPayload};

type Error = warp::reject::Rejection;
type FullBlockContents<E> = BlockContents<E, FullBlockProposal>;
type BlindedBlockContents<E> = BlockContents<E, BlindedBlockProposal>;

pub fn build_block_contents<T: BeaconChainTypes>(
    fork_name: ForkName,
    chain: Arc<BeaconChain<T>>,
    block: BeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>,
) -> Result<FullBlockContents<T::EthSpec>, Error> {
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
) -> Result<BlindedBlockContents<T::EthSpec>, Error> {
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
