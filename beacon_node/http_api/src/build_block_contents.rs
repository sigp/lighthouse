use beacon_chain::BlockProductionError;
use eth2::types::{BeaconBlockAndBlobSidecars, BlindedBeaconBlockAndBlobSidecars, BlockContents};
use types::{
    BeaconBlock, BlindedBlobSidecarList, BlindedPayload, BlobSidecarList, EthSpec, ForkName,
    FullPayload,
};

type Error = warp::reject::Rejection;
type FullBlockContents<E> = BlockContents<E, FullPayload<E>>;
type BlindedBlockContents<E> = BlockContents<E, BlindedPayload<E>>;

pub fn build_block_contents<E: EthSpec>(
    fork_name: ForkName,
    block: BeaconBlock<E, FullPayload<E>>,
    maybe_blobs: Option<BlobSidecarList<E>>,
) -> Result<FullBlockContents<E>, Error> {
    match fork_name {
        ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
            Ok(BlockContents::Block(block))
        }
        ForkName::Deneb => {
            if let Some(blob_sidecars) = maybe_blobs {
                let block_and_blobs = BeaconBlockAndBlobSidecars {
                    block,
                    blob_sidecars,
                };

                Ok(BlockContents::BlockAndBlobSidecars(block_and_blobs))
            } else {
                Err(warp_utils::reject::block_production_error(
                    BlockProductionError::MissingBlobs,
                ))
            }
        }
    }
}

pub fn build_blinded_block_contents<E: EthSpec>(
    fork_name: ForkName,
    block: BeaconBlock<E, BlindedPayload<E>>,
    maybe_blobs: Option<BlindedBlobSidecarList<E>>,
) -> Result<BlindedBlockContents<E>, Error> {
    match fork_name {
        ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
            Ok(BlockContents::Block(block))
        }
        ForkName::Deneb => {
            if let Some(blinded_blob_sidecars) = maybe_blobs {
                let block_and_blobs = BlindedBeaconBlockAndBlobSidecars {
                    blinded_block: block,
                    blinded_blob_sidecars,
                };

                Ok(BlockContents::BlindedBlockAndBlobSidecars(block_and_blobs))
            } else {
                Err(warp_utils::reject::block_production_error(
                    BlockProductionError::MissingBlobs,
                ))
            }
        }
    }
}
