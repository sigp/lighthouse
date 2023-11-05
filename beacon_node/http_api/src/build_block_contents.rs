use beacon_chain::BlockProductionError;
use eth2::types::{BeaconBlockAndBlobSidecars, BlindedBeaconBlockAndBlobSidecars, BlockContents};
use types::{AbstractExecPayload, BeaconBlock, EthSpec, ForkName, SidecarList};
type Error = warp::reject::Rejection;

pub fn build_block_contents<E: EthSpec, Payload: AbstractExecPayload<E>>(
    fork_name: ForkName,
    block: BeaconBlock<E, Payload>,
    maybe_blobs: Option<SidecarList<E, <Payload as AbstractExecPayload<E>>::Sidecar>>,
) -> Result<BlockContents<E, Payload>, Error> {
    match Payload::block_type() {
        types::BlockType::Blinded => match fork_name {
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
        },
        types::BlockType::Full => match fork_name {
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
        },
    }
}
