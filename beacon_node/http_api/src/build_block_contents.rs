use beacon_chain::BlockProductionError;
use eth2::types::{BeaconBlockAndBlobSidecars, BlockContents};
use types::{AbstractExecPayload, BeaconBlock, EthSpec, ForkName, KzgProofs, Sidecar};
type Error = warp::reject::Rejection;

pub fn build_block_contents<E: EthSpec, Payload: AbstractExecPayload<E>>(
    fork_name: ForkName,
    block: BeaconBlock<E, Payload>,
    blob_item: Option<(KzgProofs<E>, <Payload::Sidecar as Sidecar<E>>::BlobItems)>,
) -> Result<BlockContents<E, Payload>, Error> {
    match Payload::block_type() {
        types::BlockType::Blinded => match fork_name {
            ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
                Ok(BlockContents::Block(block))
            }
            ForkName::Deneb => {
                if blob_item.is_some() {
                    // We return same blinded block as pre-deneb here, but
                    // make sure to return an error if the blob items are `None`.
                    Ok(BlockContents::Block(block))
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
                if let Some((kzg_proofs, blobs)) = blob_item {
                    let block_and_blobs = BeaconBlockAndBlobSidecars {
                        block,
                        kzg_proofs,
                        blobs,
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
