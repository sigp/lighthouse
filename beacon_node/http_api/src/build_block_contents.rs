use beacon_chain::{BeaconBlockResponse, BeaconBlockResponseType, BlockProductionError};
use eth2::types::{BeaconBlockAndBlobSidecars, BlockContents, BlockContentsWrapper};
use serde::{Deserialize, Serialize};
use types::{BlindedBeaconBlock, EthSpec, ForkName};
type Error = warp::reject::Rejection;

pub fn build_block_contents<E: EthSpec>(
    fork_name: ForkName,
    block_response: BeaconBlockResponseType<E>,
) -> Result<BlockContentsWrapper<E>, Error> {
    match block_response {
        BeaconBlockResponseType::Blinded(block) => Ok(BlockContentsWrapper::Blinded(block.block)),
        BeaconBlockResponseType::Full(block) => match fork_name {
            ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => Ok(
                BlockContentsWrapper::Full(BlockContents::Block(block.block)),
            ),
            ForkName::Deneb => {
                let BeaconBlockResponse {
                    block,
                    state: _,
                    blob_items,
                    execution_payload_value: _,
                    consensus_block_value: _,
                } = block;

                let Some((kzg_proofs, blobs)) = blob_items else {
                    return Err(warp_utils::reject::block_production_error(
                        BlockProductionError::MissingBlobs,
                    ));
                };

                Ok(BlockContentsWrapper::Full(
                    BlockContents::BlockAndBlobSidecars(BeaconBlockAndBlobSidecars {
                        block,
                        kzg_proofs,
                        blobs,
                    }),
                ))
            }
        },
    }
}
