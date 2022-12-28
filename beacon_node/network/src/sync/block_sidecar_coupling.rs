use std::{collections::VecDeque, sync::Arc};

use types::{
    signed_block_and_blobs::BlockWrapper, BlobsSidecar, EthSpec, SignedBeaconBlock,
    SignedBeaconBlockAndBlobsSidecar,
};

#[derive(Debug, Default)]
pub struct BlockBlobRequestInfo<T: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    accumulated_blocks: VecDeque<Arc<SignedBeaconBlock<T>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    accumulated_sidecars: VecDeque<Arc<BlobsSidecar<T>>>,
    /// Whether the individual RPC request for blocks is finished or not.
    is_blocks_stream_terminated: bool,
    /// Whether the individual RPC request for sidecars is finished or not.
    is_sidecars_stream_terminated: bool,
}

impl<T: EthSpec> BlockBlobRequestInfo<T> {
    pub fn add_block_response(&mut self, maybe_block: Option<Arc<SignedBeaconBlock<T>>>) {
        match maybe_block {
            Some(block) => self.accumulated_blocks.push_back(block),
            None => self.is_blocks_stream_terminated = true,
        }
    }

    pub fn add_sidecar_response(&mut self, maybe_sidecar: Option<Arc<BlobsSidecar<T>>>) {
        match maybe_sidecar {
            Some(sidecar) => self.accumulated_sidecars.push_back(sidecar),
            None => self.is_sidecars_stream_terminated = true,
        }
    }

    pub fn into_responses(self) -> Result<Vec<BlockWrapper<T>>, &'static str> {
        let BlockBlobRequestInfo {
            accumulated_blocks,
            mut accumulated_sidecars,
            ..
        } = self;

        // ASSUMPTION: There can't be more more blobs than blocks. i.e. sending any blob (empty
        // included) for a skipped slot is not permitted.
        let pairs = accumulated_blocks
            .into_iter()
            .map(|beacon_block| {
                if accumulated_sidecars
                    .front()
                    .map(|sidecar| sidecar.beacon_block_slot == beacon_block.slot())
                    .unwrap_or(false)
                {
                    let blobs_sidecar =
                        accumulated_sidecars.pop_front().ok_or("missing sidecar")?;
                    Ok(BlockWrapper::BlockAndBlob(
                        SignedBeaconBlockAndBlobsSidecar {
                            beacon_block,
                            blobs_sidecar,
                        },
                    ))
                } else {
                    Ok(BlockWrapper::Block(beacon_block))
                }
            })
            .collect::<Result<Vec<_>, _>>();

        // if accumulated sidecars is not empty, throw an error.
        if !accumulated_sidecars.is_empty() {
            return Err("Received more sidecars than blocks");
        }

        pairs
    }

    pub fn is_finished(&self) -> bool {
        self.is_blocks_stream_terminated && self.is_sidecars_stream_terminated
    }
}
