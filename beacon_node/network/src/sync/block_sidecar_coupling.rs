use std::{collections::VecDeque, sync::Arc};

use types::{
    signed_block_and_blobs::BlockWrapper, BlobsSidecar, EthSpec, SignedBeaconBlock,
    SignedBeaconBlockAndBlobsSidecar,
};

struct ReceivedData<T: EthSpec> {
    block: Option<Arc<SignedBeaconBlock<T>>>,
    blob: Option<Arc<BlobsSidecar<T>>>,
}

#[derive(Debug, Default)]
pub struct BlockBlobRequestInfo<T: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    accumulated_blocks: VecDeque<Arc<SignedBeaconBlock<T>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    accumulated_sidecars: VecDeque<Arc<BlobsSidecar<T>>>,
    /// Whether the individual RPC request for blocks is finished or not.
    is_blocks_rpc_finished: bool,
    /// Whether the individual RPC request for sidecars is finished or not.
    is_sidecar_rpc_finished: bool,
}

impl<T: EthSpec> BlockBlobRequestInfo<T> {
    pub fn add_block_response(&mut self, maybe_block: Option<Arc<SignedBeaconBlock<T>>>) {
        match maybe_block {
            Some(block) => self.accumulated_blocks.push_back(block),
            None => self.is_blocks_rpc_finished = true,
        }
    }

    pub fn add_sidecar_response(&mut self, maybe_sidecar: Option<Arc<BlobsSidecar<T>>>) {
        match maybe_sidecar {
            Some(sidecar) => self.accumulated_sidecars.push_back(sidecar),
            None => self.is_sidecar_rpc_finished = true,
        }
    }

    pub fn into_responses(self) -> Result<Vec<BlockWrapper<T>>, &'static str> {
        let BlockBlobRequestInfo {
            accumulated_blocks,
            accumulated_sidecars,
            ..
        } = self;

        // Create the storage for our pairs.
        let mut pairs = Vec::with_capacity(accumulated_blocks.len());

        // ASSUMPTION: There can't be more more blobs than blocks. i.e. sending any block (empty
        // included) for a skipped slot is not permitted.
        for sidecar in accumulated_sidecars {
            let blob_slot = sidecar.beacon_block_slot;
            // First queue any blocks that might not have a blob.
            while let Some(block) = {
                // We identify those if their slot is less than the current blob's slot.
                match accumulated_blocks.front() {
                    Some(borrowed_block) if borrowed_block.slot() < blob_slot => {
                        accumulated_blocks.pop_front()
                    }
                    Some(_) => None,
                    None => {
                        // We received a blob and ran out of blocks. This is a peer error
                        return Err("Blob without more blobs to pair with returned by peer");
                    }
                }
            } {
                pairs.push(BlockWrapper::Block { block })
            }

            // The next block must be present and must match the blob's slot
            let next_block = accumulated_blocks
                .pop_front()
                .expect("If block stream ended, an error was previously returned");
            if next_block.slot() != blob_slot {
                // We verified that the slot of the block is not less than the slot of the blob (it
                // would have been returned before). It's also not equal, so this block is ahead
                // than the blob. This means the blob is not paired.
                return Err("Blob without a matching block returned by peer");
            }
            pairs.push(BlockWrapper::BlockAndBlob {
                block_sidecar_pair: SignedBeaconBlockAndBlobsSidecar {
                    beacon_block: next_block,
                    blobs_sidecar: sidecar,
                },
            });
        }

        // Every remaining block does not have a blob
        for block in accumulated_blocks {
            pairs.push(BlockWrapper::Block { block })
        }

        Ok(pairs)
    }

    pub fn is_finished(&self) -> bool {
        self.is_blocks_rpc_finished && self.is_sidecar_rpc_finished
    }
}
