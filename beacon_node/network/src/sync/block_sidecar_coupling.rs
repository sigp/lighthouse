use beacon_chain::blob_verification::BlockWrapper;
use ssz_types::FixedVector;
use std::{collections::VecDeque, sync::Arc};
use types::{BlobSidecar, EthSpec, SignedBeaconBlock};

#[derive(Debug, Default)]
pub struct BlocksAndBlobsRequestInfo<T: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    accumulated_blocks: VecDeque<Arc<SignedBeaconBlock<T>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    accumulated_sidecars: VecDeque<Arc<BlobSidecar<T>>>,
    /// Whether the individual RPC request for blocks is finished or not.
    is_blocks_stream_terminated: bool,
    /// Whether the individual RPC request for sidecars is finished or not.
    is_sidecars_stream_terminated: bool,
}

impl<T: EthSpec> BlocksAndBlobsRequestInfo<T> {
    pub fn add_block_response(&mut self, maybe_block: Option<Arc<SignedBeaconBlock<T>>>) {
        match maybe_block {
            Some(block) => self.accumulated_blocks.push_back(block),
            None => self.is_blocks_stream_terminated = true,
        }
    }

    pub fn add_sidecar_response(&mut self, maybe_sidecar: Option<Arc<BlobSidecar<T>>>) {
        match maybe_sidecar {
            Some(sidecar) => self.accumulated_sidecars.push_back(sidecar),
            None => self.is_sidecars_stream_terminated = true,
        }
    }

    pub fn into_responses(self) -> Result<Vec<BlockWrapper<T>>, &'static str> {
        let BlocksAndBlobsRequestInfo {
            accumulated_blocks,
            accumulated_sidecars,
            ..
        } = self;

        // ASSUMPTION: There can't be more more blobs than blocks. i.e. sending any blob (empty
        // included) for a skipped slot is not permitted.
        let mut responses = Vec::with_capacity(accumulated_blocks.len());
        let mut blob_iter = accumulated_sidecars.into_iter().peekable();
        for block in accumulated_blocks.into_iter() {
            let mut blob_list = Vec::with_capacity(T::max_blobs_per_block());
            while {
                let pair_next_blob = blob_iter
                    .peek()
                    .map(|sidecar| sidecar.slot == block.slot())
                    .unwrap_or(false);
                pair_next_blob
            } {
                blob_list.push(blob_iter.next().expect("iterator is not empty"));
            }

            if blob_list.is_empty() {
                responses.push(BlockWrapper::Block(block))
            } else {
                let mut blobs_fixed = Vec::with_capacity(T::max_blobs_per_block());
                for blob in blob_list {
                    let blob_index = blob.index as usize;
                    if blob_index >= T::max_blobs_per_block() {
                        return Err("Invalid blob index");
                    }
                    blobs_fixed.insert(blob_index, Some(blob));
                }
                responses.push(BlockWrapper::BlockAndBlobs(
                    block,
                    FixedVector::from(blobs_fixed),
                ))
            }
        }

        // if accumulated sidecars is not empty, throw an error.
        if blob_iter.next().is_some() {
            return Err("Received sidecars that don't pair well");
        }

        Ok(responses)
    }

    pub fn is_finished(&self) -> bool {
        self.is_blocks_stream_terminated && self.is_sidecars_stream_terminated
    }
}
