use beacon_chain::block_verification_types::RpcBlock;
use ssz_types::VariableList;
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
    pub fn add_block_response(&mut self, block_opt: Option<Arc<SignedBeaconBlock<T>>>) {
        match block_opt {
            Some(block) => self.accumulated_blocks.push_back(block),
            None => self.is_blocks_stream_terminated = true,
        }
    }

    pub fn add_sidecar_response(&mut self, sidecar_opt: Option<Arc<BlobSidecar<T>>>) {
        match sidecar_opt {
            Some(sidecar) => self.accumulated_sidecars.push_back(sidecar),
            None => self.is_sidecars_stream_terminated = true,
        }
    }

    pub fn into_responses(self) -> Result<Vec<RpcBlock<T>>, String> {
        let BlocksAndBlobsRequestInfo {
            accumulated_blocks,
            accumulated_sidecars,
            ..
        } = self;

        // There can't be more more blobs than blocks. i.e. sending any blob (empty
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
                blob_list.push(blob_iter.next().ok_or("Missing next blob".to_string())?);
            }

            let mut blobs_buffer = vec![None; T::max_blobs_per_block()];
            for blob in blob_list {
                let blob_index = blob.index as usize;
                let Some(blob_opt) = blobs_buffer.get_mut(blob_index) else {
                    return Err("Invalid blob index".to_string());
                };
                if blob_opt.is_some() {
                    return Err("Repeat blob index".to_string());
                } else {
                    *blob_opt = Some(blob);
                }
            }
            let blobs = VariableList::from(blobs_buffer.into_iter().flatten().collect::<Vec<_>>());
            responses.push(RpcBlock::new(None, block, Some(blobs)).map_err(|e| format!("{e:?}"))?)
        }

        // if accumulated sidecars is not empty, throw an error.
        if blob_iter.next().is_some() {
            return Err("Received sidecars that don't pair well".to_string());
        }

        Ok(responses)
    }

    pub fn is_finished(&self) -> bool {
        self.is_blocks_stream_terminated && self.is_sidecars_stream_terminated
    }
}
