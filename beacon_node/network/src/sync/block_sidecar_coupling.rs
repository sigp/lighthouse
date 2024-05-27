use beacon_chain::block_verification_types::RpcBlock;
use ssz_types::VariableList;
use std::{collections::VecDeque, sync::Arc};
use types::{BlobSidecar, EthSpec, SignedBeaconBlock};

use super::range_sync::ByRangeRequestType;

#[derive(Debug)]
pub struct BlocksAndBlobsRequestInfo<E: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    accumulated_blocks: VecDeque<Arc<SignedBeaconBlock<E>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    accumulated_sidecars: VecDeque<Arc<BlobSidecar<E>>>,
    /// Whether the individual RPC request for blocks is finished or not.
    is_blocks_stream_terminated: bool,
    /// Whether the individual RPC request for sidecars is finished or not.
    is_sidecars_stream_terminated: bool,
    /// Used to determine if this accumulator should wait for a sidecars stream termination
    request_type: ByRangeRequestType,
}

impl<E: EthSpec> BlocksAndBlobsRequestInfo<E> {
    pub fn new(request_type: ByRangeRequestType) -> Self {
        Self {
            accumulated_blocks: <_>::default(),
            accumulated_sidecars: <_>::default(),
            is_blocks_stream_terminated: <_>::default(),
            is_sidecars_stream_terminated: <_>::default(),
            request_type,
        }
    }

    pub fn get_request_type(&self) -> ByRangeRequestType {
        self.request_type
    }

    pub fn add_block_response(&mut self, block_opt: Option<Arc<SignedBeaconBlock<E>>>) {
        match block_opt {
            Some(block) => self.accumulated_blocks.push_back(block),
            None => self.is_blocks_stream_terminated = true,
        }
    }

    pub fn add_sidecar_response(&mut self, sidecar_opt: Option<Arc<BlobSidecar<E>>>) {
        match sidecar_opt {
            Some(sidecar) => self.accumulated_sidecars.push_back(sidecar),
            None => self.is_sidecars_stream_terminated = true,
        }
    }

    pub fn into_responses(self) -> Result<Vec<RpcBlock<E>>, String> {
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
            let mut blob_list = Vec::with_capacity(E::max_blobs_per_block());
            while {
                let pair_next_blob = blob_iter
                    .peek()
                    .map(|sidecar| sidecar.slot() == block.slot())
                    .unwrap_or(false);
                pair_next_blob
            } {
                blob_list.push(blob_iter.next().ok_or("Missing next blob".to_string())?);
            }

            let mut blobs_buffer = vec![None; E::max_blobs_per_block()];
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
        let blobs_requested = match self.request_type {
            ByRangeRequestType::Blocks => false,
            ByRangeRequestType::BlocksAndBlobs => true,
        };
        self.is_blocks_stream_terminated && (!blobs_requested || self.is_sidecars_stream_terminated)
    }
}

#[cfg(test)]
mod tests {
    use super::BlocksAndBlobsRequestInfo;
    use crate::sync::range_sync::ByRangeRequestType;
    use beacon_chain::test_utils::{generate_rand_block_and_blobs, NumBlobs};
    use rand::SeedableRng;
    use types::{test_utils::XorShiftRng, ForkName, MinimalEthSpec as E};

    #[test]
    fn no_blobs_into_responses() {
        let mut info = BlocksAndBlobsRequestInfo::<E>::new(ByRangeRequestType::Blocks);
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| generate_rand_block_and_blobs::<E>(ForkName::Base, NumBlobs::None, &mut rng).0)
            .collect::<Vec<_>>();

        // Send blocks and complete terminate response
        for block in blocks {
            info.add_block_response(Some(block.into()));
        }
        info.add_block_response(None);

        // Assert response is finished and RpcBlocks can be constructed
        assert!(info.is_finished());
        info.into_responses().unwrap();
    }

    #[test]
    fn empty_blobs_into_responses() {
        let mut info = BlocksAndBlobsRequestInfo::<E>::new(ByRangeRequestType::BlocksAndBlobs);
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                // Always generate some blobs.
                generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Number(3), &mut rng).0
            })
            .collect::<Vec<_>>();

        // Send blocks and complete terminate response
        for block in blocks {
            info.add_block_response(Some(block.into()));
        }
        info.add_block_response(None);
        // Expect no blobs returned
        info.add_sidecar_response(None);

        // Assert response is finished and RpcBlocks can be constructed, even if blobs weren't returned.
        // This makes sure we don't expect blobs here when they have expired. Checking this logic should
        // be hendled elsewhere.
        assert!(info.is_finished());
        info.into_responses().unwrap();
    }
}
