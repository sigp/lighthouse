use beacon_chain::{
    block_verification_types::RpcBlock, data_column_verification::CustodyDataColumn, get_block_root,
};
use lighthouse_network::PeerId;
use ssz_types::VariableList;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use types::{
    BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecar, EthSpec, Hash256, SignedBeaconBlock,
};

#[derive(Debug)]
pub struct RangeBlockComponentsRequest<E: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    blocks: VecDeque<Arc<SignedBeaconBlock<E>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    blobs: VecDeque<Arc<BlobSidecar<E>>>,
    data_columns: VecDeque<Arc<DataColumnSidecar<E>>>,
    /// Whether the individual RPC request for blocks is finished or not.
    is_blocks_stream_terminated: bool,
    /// Whether the individual RPC request for sidecars is finished or not.
    is_sidecars_stream_terminated: bool,
    custody_columns_streams_terminated: usize,
    /// Used to determine if this accumulator should wait for a sidecars stream termination
    expects_blobs: bool,
    expects_custody_columns: Option<Vec<ColumnIndex>>,
    /// Used to determine if the number of data columns stream termination this accumulator should
    /// wait for. This may be less than the number of `expects_custody_columns` due to request batching.
    num_custody_column_requests: Option<usize>,
    /// The peers the request was made to.
    pub(crate) peer_ids: Vec<PeerId>,
}

impl<E: EthSpec> RangeBlockComponentsRequest<E> {
    pub fn new(
        expects_blobs: bool,
        expects_custody_columns: Option<Vec<ColumnIndex>>,
        num_custody_column_requests: Option<usize>,
        peer_ids: Vec<PeerId>,
    ) -> Self {
        Self {
            blocks: <_>::default(),
            blobs: <_>::default(),
            data_columns: <_>::default(),
            is_blocks_stream_terminated: false,
            is_sidecars_stream_terminated: false,
            custody_columns_streams_terminated: 0,
            expects_blobs,
            expects_custody_columns,
            num_custody_column_requests,
            peer_ids,
        }
    }

    // TODO: This function should be deprecated when simplying the retry mechanism of this range
    // requests.
    pub fn get_requirements(&self) -> (bool, Option<Vec<ColumnIndex>>) {
        (self.expects_blobs, self.expects_custody_columns.clone())
    }

    pub fn add_block_response(&mut self, block_opt: Option<Arc<SignedBeaconBlock<E>>>) {
        match block_opt {
            Some(block) => self.blocks.push_back(block),
            None => self.is_blocks_stream_terminated = true,
        }
    }

    pub fn add_sidecar_response(&mut self, sidecar_opt: Option<Arc<BlobSidecar<E>>>) {
        match sidecar_opt {
            Some(sidecar) => self.blobs.push_back(sidecar),
            None => self.is_sidecars_stream_terminated = true,
        }
    }

    pub fn add_data_column(&mut self, column_opt: Option<Arc<DataColumnSidecar<E>>>) {
        match column_opt {
            Some(column) => self.data_columns.push_back(column),
            // TODO(das): this mechanism is dangerous, if somehow there are two requests for the
            // same column index it can terminate early. This struct should track that all requests
            // for all custody columns terminate.
            None => self.custody_columns_streams_terminated += 1,
        }
    }

    pub fn into_responses(self, spec: &ChainSpec) -> Result<Vec<RpcBlock<E>>, String> {
        if let Some(expects_custody_columns) = self.expects_custody_columns.clone() {
            self.into_responses_with_custody_columns(expects_custody_columns, spec)
        } else {
            self.into_responses_with_blobs()
        }
    }

    fn into_responses_with_blobs(self) -> Result<Vec<RpcBlock<E>>, String> {
        let RangeBlockComponentsRequest { blocks, blobs, .. } = self;

        // There can't be more more blobs than blocks. i.e. sending any blob (empty
        // included) for a skipped slot is not permitted.
        let mut responses = Vec::with_capacity(blocks.len());
        let mut blob_iter = blobs.into_iter().peekable();
        for block in blocks.into_iter() {
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

    fn into_responses_with_custody_columns(
        self,
        expects_custody_columns: Vec<ColumnIndex>,
        spec: &ChainSpec,
    ) -> Result<Vec<RpcBlock<E>>, String> {
        let RangeBlockComponentsRequest {
            blocks,
            data_columns,
            ..
        } = self;

        // Group data columns by block_root and index
        let mut data_columns_by_block =
            HashMap::<Hash256, HashMap<ColumnIndex, Arc<DataColumnSidecar<E>>>>::new();

        for column in data_columns {
            let block_root = column.block_root();
            let index = column.index;
            if data_columns_by_block
                .entry(block_root)
                .or_default()
                .insert(index, column)
                .is_some()
            {
                return Err(format!(
                    "Repeated column block_root {block_root:?} index {index}"
                ));
            }
        }

        // Now iterate all blocks ensuring that the block roots of each block and data column match,
        // plus we have columns for our custody requirements
        let mut rpc_blocks = Vec::with_capacity(blocks.len());

        for block in blocks {
            let block_root = get_block_root(&block);
            rpc_blocks.push(if block.num_expected_blobs() > 0 {
                let Some(mut data_columns_by_index) = data_columns_by_block.remove(&block_root)
                else {
                    // This PR ignores the fix from https://github.com/sigp/lighthouse/pull/5675
                    // which allows blobs to not match blocks.
                    // TODO(das): on the initial version of PeerDAS the beacon chain does not check
                    // rpc custody requirements and dropping this check can allow the block to have
                    // an inconsistent DB.
                    return Err(format!("No columns for block {block_root:?} with data"));
                };

                let mut custody_columns = vec![];
                for index in &expects_custody_columns {
                    let Some(data_column) = data_columns_by_index.remove(index) else {
                        return Err(format!("No column for block {block_root:?} index {index}"));
                    };
                    // Safe to convert to `CustodyDataColumn`: we have asserted that the index of
                    // this column is in the set of `expects_custody_columns` and with the expected
                    // block root, so for the expected epoch of this batch.
                    custody_columns.push(CustodyDataColumn::from_asserted_custody(data_column));
                }

                // Assert that there are no columns left
                if !data_columns_by_index.is_empty() {
                    let remaining_indices = data_columns_by_index.keys().collect::<Vec<_>>();
                    return Err(format!(
                        "Not all columns consumed for block {block_root:?}: {remaining_indices:?}"
                    ));
                }

                RpcBlock::new_with_custody_columns(Some(block_root), block, custody_columns, spec)
                    .map_err(|e| format!("{e:?}"))?
            } else {
                RpcBlock::new_without_blobs(Some(block_root), block)
            });
        }

        // Assert that there are no columns left for other blocks
        if !data_columns_by_block.is_empty() {
            let remaining_roots = data_columns_by_block.keys().collect::<Vec<_>>();
            return Err(format!("Not all columns consumed: {remaining_roots:?}"));
        }

        Ok(rpc_blocks)
    }

    pub fn is_finished(&self) -> bool {
        if !self.is_blocks_stream_terminated {
            return false;
        }
        if self.expects_blobs && !self.is_sidecars_stream_terminated {
            return false;
        }
        if let Some(expects_custody_column_responses) = self.num_custody_column_requests {
            if self.custody_columns_streams_terminated < expects_custody_column_responses {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::RangeBlockComponentsRequest;
    use beacon_chain::test_utils::{
        generate_rand_block_and_blobs, generate_rand_block_and_data_columns, test_spec, NumBlobs,
    };
    use lighthouse_network::PeerId;
    use rand::SeedableRng;
    use types::{test_utils::XorShiftRng, ForkName, MinimalEthSpec as E};

    #[test]
    fn no_blobs_into_responses() {
        let peer_id = PeerId::random();
        let mut info = RangeBlockComponentsRequest::<E>::new(false, None, None, vec![peer_id]);
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
        info.into_responses(&test_spec::<E>()).unwrap();
    }

    #[test]
    fn empty_blobs_into_responses() {
        let peer_id = PeerId::random();
        let mut info = RangeBlockComponentsRequest::<E>::new(true, None, None, vec![peer_id]);
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
        info.into_responses(&test_spec::<E>()).unwrap();
    }

    #[test]
    fn rpc_block_with_custody_columns() {
        let spec = test_spec::<E>();
        let expects_custody_columns = vec![1, 2, 3, 4];
        let mut info = RangeBlockComponentsRequest::<E>::new(
            false,
            Some(expects_custody_columns.clone()),
            Some(expects_custody_columns.len()),
            vec![PeerId::random()],
        );
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Deneb,
                    NumBlobs::Number(1),
                    &mut rng,
                    &spec,
                )
            })
            .collect::<Vec<_>>();

        // Send blocks and complete terminate response
        for block in &blocks {
            info.add_block_response(Some(block.0.clone().into()));
        }
        info.add_block_response(None);
        // Assert response is not finished
        assert!(!info.is_finished());

        // Send data columns interleaved
        for block in &blocks {
            for column in &block.1 {
                if expects_custody_columns.contains(&column.index) {
                    info.add_data_column(Some(column.clone()));
                }
            }
        }

        // Terminate the requests
        for (i, _column_index) in expects_custody_columns.iter().enumerate() {
            info.add_data_column(None);

            if i < expects_custody_columns.len() - 1 {
                assert!(
                    !info.is_finished(),
                    "requested should not be finished at loop {i}"
                );
            } else {
                assert!(
                    info.is_finished(),
                    "request should be finishied at loop {i}"
                );
            }
        }

        // All completed construct response
        info.into_responses(&spec).unwrap();
    }

    #[test]
    fn rpc_block_with_custody_columns_batched() {
        let spec = test_spec::<E>();
        let expects_custody_columns = vec![1, 2, 3, 4];
        let num_of_data_column_requests = 2;
        let mut info = RangeBlockComponentsRequest::<E>::new(
            false,
            Some(expects_custody_columns.clone()),
            Some(num_of_data_column_requests),
            vec![PeerId::random()],
        );
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Deneb,
                    NumBlobs::Number(1),
                    &mut rng,
                    &spec,
                )
            })
            .collect::<Vec<_>>();

        // Send blocks and complete terminate response
        for block in &blocks {
            info.add_block_response(Some(block.0.clone().into()));
        }
        info.add_block_response(None);
        // Assert response is not finished
        assert!(!info.is_finished());

        // Send data columns interleaved
        for block in &blocks {
            for column in &block.1 {
                if expects_custody_columns.contains(&column.index) {
                    info.add_data_column(Some(column.clone()));
                }
            }
        }

        // Terminate the requests
        for i in 0..num_of_data_column_requests {
            info.add_data_column(None);
            if i < num_of_data_column_requests - 1 {
                assert!(
                    !info.is_finished(),
                    "requested should not be finished at loop {i}"
                );
            } else {
                assert!(info.is_finished(), "request should be finished at loop {i}");
            }
        }

        // All completed construct response
        info.into_responses(&spec).unwrap();
    }
}
