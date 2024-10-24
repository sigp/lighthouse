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
    BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecar, EthSpec, Hash256, RuntimeVariableList,
    SignedBeaconBlock,
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
    expected_column_indices: Option<Vec<ColumnIndex>>,
    /// Used to determine if the number of data columns stream termination this accumulator should
    /// wait for. This may be less than the number of `expected_column_indices` due to request batching.
    num_custody_column_requests: Option<usize>,
    /// The peers the request was made to.
    pub(crate) peer_ids: Vec<PeerId>,
}

impl<E: EthSpec> RangeBlockComponentsRequest<E> {
    pub fn new(
        expects_blobs: bool,
        expected_column_indices: Option<Vec<ColumnIndex>>,
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
            expected_column_indices,
            num_custody_column_requests,
            peer_ids,
        }
    }

    // TODO: This function should be deprecated when simplying the retry mechanism of this range
    // requests.
    pub fn get_requirements(&self) -> (bool, Option<Vec<ColumnIndex>>) {
        (self.expects_blobs, self.expected_column_indices.clone())
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
        if let Some(expected_column_indices) = self.expected_column_indices.as_ref() {
            let expected_column_indices = expected_column_indices.clone();
            self.into_responses_with_custody_columns(spec, expected_column_indices)
        } else {
            Ok(self.into_responses_with_blobs())
        }
    }

    fn into_responses_with_blobs(self) -> Vec<RpcBlock<E>> {
        let RangeBlockComponentsRequest { blocks, blobs, .. } = self;

        let mut blobs_by_block = HashMap::<Hash256, Vec<Arc<BlobSidecar<E>>>>::new();

        for blob in blobs {
            let block_root = blob.block_root();
            blobs_by_block.entry(block_root).or_default().push(blob);
        }

        // Now iterate all blocks ensuring that the block roots of each block and blob match
        let mut rpc_blocks = Vec::with_capacity(blocks.len());

        for block in blocks {
            let block_root = get_block_root(&block);
            let blobs = blobs_by_block.remove(&block_root).map(VariableList::from);
            rpc_blocks.push(RpcBlock::new_unchecked(block_root, block, blobs, None));
        }

        rpc_blocks
    }

    fn into_responses_with_custody_columns(
        self,
        spec: &ChainSpec,
        expeced_custody_columns: Vec<ColumnIndex>,
    ) -> Result<Vec<RpcBlock<E>>, String> {
        let RangeBlockComponentsRequest {
            blocks,
            data_columns,
            ..
        } = self;

        // Group data columns by block_root and index
        let mut data_columns_by_block = HashMap::<Hash256, Vec<_>>::new();

        for column in data_columns {
            data_columns_by_block
                .entry(column.block_root())
                .or_default()
                // Safe to convert to `CustodyDataColumn`: we have asserted that the index of
                // this column is in the set of `expected_column_indices` and with the expected
                // block root, so for the expected epoch of this batch.
                .push(CustodyDataColumn::from_asserted_custody(column));
            // Note: no need to check for duplicates `ActiveDataColumnsByRangeRequest` ensures that
            // only requested column indices are returned.
        }

        // Here we don't know what's the canonical block at a specific slot. A block may claim to
        // have data (some blob transactions) but be invalid. Therefore, the block peer may disagree
        // with the data column peer wether a block has data or not. However, we can match columns to
        // blocks by block roots safely. If the block peer and column peer disagree we will have a
        // mismatch of columns, which we HAVE to tolerate here.
        //
        // Note that we can have a partial match of columns. Column peers can disagree between them,
        // so we must track who was expected to provide what columns for a set of indexes. If the
        // block ends up with data and we are missing columns, penalize the peers that did not send
        // the columns.

        // Now iterate all blocks ensuring that the block roots of each block and data column match,
        // plus we have columns for our custody requirements
        let mut rpc_blocks = Vec::with_capacity(blocks.len());

        for block in blocks {
            let block_root = get_block_root(&block);
            let columns = match data_columns_by_block.remove(&block_root) {
                Some(columns) => Some((
                    RuntimeVariableList::new(columns, spec.number_of_columns)
                        .map_err(|e| format!("{:?}", e))?,
                    expeced_custody_columns.clone(),
                )),
                None => None,
            };
            rpc_blocks.push(RpcBlock::new_unchecked(block_root, block, None, columns));
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
        let expected_column_indices = vec![1, 2, 3, 4];
        let mut info = RangeBlockComponentsRequest::<E>::new(
            false,
            Some(expected_column_indices.clone()),
            Some(expected_column_indices.len()),
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
                if expected_column_indices.contains(&column.index) {
                    info.add_data_column(Some(column.clone()));
                }
            }
        }

        // Terminate the requests
        for (i, _column_index) in expected_column_indices.iter().enumerate() {
            info.add_data_column(None);

            if i < expected_column_indices.len() - 1 {
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
        let expected_column_indices = vec![1, 2, 3, 4];
        let num_of_data_column_requests = 2;
        let mut info = RangeBlockComponentsRequest::<E>::new(
            false,
            Some(expected_column_indices.clone()),
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
                if expected_column_indices.contains(&column.index) {
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
