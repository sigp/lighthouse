use beacon_chain::{
    block_verification_types::RpcBlock, data_column_verification::CustodyDataColumn, get_block_root,
};
use lighthouse_network::service::api_types::{
    BlobsByRangeRequestId, BlocksByRangeRequestId, DataColumnsByRangeRequestId,
};
use std::{collections::HashMap, sync::Arc};
use types::{
    BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec,
    Hash256, RuntimeVariableList, SignedBeaconBlock,
};

pub struct RangeBlockComponentsRequest<E: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    blocks_request: ByRangeRequest<BlocksByRangeRequestId, Vec<Arc<SignedBeaconBlock<E>>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    block_data_request: RangeBlockDataRequest<E>,
}

enum ByRangeRequest<I: PartialEq + std::fmt::Display, T> {
    Active(I),
    Complete(T),
}

enum RangeBlockDataRequest<E: EthSpec> {
    NoData,
    Blobs(ByRangeRequest<BlobsByRangeRequestId, Vec<Arc<BlobSidecar<E>>>>),
    DataColumns {
        requests: HashMap<
            DataColumnsByRangeRequestId,
            ByRangeRequest<DataColumnsByRangeRequestId, DataColumnSidecarList<E>>,
        >,
        expected_custody_columns: Vec<ColumnIndex>,
    },
}

impl<E: EthSpec> RangeBlockComponentsRequest<E> {
    pub fn new(
        blocks_req_id: BlocksByRangeRequestId,
        blobs_req_id: Option<BlobsByRangeRequestId>,
        data_columns: Option<(Vec<DataColumnsByRangeRequestId>, Vec<ColumnIndex>)>,
    ) -> Self {
        let block_data_request = if let Some(blobs_req_id) = blobs_req_id {
            RangeBlockDataRequest::Blobs(ByRangeRequest::Active(blobs_req_id))
        } else if let Some((requests, expected_custody_columns)) = data_columns {
            RangeBlockDataRequest::DataColumns {
                requests: requests
                    .into_iter()
                    .map(|id| (id, ByRangeRequest::Active(id)))
                    .collect(),
                expected_custody_columns,
            }
        } else {
            RangeBlockDataRequest::NoData
        };

        Self {
            blocks_request: ByRangeRequest::Active(blocks_req_id),
            block_data_request,
        }
    }

    pub fn add_blocks(
        &mut self,
        req_id: BlocksByRangeRequestId,
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
    ) -> Result<(), String> {
        self.blocks_request.finish(req_id, blocks)
    }

    pub fn add_blobs(
        &mut self,
        req_id: BlobsByRangeRequestId,
        blobs: Vec<Arc<BlobSidecar<E>>>,
    ) -> Result<(), String> {
        match &mut self.block_data_request {
            RangeBlockDataRequest::NoData => Err("received blobs but expected no data".to_owned()),
            RangeBlockDataRequest::Blobs(ref mut req) => req.finish(req_id, blobs),
            RangeBlockDataRequest::DataColumns { .. } => {
                Err("received blobs but expected data columns".to_owned())
            }
        }
    }

    pub fn add_custody_columns(
        &mut self,
        req_id: DataColumnsByRangeRequestId,
        columns: Vec<Arc<DataColumnSidecar<E>>>,
    ) -> Result<(), String> {
        match &mut self.block_data_request {
            RangeBlockDataRequest::NoData => {
                Err("received data columns but expected no data".to_owned())
            }
            RangeBlockDataRequest::Blobs(_) => {
                Err("received data columns but expected blobs".to_owned())
            }
            RangeBlockDataRequest::DataColumns {
                ref mut requests, ..
            } => {
                let req = requests
                    .get_mut(&req_id)
                    .ok_or(format!("unknown data columns by range req_id {req_id}"))?;
                req.finish(req_id, columns)
            }
        }
    }

    pub fn responses(&self, spec: &ChainSpec) -> Option<Result<Vec<RpcBlock<E>>, String>> {
        let Some(blocks) = self.blocks_request.to_finished() else {
            return None;
        };

        match &self.block_data_request {
            RangeBlockDataRequest::NoData => {
                Some(Self::responses_with_blobs(blocks.to_vec(), vec![], spec))
            }
            RangeBlockDataRequest::Blobs(request) => {
                let Some(blobs) = request.to_finished() else {
                    return None;
                };
                Some(Self::responses_with_blobs(
                    blocks.to_vec(),
                    blobs.to_vec(),
                    spec,
                ))
            }
            RangeBlockDataRequest::DataColumns {
                requests,
                expected_custody_columns,
            } => {
                let mut data_columns = vec![];
                for req in requests.values() {
                    let Some(data) = req.to_finished() else {
                        return None;
                    };
                    data_columns.extend(data.clone())
                }

                Some(Self::responses_with_custody_columns(
                    blocks.to_vec(),
                    data_columns,
                    expected_custody_columns,
                    spec,
                ))
            }
        }
    }

    fn responses_with_blobs(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        blobs: Vec<Arc<BlobSidecar<E>>>,
        spec: &ChainSpec,
    ) -> Result<Vec<RpcBlock<E>>, String> {
        // There can't be more more blobs than blocks. i.e. sending any blob (empty
        // included) for a skipped slot is not permitted.
        let mut responses = Vec::with_capacity(blocks.len());
        let mut blob_iter = blobs.into_iter().peekable();
        for block in blocks.into_iter() {
            let max_blobs_per_block = spec.max_blobs_per_block(block.epoch()) as usize;
            let mut blob_list = Vec::with_capacity(max_blobs_per_block);
            while {
                let pair_next_blob = blob_iter
                    .peek()
                    .map(|sidecar| sidecar.slot() == block.slot())
                    .unwrap_or(false);
                pair_next_blob
            } {
                blob_list.push(blob_iter.next().ok_or("Missing next blob".to_string())?);
            }

            let mut blobs_buffer = vec![None; max_blobs_per_block];
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
            let blobs = RuntimeVariableList::new(
                blobs_buffer.into_iter().flatten().collect::<Vec<_>>(),
                max_blobs_per_block,
            )
            .map_err(|_| "Blobs returned exceeds max length".to_string())?;
            responses.push(RpcBlock::new(None, block, Some(blobs)).map_err(|e| format!("{e:?}"))?)
        }

        // if accumulated sidecars is not empty, throw an error.
        if blob_iter.next().is_some() {
            return Err("Received sidecars that don't pair well".to_string());
        }

        Ok(responses)
    }

    fn responses_with_custody_columns(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        data_columns: DataColumnSidecarList<E>,
        expects_custody_columns: &[ColumnIndex],
        spec: &ChainSpec,
    ) -> Result<Vec<RpcBlock<E>>, String> {
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
                for index in expects_custody_columns {
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

                RpcBlock::new_with_custody_columns(
                    Some(block_root),
                    block,
                    custody_columns,
                    expects_custody_columns.len(),
                    spec,
                )
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
}

impl<I: PartialEq + std::fmt::Display, T> ByRangeRequest<I, T> {
    fn finish(&mut self, id: I, data: T) -> Result<(), String> {
        match self {
            Self::Active(expected_id) => {
                if expected_id != &id {
                    return Err(format!("unexpected req_id expected {expected_id} got {id}"));
                }
                *self = Self::Complete(data);
                Ok(())
            }
            Self::Complete(_) => Err("request already complete".to_owned()),
        }
    }

    fn to_finished(&self) -> Option<&T> {
        match self {
            Self::Active(_) => None,
            Self::Complete(data) => Some(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RangeBlockComponentsRequest;
    use beacon_chain::test_utils::{
        generate_rand_block_and_blobs, generate_rand_block_and_data_columns, test_spec, NumBlobs,
    };
    use lighthouse_network::service::api_types::{
        BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId,
        DataColumnsByRangeRequestId, Id, RangeRequestId,
    };
    use rand::SeedableRng;
    use std::sync::Arc;
    use types::{test_utils::XorShiftRng, Epoch, ForkName, MinimalEthSpec as E, SignedBeaconBlock};

    fn components_id() -> ComponentsByRangeRequestId {
        ComponentsByRangeRequestId {
            id: 0,
            requester: RangeRequestId::RangeSync {
                chain_id: 1,
                batch_id: Epoch::new(0),
            },
        }
    }

    fn blocks_id(parent_request_id: ComponentsByRangeRequestId) -> BlocksByRangeRequestId {
        BlocksByRangeRequestId {
            id: 1,
            parent_request_id,
        }
    }

    fn blobs_id(parent_request_id: ComponentsByRangeRequestId) -> BlobsByRangeRequestId {
        BlobsByRangeRequestId {
            id: 1,
            parent_request_id,
        }
    }

    fn columns_id(
        id: Id,
        parent_request_id: ComponentsByRangeRequestId,
    ) -> DataColumnsByRangeRequestId {
        DataColumnsByRangeRequestId {
            id,
            parent_request_id,
        }
    }

    fn is_finished(info: &RangeBlockComponentsRequest<E>) -> bool {
        let spec = test_spec::<E>();
        info.responses(&spec).is_some()
    }

    #[test]
    fn no_blobs_into_responses() {
        let spec = test_spec::<E>();
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_blobs::<E>(ForkName::Base, NumBlobs::None, &mut rng, &spec)
                    .0
                    .into()
            })
            .collect::<Vec<Arc<SignedBeaconBlock<E>>>>();

        let blocks_req_id = blocks_id(components_id());
        let mut info = RangeBlockComponentsRequest::<E>::new(blocks_req_id, None, None);

        // Send blocks and complete terminate response
        info.add_blocks(blocks_req_id, blocks).unwrap();

        // Assert response is finished and RpcBlocks can be constructed
        info.responses(&test_spec::<E>()).unwrap().unwrap();
    }

    #[test]
    fn empty_blobs_into_responses() {
        let spec = test_spec::<E>();
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                // Always generate some blobs.
                generate_rand_block_and_blobs::<E>(
                    ForkName::Deneb,
                    NumBlobs::Number(3),
                    &mut rng,
                    &spec,
                )
                .0
                .into()
            })
            .collect::<Vec<Arc<SignedBeaconBlock<E>>>>();

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let blobs_req_id = blobs_id(components_id);
        let mut info =
            RangeBlockComponentsRequest::<E>::new(blocks_req_id, Some(blobs_req_id), None);

        // Send blocks and complete terminate response
        info.add_blocks(blocks_req_id, blocks).unwrap();
        // Expect no blobs returned
        info.add_blobs(blobs_req_id, vec![]).unwrap();

        // Assert response is finished and RpcBlocks can be constructed, even if blobs weren't returned.
        // This makes sure we don't expect blobs here when they have expired. Checking this logic should
        // be hendled elsewhere.
        info.responses(&test_spec::<E>()).unwrap().unwrap();
    }

    #[test]
    fn rpc_block_with_custody_columns() {
        let spec = test_spec::<E>();
        let expects_custody_columns = vec![1, 2, 3, 4];
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Fulu,
                    NumBlobs::Number(1),
                    &mut rng,
                    &spec,
                )
            })
            .collect::<Vec<_>>();

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let columns_req_id = expects_custody_columns
            .iter()
            .enumerate()
            .map(|(i, _)| columns_id(i as Id, components_id))
            .collect::<Vec<_>>();
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some((columns_req_id.clone(), expects_custody_columns.clone())),
        );
        // Send blocks and complete terminate response
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
        )
        .unwrap();
        // Assert response is not finished
        assert!(!is_finished(&info));

        // Send data columns
        for (i, &column_index) in expects_custody_columns.iter().enumerate() {
            info.add_custody_columns(
                columns_req_id.get(i).copied().unwrap(),
                blocks
                    .iter()
                    .flat_map(|b| b.1.iter().filter(|d| d.index == column_index).cloned())
                    .collect(),
            )
            .unwrap();

            if i < expects_custody_columns.len() - 1 {
                assert!(
                    !is_finished(&info),
                    "requested should not be finished at loop {i}"
                );
            }
        }

        // All completed construct response
        info.responses(&spec).unwrap().unwrap();
    }

    #[test]
    fn rpc_block_with_custody_columns_batched() {
        let spec = test_spec::<E>();
        let batched_column_requests = [vec![1_u64, 2], vec![3, 4]];
        let expects_custody_columns = batched_column_requests
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        let custody_column_request_ids =
            (0..batched_column_requests.len() as u32).collect::<Vec<_>>();
        let num_of_data_column_requests = custody_column_request_ids.len();

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let columns_req_id = batched_column_requests
            .iter()
            .enumerate()
            .map(|(i, _)| columns_id(i as Id, components_id))
            .collect::<Vec<_>>();

        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some((columns_req_id.clone(), expects_custody_columns.clone())),
        );

        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Fulu,
                    NumBlobs::Number(1),
                    &mut rng,
                    &spec,
                )
            })
            .collect::<Vec<_>>();

        // Send blocks and complete terminate response
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
        )
        .unwrap();
        // Assert response is not finished
        assert!(!is_finished(&info));

        for (i, column_indices) in batched_column_requests.iter().enumerate() {
            // Send the set of columns in the same batch request
            info.add_custody_columns(
                columns_req_id.get(i).copied().unwrap(),
                blocks
                    .iter()
                    .flat_map(|b| {
                        b.1.iter()
                            .filter(|d| column_indices.contains(&d.index))
                            .cloned()
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();

            if i < num_of_data_column_requests - 1 {
                assert!(
                    !is_finished(&info),
                    "requested should not be finished at loop {i}"
                );
            }
        }

        // All completed construct response
        info.responses(&spec).unwrap().unwrap();
    }
}
