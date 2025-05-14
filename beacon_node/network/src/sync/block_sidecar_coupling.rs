use beacon_chain::{
    block_verification_types::RpcBlock, data_column_verification::CustodyDataColumn, get_block_root,
};
use lighthouse_network::{
    service::api_types::{
        BlobsByRangeRequestId, BlocksByRangeRequestId, DataColumnsByRangeRequestId,
    },
    PeerId,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use types::{
    BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec,
    Hash256, RuntimeVariableList, SignedBeaconBlock, Slot,
};

use super::range_sync::BatchPeers;

pub struct RangeBlockComponentsRequest<E: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    blocks_request: ByRangeRequest<BlocksByRangeRequestId, Vec<Arc<SignedBeaconBlock<E>>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    block_data_request: RangeBlockDataRequest<E>,
}

enum ByRangeRequest<I: PartialEq + std::fmt::Display, T> {
    Active(I),
    Complete(T, PeerId),
}

enum RangeBlockDataRequest<E: EthSpec> {
    /// All pre-deneb blocks
    NoData,
    /// All post-Deneb blocks, regardless of if they have data or not
    Blobs(ByRangeRequest<BlobsByRangeRequestId, Vec<Arc<BlobSidecar<E>>>>),
    /// All post-Fulu blocks, regardless of if they have data or not
    DataColumns {
        requests: HashMap<
            DataColumnsByRangeRequestId,
            ByRangeRequest<DataColumnsByRangeRequestId, DataColumnSidecarList<E>>,
        >,
        expected_column_to_peer: HashMap<ColumnIndex, PeerId>,
    },
}

impl<E: EthSpec> RangeBlockComponentsRequest<E> {
    pub fn new(
        blocks_req_id: BlocksByRangeRequestId,
        blobs_req_id: Option<BlobsByRangeRequestId>,
        data_columns: Option<(
            Vec<DataColumnsByRangeRequestId>,
            HashMap<ColumnIndex, PeerId>,
        )>,
    ) -> Self {
        let block_data_request = if let Some(blobs_req_id) = blobs_req_id {
            RangeBlockDataRequest::Blobs(ByRangeRequest::Active(blobs_req_id))
        } else if let Some((requests, expected_column_to_peer)) = data_columns {
            RangeBlockDataRequest::DataColumns {
                requests: requests
                    .into_iter()
                    .map(|id| (id, ByRangeRequest::Active(id)))
                    .collect(),
                expected_column_to_peer,
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
        peer_id: PeerId,
    ) -> Result<(), String> {
        self.blocks_request.finish(req_id, blocks, peer_id)
    }

    pub fn add_blobs(
        &mut self,
        req_id: BlobsByRangeRequestId,
        blobs: Vec<Arc<BlobSidecar<E>>>,
        peer_id: PeerId,
    ) -> Result<(), String> {
        match &mut self.block_data_request {
            RangeBlockDataRequest::NoData => Err("received blobs but expected no data".to_owned()),
            RangeBlockDataRequest::Blobs(ref mut req) => req.finish(req_id, blobs, peer_id),
            RangeBlockDataRequest::DataColumns { .. } => {
                Err("received blobs but expected data columns".to_owned())
            }
        }
    }

    pub fn add_custody_columns(
        &mut self,
        req_id: DataColumnsByRangeRequestId,
        columns: Vec<Arc<DataColumnSidecar<E>>>,
        peer_id: PeerId,
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
                req.finish(req_id, columns, peer_id)
            }
        }
    }

    /// If all internal requests are complete returns a Vec of coupled RpcBlocks
    #[allow(clippy::type_complexity)]
    pub fn responses(
        &self,
        spec: &ChainSpec,
    ) -> Option<Result<(Vec<RpcBlock<E>>, BatchPeers), String>> {
        let Some((blocks, &block_peer)) = self.blocks_request.to_finished() else {
            return None;
        };

        match &self.block_data_request {
            RangeBlockDataRequest::NoData => Some(
                Self::responses_with_blobs(blocks.to_vec(), vec![], spec)
                    .map(|blocks| (blocks, BatchPeers::new_from_block_peer(block_peer))),
            ),
            RangeBlockDataRequest::Blobs(request) => {
                let Some((blobs, _blob_peer)) = request.to_finished() else {
                    return None;
                };
                Some(
                    Self::responses_with_blobs(blocks.to_vec(), blobs.to_vec(), spec)
                        .map(|blocks| (blocks, BatchPeers::new_from_block_peer(block_peer))),
                )
            }
            RangeBlockDataRequest::DataColumns {
                requests,
                expected_column_to_peer,
            } => {
                let mut data_columns = vec![];
                let mut column_peers = HashMap::new();
                for req in requests.values() {
                    let Some((resp_columns, column_peer)) = req.to_finished() else {
                        return None;
                    };
                    data_columns.extend(resp_columns.clone());
                    for column in resp_columns {
                        column_peers.insert(column.index, *column_peer);
                    }
                }

                Some(
                    Self::responses_with_custody_columns(
                        blocks.to_vec(),
                        data_columns,
                        expected_column_to_peer.clone(),
                        spec,
                    )
                    .map(|blocks| (blocks, BatchPeers::new(block_peer, column_peers))),
                )
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
        expected_custody_columns: HashMap<ColumnIndex, PeerId>,
        spec: &ChainSpec,
    ) -> Result<Vec<RpcBlock<E>>, String> {
        // Group data columns by block_root and index
        let mut custody_columns_by_block = HashMap::<Hash256, Vec<CustodyDataColumn<E>>>::new();
        let mut block_roots_by_slot = HashMap::<Slot, HashSet<Hash256>>::new();
        let expected_custody_indices = expected_custody_columns.keys().cloned().collect::<Vec<_>>();

        for column in data_columns {
            let block_root = column.block_root();
            let index = column.index;

            block_roots_by_slot
                .entry(column.slot())
                .or_default()
                .insert(block_root);

            // Sanity check before casting to `CustodyDataColumn`. But this should never happen
            if !expected_custody_columns.contains_key(&index) {
                return Err(format!(
                    "Received column not in expected custody indices {index}"
                ));
            }

            custody_columns_by_block
                .entry(block_root)
                .or_default()
                .push(CustodyDataColumn::from_asserted_custody(column));
        }

        // Now iterate all blocks ensuring that the block roots of each block and data column match,
        // plus we have columns for our custody requirements
        let rpc_blocks = blocks
            .into_iter()
            .map(|block| {
                let block_root = get_block_root(&block);
                block_roots_by_slot
                    .entry(block.slot())
                    .or_default()
                    .insert(block_root);

                let custody_columns = custody_columns_by_block
                    .remove(&block_root)
                    .unwrap_or_default();

                RpcBlock::new_with_custody_columns(
                    Some(block_root),
                    block,
                    custody_columns,
                    expected_custody_indices.clone(),
                    spec,
                )
                .map_err(|e| format!("{e:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Assert that there are no columns left for other blocks
        if !custody_columns_by_block.is_empty() {
            let remaining_roots = custody_columns_by_block.keys().collect::<Vec<_>>();
            return Err(format!("Not all columns consumed: {remaining_roots:?}"));
        }

        for (_slot, block_roots) in block_roots_by_slot {
            if block_roots.len() > 1 {
                // TODO: Some peer(s) are faulty or malicious. This batch will fail processing but
                // we want to send it to the process to better attribute fault. Maybe warn log for
                // now and track it in a metric?
            }
        }

        Ok(rpc_blocks)
    }
}

impl<I: PartialEq + std::fmt::Display, T> ByRangeRequest<I, T> {
    fn finish(&mut self, id: I, data: T, peer_id: PeerId) -> Result<(), String> {
        match self {
            Self::Active(expected_id) => {
                if expected_id != &id {
                    return Err(format!("unexpected req_id expected {expected_id} got {id}"));
                }
                *self = Self::Complete(data, peer_id);
                Ok(())
            }
            Self::Complete(_, _) => Err("request already complete".to_owned()),
        }
    }

    fn to_finished(&self) -> Option<(&T, &PeerId)> {
        match self {
            Self::Active(_) => None,
            Self::Complete(data, peer_id) => Some((data, peer_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RangeBlockComponentsRequest;
    use beacon_chain::test_utils::{
        generate_rand_block_and_blobs, generate_rand_block_and_data_columns, test_spec, NumBlobs,
    };
    use lighthouse_network::{
        service::api_types::{
            BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId,
            DataColumnsByRangeRequestId, Id, RangeRequestId,
        },
        PeerId,
    };
    use rand::SeedableRng;
    use std::{collections::HashMap, sync::Arc};
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
        let peer = PeerId::random();
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
        info.add_blocks(blocks_req_id, blocks, peer).unwrap();

        // Assert response is finished and RpcBlocks can be constructed
        info.responses(&test_spec::<E>()).unwrap().unwrap();
    }

    #[test]
    fn empty_blobs_into_responses() {
        let spec = test_spec::<E>();
        let peer = PeerId::random();
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
        info.add_blocks(blocks_req_id, blocks, peer).unwrap();
        // Expect no blobs returned
        info.add_blobs(blobs_req_id, vec![], peer).unwrap();

        // Assert response is finished and RpcBlocks can be constructed, even if blobs weren't returned.
        // This makes sure we don't expect blobs here when they have expired. Checking this logic should
        // be hendled elsewhere.
        info.responses(&test_spec::<E>()).unwrap().unwrap();
    }

    #[test]
    fn rpc_block_with_custody_columns() {
        let spec = test_spec::<E>();
        let peer = PeerId::random();
        let expects_custody_columns = [1, 2, 3, 4];
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

        let column_to_peer = expects_custody_columns
            .iter()
            .map(|index| (*index, peer))
            .collect::<HashMap<_, _>>();

        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some((columns_req_id.clone(), column_to_peer)),
        );
        // Send blocks and complete terminate response
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
            peer,
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
                peer,
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
        let peer = PeerId::random();
        let batched_column_requests = [vec![1_u64, 2], vec![3, 4]];
        let expects_custody_columns = batched_column_requests
            .iter()
            .flatten()
            .map(|index| (*index, peer))
            .collect::<HashMap<_, _>>();
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
            peer,
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
                peer,
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
