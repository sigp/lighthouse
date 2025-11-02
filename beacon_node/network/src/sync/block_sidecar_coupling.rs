use beacon_chain::{
    block_verification_types::RpcBlock, data_column_verification::CustodyDataColumn, get_block_root,
};
use lighthouse_network::{
    PeerId,
    service::api_types::{
        BlobsByRangeRequestId, BlocksByRangeRequestId, DataColumnsByRangeRequestId,
    },
};
use std::{collections::HashMap, sync::Arc};
use tracing::{Span, debug};
use types::{
    BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec,
    Hash256, RuntimeVariableList, SignedBeaconBlock,
};

use crate::sync::network_context::MAX_COLUMN_RETRIES;

/// Accumulates and couples beacon blocks with their associated data (blobs or data columns)
/// from range sync network responses.
///
/// This struct acts as temporary storage while multiple network responses arrive:
/// - Blocks themselves (always required)
/// - Blob sidecars (pre-Fulu fork)
/// - Data columns (Fulu fork and later)
///
/// It accumulates responses until all expected components are received, then couples
/// them together and returns complete `RpcBlock`s ready for processing. Handles validation
/// and peer failure detection during the coupling process.
pub struct RangeBlockComponentsRequest<E: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    blocks_request: ByRangeRequest<BlocksByRangeRequestId, Vec<Arc<SignedBeaconBlock<E>>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    block_data_request: RangeBlockDataRequest<E>,
    /// Span to track the range request and all children range requests.
    pub(crate) request_span: Span,
}

pub enum ByRangeRequest<I: PartialEq + std::fmt::Display, T> {
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
        /// The column indices corresponding to the request
        column_peers: HashMap<DataColumnsByRangeRequestId, Vec<ColumnIndex>>,
        expected_custody_columns: Vec<ColumnIndex>,
        attempt: usize,
    },
}

#[derive(Debug)]
pub(crate) enum CouplingError {
    InternalError(String),
    /// The peer we requested the columns from was faulty/malicious
    DataColumnPeerFailure {
        error: String,
        faulty_peers: Vec<(ColumnIndex, PeerId)>,
        exceeded_retries: bool,
    },
    BlobPeerFailure(String),
}

impl<E: EthSpec> RangeBlockComponentsRequest<E> {
    /// Creates a new range request for blocks and their associated data (blobs or data columns).
    ///
    /// # Arguments
    /// * `blocks_req_id` - Request ID for the blocks
    /// * `blobs_req_id` - Optional request ID for blobs (pre-Fulu fork)
    /// * `data_columns` - Optional tuple of (request_id->column_indices pairs, expected_custody_columns) for Fulu fork
    #[allow(clippy::type_complexity)]
    pub fn new(
        blocks_req_id: BlocksByRangeRequestId,
        blobs_req_id: Option<BlobsByRangeRequestId>,
        data_columns: Option<(
            Vec<(DataColumnsByRangeRequestId, Vec<ColumnIndex>)>,
            Vec<ColumnIndex>,
        )>,
        request_span: Span,
    ) -> Self {
        let block_data_request = if let Some(blobs_req_id) = blobs_req_id {
            RangeBlockDataRequest::Blobs(ByRangeRequest::Active(blobs_req_id))
        } else if let Some((requests, expected_custody_columns)) = data_columns {
            let column_peers: HashMap<_, _> = requests.into_iter().collect();
            RangeBlockDataRequest::DataColumns {
                requests: column_peers
                    .keys()
                    .map(|id| (*id, ByRangeRequest::Active(*id)))
                    .collect(),
                column_peers,
                expected_custody_columns,
                attempt: 0,
            }
        } else {
            RangeBlockDataRequest::NoData
        };

        Self {
            blocks_request: ByRangeRequest::Active(blocks_req_id),
            block_data_request,
            request_span,
        }
    }

    /// Modifies `self` by inserting a new `DataColumnsByRangeRequestId` for a formerly failed
    /// request for some columns.
    pub fn reinsert_failed_column_requests(
        &mut self,
        failed_column_requests: Vec<(DataColumnsByRangeRequestId, Vec<u64>)>,
    ) -> Result<(), String> {
        match &mut self.block_data_request {
            RangeBlockDataRequest::DataColumns {
                requests,
                expected_custody_columns: _,
                column_peers,
                attempt: _,
            } => {
                for (request, columns) in failed_column_requests.into_iter() {
                    requests.insert(request, ByRangeRequest::Active(request));
                    column_peers.insert(request, columns);
                }
                Ok(())
            }
            _ => Err("not a column request".to_string()),
        }
    }

    /// Adds received blocks to the request.
    ///
    /// Returns an error if the request ID doesn't match the expected blocks request.
    pub fn add_blocks(
        &mut self,
        req_id: BlocksByRangeRequestId,
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
    ) -> Result<(), String> {
        self.blocks_request.finish(req_id, blocks)
    }

    /// Adds received blobs to the request.
    ///
    /// Returns an error if this request expects data columns instead of blobs,
    /// or if the request ID doesn't match.
    pub fn add_blobs(
        &mut self,
        req_id: BlobsByRangeRequestId,
        blobs: Vec<Arc<BlobSidecar<E>>>,
    ) -> Result<(), String> {
        match &mut self.block_data_request {
            RangeBlockDataRequest::NoData => Err("received blobs but expected no data".to_owned()),
            RangeBlockDataRequest::Blobs(req) => req.finish(req_id, blobs),
            RangeBlockDataRequest::DataColumns { .. } => {
                Err("received blobs but expected data columns".to_owned())
            }
        }
    }

    /// Adds received custody columns to the request.
    ///
    /// Returns an error if this request expects blobs instead of data columns,
    /// or if the request ID is unknown.
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
            RangeBlockDataRequest::DataColumns { requests, .. } => {
                let req = requests
                    .get_mut(&req_id)
                    .ok_or(format!("unknown data columns by range req_id {req_id}"))?;
                req.finish(req_id, columns)
            }
        }
    }

    /// Attempts to construct RPC blocks from all received components.
    ///
    /// Returns `None` if not all expected requests have completed.
    /// Returns `Some(Ok(_))` with valid RPC blocks if all data is present and valid.
    /// Returns `Some(Err(_))` if there are issues coupling blocks with their data.
    pub fn responses(
        &mut self,
        spec: &ChainSpec,
    ) -> Option<Result<Vec<RpcBlock<E>>, CouplingError>> {
        let Some(blocks) = self.blocks_request.to_finished() else {
            return None;
        };

        // Increment the attempt once this function returns the response or errors
        match &mut self.block_data_request {
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
                column_peers,
                attempt,
            } => {
                let mut data_columns = vec![];
                let mut column_to_peer_id: HashMap<u64, PeerId> = HashMap::new();
                for req in requests.values() {
                    let Some(data) = req.to_finished() else {
                        return None;
                    };
                    data_columns.extend(data.clone())
                }

                // An "attempt" is complete here after we have received a response for all the
                // requests we made. i.e. `req.to_finished()` returns Some for all requests.
                *attempt += 1;

                // Note: this assumes that only 1 peer is responsible for a column
                // with a batch.
                for (id, columns) in column_peers {
                    for column in columns {
                        column_to_peer_id.insert(*column, id.peer);
                    }
                }

                let resp = Self::responses_with_custody_columns(
                    blocks.to_vec(),
                    data_columns,
                    column_to_peer_id,
                    expected_custody_columns,
                    *attempt,
                );

                if let Err(CouplingError::DataColumnPeerFailure {
                    error: _,
                    faulty_peers,
                    exceeded_retries: _,
                }) = &resp
                {
                    for (_, peer) in faulty_peers.iter() {
                        // find the req id associated with the peer and
                        // delete it from the entries as we are going to make
                        // a separate attempt for those components.
                        requests.retain(|&k, _| k.peer != *peer);
                    }
                }

                Some(resp)
            }
        }
    }

    fn responses_with_blobs(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        blobs: Vec<Arc<BlobSidecar<E>>>,
        spec: &ChainSpec,
    ) -> Result<Vec<RpcBlock<E>>, CouplingError> {
        // There can't be more more blobs than blocks. i.e. sending any blob (empty
        // included) for a skipped slot is not permitted.
        let mut responses = Vec::with_capacity(blocks.len());
        let mut blob_iter = blobs.into_iter().peekable();
        for block in blocks.into_iter() {
            let max_blobs_per_block = spec.max_blobs_per_block(block.epoch()) as usize;
            let mut blob_list = Vec::with_capacity(max_blobs_per_block);
            while {
                blob_iter
                    .peek()
                    .map(|sidecar| sidecar.slot() == block.slot())
                    .unwrap_or(false)
            } {
                blob_list.push(blob_iter.next().ok_or_else(|| {
                    CouplingError::BlobPeerFailure("Missing next blob".to_string())
                })?);
            }

            let mut blobs_buffer = vec![None; max_blobs_per_block];
            for blob in blob_list {
                let blob_index = blob.index as usize;
                let Some(blob_opt) = blobs_buffer.get_mut(blob_index) else {
                    return Err(CouplingError::BlobPeerFailure(
                        "Invalid blob index".to_string(),
                    ));
                };
                if blob_opt.is_some() {
                    return Err(CouplingError::BlobPeerFailure(
                        "Repeat blob index".to_string(),
                    ));
                } else {
                    *blob_opt = Some(blob);
                }
            }
            let blobs = RuntimeVariableList::new(
                blobs_buffer.into_iter().flatten().collect::<Vec<_>>(),
                max_blobs_per_block,
            )
            .map_err(|_| {
                CouplingError::BlobPeerFailure("Blobs returned exceeds max length".to_string())
            })?;
            responses.push(
                RpcBlock::new(None, block, Some(blobs))
                    .map_err(|e| CouplingError::BlobPeerFailure(format!("{e:?}")))?,
            )
        }

        // if accumulated sidecars is not empty, log an error but return the responses
        // as we can still make progress.
        if blob_iter.next().is_some() {
            let remaining_blobs = blob_iter
                .map(|b| (b.index, b.block_root()))
                .collect::<Vec<_>>();
            debug!(?remaining_blobs, "Received sidecars that don't pair well",);
        }

        Ok(responses)
    }

    fn responses_with_custody_columns(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        data_columns: DataColumnSidecarList<E>,
        column_to_peer: HashMap<u64, PeerId>,
        expects_custody_columns: &[ColumnIndex],
        attempt: usize,
    ) -> Result<Vec<RpcBlock<E>>, CouplingError> {
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
                // `DataColumnsByRangeRequestItems` ensures that we do not request any duplicated indices across all peers
                // we request the data from.
                // If there are duplicated indices, its likely a peer sending us the same index multiple times.
                // However we can still proceed even if there are extra columns, just log an error.
                tracing::debug!(?block_root, ?index, "Repeated column for block_root");
                continue;
            }
        }

        // Now iterate all blocks ensuring that the block roots of each block and data column match,
        // plus we have columns for our custody requirements
        let mut rpc_blocks = Vec::with_capacity(blocks.len());

        let exceeded_retries = attempt >= MAX_COLUMN_RETRIES;
        for block in blocks {
            let block_root = get_block_root(&block);
            rpc_blocks.push(if block.num_expected_blobs() > 0 {
                let Some(mut data_columns_by_index) = data_columns_by_block.remove(&block_root)
                else {
                    let responsible_peers = column_to_peer.iter().map(|c| (*c.0, *c.1)).collect();
                    return Err(CouplingError::DataColumnPeerFailure {
                        error: format!("No columns for block {block_root:?} with data"),
                        faulty_peers: responsible_peers,
                        exceeded_retries,

                    });
                };

                let mut custody_columns = vec![];
                let mut naughty_peers = vec![];
                for index in expects_custody_columns {
                    // Safe to convert to `CustodyDataColumn`: we have asserted that the index of
                    // this column is in the set of `expects_custody_columns` and with the expected
                    // block root, so for the expected epoch of this batch.
                    if let Some(data_column) = data_columns_by_index.remove(index) {
                        custody_columns.push(CustodyDataColumn::from_asserted_custody(data_column));
                    } else {
                        let Some(responsible_peer) = column_to_peer.get(index) else {
                            return Err(CouplingError::InternalError(format!("Internal error, no request made for column {}", index)));
                        };
                        naughty_peers.push((*index, *responsible_peer));
                    }
                }
                if !naughty_peers.is_empty() {
                    return Err(CouplingError::DataColumnPeerFailure {
                        error: format!("Peers did not return column for block_root {block_root:?} {naughty_peers:?}"),
                        faulty_peers: naughty_peers,
                        exceeded_retries
                    });
                }

                // Assert that there are no columns left
                if !data_columns_by_index.is_empty() {
                    let remaining_indices = data_columns_by_index.keys().collect::<Vec<_>>();
                    // log the error but don't return an error, we can still progress with extra columns.
                    tracing::debug!(
                        ?block_root,
                        ?remaining_indices,
                        "Not all columns consumed for block"
                    );
                }

                RpcBlock::new_with_custody_columns(Some(block_root), block, custody_columns)
                    .map_err(|e| CouplingError::InternalError(format!("{:?}", e)))?
            } else {
                // Block has no data, expects zero columns
                RpcBlock::new_without_blobs(Some(block_root), block)
            });
        }

        // Assert that there are no columns left for other blocks
        if !data_columns_by_block.is_empty() {
            let remaining_roots = data_columns_by_block.keys().collect::<Vec<_>>();
            // log the error but don't return an error, we can still progress with responses.
            // this is most likely an internal error with overrequesting or a client bug.
            tracing::debug!(?remaining_roots, "Not all columns consumed for block");
        }

        Ok(rpc_blocks)
    }
}

impl<I: PartialEq + std::fmt::Display, T> ByRangeRequest<I, T> {
    pub fn finish(&mut self, id: I, data: T) -> Result<(), String> {
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

    pub fn to_finished(&self) -> Option<&T> {
        match self {
            Self::Active(_) => None,
            Self::Complete(data) => Some(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RangeBlockComponentsRequest;
    use crate::sync::network_context::MAX_COLUMN_RETRIES;
    use beacon_chain::test_utils::{
        NumBlobs, generate_rand_block_and_blobs, generate_rand_block_and_data_columns, test_spec,
    };
    use lighthouse_network::{
        PeerId,
        service::api_types::{
            BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId,
            DataColumnsByRangeRequestId, DataColumnsByRangeRequester, Id, RangeRequestId,
        },
    };
    use rand::SeedableRng;
    use std::sync::Arc;
    use tracing::Span;
    use types::{Epoch, ForkName, MinimalEthSpec as E, SignedBeaconBlock, test_utils::XorShiftRng};

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
        parent_request_id: DataColumnsByRangeRequester,
    ) -> DataColumnsByRangeRequestId {
        DataColumnsByRangeRequestId {
            id,
            parent_request_id,
            peer: PeerId::random(),
        }
    }

    fn is_finished(info: &mut RangeBlockComponentsRequest<E>) -> bool {
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
        let mut info =
            RangeBlockComponentsRequest::<E>::new(blocks_req_id, None, None, Span::none());

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
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            Some(blobs_req_id),
            None,
            Span::none(),
        );

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
            .map(|(i, column)| {
                (
                    columns_id(
                        i as Id,
                        DataColumnsByRangeRequester::ComponentsByRange(components_id),
                    ),
                    vec![*column],
                )
            })
            .collect::<Vec<_>>();
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some((columns_req_id.clone(), expects_custody_columns.clone())),
            Span::none(),
        );
        // Send blocks and complete terminate response
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
        )
        .unwrap();
        // Assert response is not finished
        assert!(!is_finished(&mut info));

        // Send data columns
        for (i, &column_index) in expects_custody_columns.iter().enumerate() {
            let (req, _columns) = columns_req_id.get(i).unwrap();
            info.add_custody_columns(
                *req,
                blocks
                    .iter()
                    .flat_map(|b| b.1.iter().filter(|d| d.index == column_index).cloned())
                    .collect(),
            )
            .unwrap();

            if i < expects_custody_columns.len() - 1 {
                assert!(
                    !is_finished(&mut info),
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
            .map(|(i, columns)| {
                (
                    columns_id(
                        i as Id,
                        DataColumnsByRangeRequester::ComponentsByRange(components_id),
                    ),
                    columns.clone(),
                )
            })
            .collect::<Vec<_>>();

        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some((columns_req_id.clone(), expects_custody_columns.clone())),
            Span::none(),
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
        assert!(!is_finished(&mut info));

        for (i, column_indices) in batched_column_requests.iter().enumerate() {
            let (req, _columns) = columns_req_id.get(i).unwrap();
            // Send the set of columns in the same batch request
            info.add_custody_columns(
                *req,
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
                    !is_finished(&mut info),
                    "requested should not be finished at loop {i}"
                );
            }
        }

        // All completed construct response
        info.responses(&spec).unwrap().unwrap();
    }

    #[test]
    fn missing_custody_columns_from_faulty_peers() {
        // GIVEN: A request expecting custody columns from multiple peers
        let spec = test_spec::<E>();
        let expected_custody_columns = vec![1, 2, 3, 4];
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..2)
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
        let columns_req_id = expected_custody_columns
            .iter()
            .enumerate()
            .map(|(i, column)| {
                (
                    columns_id(
                        i as Id,
                        DataColumnsByRangeRequester::ComponentsByRange(components_id),
                    ),
                    vec![*column],
                )
            })
            .collect::<Vec<_>>();
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some((columns_req_id.clone(), expected_custody_columns.clone())),
            Span::none(),
        );

        // AND: All blocks are received successfully
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
        )
        .unwrap();

        // AND: Only some custody columns are received (columns 1 and 2)
        for (i, &column_index) in expected_custody_columns.iter().take(2).enumerate() {
            let (req, _columns) = columns_req_id.get(i).unwrap();
            info.add_custody_columns(
                *req,
                blocks
                    .iter()
                    .flat_map(|b| b.1.iter().filter(|d| d.index == column_index).cloned())
                    .collect(),
            )
            .unwrap();
        }

        // AND: Remaining column requests are completed with empty data (simulating faulty peers)
        for i in 2..4 {
            let (req, _columns) = columns_req_id.get(i).unwrap();
            info.add_custody_columns(*req, vec![]).unwrap();
        }

        // WHEN: Attempting to construct RPC blocks
        let result = info.responses(&spec).unwrap();

        // THEN: Should fail with PeerFailure identifying the faulty peers
        assert!(result.is_err());
        if let Err(super::CouplingError::DataColumnPeerFailure {
            error,
            faulty_peers,
            exceeded_retries,
        }) = result
        {
            assert!(error.contains("Peers did not return column"));
            assert_eq!(faulty_peers.len(), 2); // columns 3 and 4 missing
            assert_eq!(faulty_peers[0].0, 3); // column index 3
            assert_eq!(faulty_peers[1].0, 4); // column index 4
            assert!(!exceeded_retries); // First attempt, should be false
        } else {
            panic!("Expected PeerFailure error");
        }
    }

    #[test]
    fn retry_logic_after_peer_failures() {
        // GIVEN: A request expecting custody columns where some peers initially fail
        let spec = test_spec::<E>();
        let expected_custody_columns = vec![1, 2];
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..2)
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
        let columns_req_id = expected_custody_columns
            .iter()
            .enumerate()
            .map(|(i, column)| {
                (
                    columns_id(
                        i as Id,
                        DataColumnsByRangeRequester::ComponentsByRange(components_id),
                    ),
                    vec![*column],
                )
            })
            .collect::<Vec<_>>();
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some((columns_req_id.clone(), expected_custody_columns.clone())),
            Span::none(),
        );

        // AND: All blocks are received
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
        )
        .unwrap();

        // AND: Only partial custody columns are received (column 1 but not 2)
        let (req1, _) = columns_req_id.first().unwrap();
        info.add_custody_columns(
            *req1,
            blocks
                .iter()
                .flat_map(|b| b.1.iter().filter(|d| d.index == 1).cloned())
                .collect(),
        )
        .unwrap();

        // AND: The missing column request is completed with empty data (peer failure)
        let (req2, _) = columns_req_id.get(1).unwrap();
        info.add_custody_columns(*req2, vec![]).unwrap();

        // WHEN: First attempt to get responses fails
        let result = info.responses(&spec).unwrap();
        assert!(result.is_err());

        // AND: We retry with a new peer for the failed column
        let new_columns_req_id = columns_id(
            10 as Id,
            DataColumnsByRangeRequester::ComponentsByRange(components_id),
        );
        let failed_column_requests = vec![(new_columns_req_id, vec![2])];
        info.reinsert_failed_column_requests(failed_column_requests)
            .unwrap();

        // AND: The new peer provides the missing column data
        info.add_custody_columns(
            new_columns_req_id,
            blocks
                .iter()
                .flat_map(|b| b.1.iter().filter(|d| d.index == 2).cloned())
                .collect(),
        )
        .unwrap();

        // WHEN: Attempting to get responses again
        let result = info.responses(&spec).unwrap();

        // THEN: Should succeed with complete RPC blocks
        assert!(result.is_ok());
        let rpc_blocks = result.unwrap();
        assert_eq!(rpc_blocks.len(), 2);
    }

    #[test]
    fn max_retries_exceeded_behavior() {
        // GIVEN: A request where peers consistently fail to provide required columns
        let spec = test_spec::<E>();
        let expected_custody_columns = vec![1, 2];
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..1)
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
        let columns_req_id = expected_custody_columns
            .iter()
            .enumerate()
            .map(|(i, column)| {
                (
                    columns_id(
                        i as Id,
                        DataColumnsByRangeRequester::ComponentsByRange(components_id),
                    ),
                    vec![*column],
                )
            })
            .collect::<Vec<_>>();
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some((columns_req_id.clone(), expected_custody_columns.clone())),
            Span::none(),
        );

        // AND: All blocks are received
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
        )
        .unwrap();

        // AND: Only partial custody columns are provided (column 1 but not 2)
        let (req1, _) = columns_req_id.first().unwrap();
        info.add_custody_columns(
            *req1,
            blocks
                .iter()
                .flat_map(|b| b.1.iter().filter(|d| d.index == 1).cloned())
                .collect(),
        )
        .unwrap();

        // AND: Column 2 request completes with empty data (persistent peer failure)
        let (req2, _) = columns_req_id.get(1).unwrap();
        info.add_custody_columns(*req2, vec![]).unwrap();

        // WHEN: Multiple retry attempts are made (up to max retries)
        for _ in 0..MAX_COLUMN_RETRIES {
            let result = info.responses(&spec).unwrap();
            assert!(result.is_err());

            if let Err(super::CouplingError::DataColumnPeerFailure {
                exceeded_retries, ..
            }) = &result
                && *exceeded_retries
            {
                break;
            }
        }

        // AND: One final attempt after exceeding max retries
        let result = info.responses(&spec).unwrap();

        // THEN: Should fail with exceeded_retries = true
        assert!(result.is_err());
        if let Err(super::CouplingError::DataColumnPeerFailure {
            error: _,
            faulty_peers,
            exceeded_retries,
        }) = result
        {
            assert_eq!(faulty_peers.len(), 1); // column 2 missing
            assert_eq!(faulty_peers[0].0, 2); // column index 2
            assert!(exceeded_retries); // Should be true after max retries
        } else {
            panic!("Expected PeerFailure error with exceeded_retries=true");
        }
    }
}
