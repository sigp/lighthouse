use beacon_chain::payload_envelope_verification::AvailableEnvelope;
use beacon_chain::{
    BeaconChainTypes,
    block_verification_types::{AvailableBlockData, RangeSyncBlock},
    data_availability_checker::DataAvailabilityChecker,
    data_column_verification::CustodyDataColumn,
    get_block_root,
};
use lighthouse_network::{
    PeerId,
    service::api_types::{
        BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId,
        CustodyRequester, PayloadEnvelopesByRangeRequestId, RangeSyncCustodyId,
    },
};
use parking_lot::RwLock;
use ssz_types::RuntimeVariableList;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, warn};
use types::{
    BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec,
    Hash256, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
};

use crate::sync::network_context::{LookupRequestResult, PeerGroup, SyncNetworkContext};

/// Accumulates and couples beacon blocks with their associated data (blobs or data columns)
/// from range sync network responses.
///
/// This struct acts as temporary storage while multiple network responses arrive:
/// - Blocks themselves (always required)
/// - Blob sidecars (pre-Fulu fork)
/// - Data columns (Fulu fork and later, via custody-by-root)
/// - Payload envelopes (Gloas fork and later)
///
/// It accumulates responses until all expected components are received, then couples
/// them together and returns complete `RangeSyncBlock`s ready for processing.
pub struct RangeBlockComponentsRequest<E: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    blocks_request: ByRangeRequest<BlocksByRangeRequestId, Vec<Arc<SignedBeaconBlock<E>>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    block_data_request: RangeBlockDataRequest<E>,
    /// Payload envelopes for Gloas blocks.
    payloads_request: Option<
        ByRangeRequest<
            PayloadEnvelopesByRangeRequestId,
            Vec<Arc<SignedExecutionPayloadEnvelope<E>>>,
        >,
    >,
}

pub enum ByRangeRequest<I: PartialEq + std::fmt::Display, T> {
    Active(I),
    Complete(T),
}

enum RangeBlockDataRequest<E: EthSpec> {
    NoData,
    Blobs(ByRangeRequest<BlobsByRangeRequestId, Vec<Arc<BlobSidecar<E>>>>),
    DataColumns {
        /// Per-block-root custody-by-root state. Populated by `continue_requests` once blocks
        /// arrive and completed by `add_custody_columns` as each custody-by-root request resolves.
        custody_columns_by_root: HashMap<Hash256, DataColumnsState<E>>,
        /// The custody columns we expect for each block with data in this batch.
        expected_custody_columns: Vec<ColumnIndex>,
    },
}

#[derive(Clone)]
enum DataColumnsState<E: EthSpec> {
    Requesting,
    Complete(DataColumnSidecarList<E>, PeerGroup),
}

#[derive(Debug)]
pub enum CouplingError {
    InternalError(String),
    /// The peer we requested the columns from was faulty/malicious
    DataColumnPeerFailure {
        error: String,
        faulty_peers: Vec<(ColumnIndex, PeerId)>,
    },
    BlobPeerFailure(String),
    EnvelopePeerFailure(String),
}

impl<E: EthSpec> RangeBlockComponentsRequest<E> {
    /// Creates a new range request for blocks and their associated data (blobs or data columns).
    ///
    /// # Arguments
    /// * `blocks_req_id` - Request ID for the blocks
    /// * `blobs_req_id` - Optional request ID for blobs (pre-Fulu fork)
    /// * `expects_custody_columns` - If Some, custody-by-root will be used after blocks arrive
    /// * `payloads_req_id` - Optional request ID for payload envelopes (Gloas fork)
    pub fn new(
        blocks_req_id: BlocksByRangeRequestId,
        blobs_req_id: Option<BlobsByRangeRequestId>,
        expects_custody_columns: Option<Vec<ColumnIndex>>,
        payloads_req_id: Option<PayloadEnvelopesByRangeRequestId>,
    ) -> Self {
        let block_data_request = if let Some(blobs_req_id) = blobs_req_id {
            RangeBlockDataRequest::Blobs(ByRangeRequest::Active(blobs_req_id))
        } else if let Some(expected_custody_columns) = expects_custody_columns {
            RangeBlockDataRequest::DataColumns {
                custody_columns_by_root: HashMap::new(),
                expected_custody_columns,
            }
        } else {
            RangeBlockDataRequest::NoData
        };

        Self {
            blocks_request: ByRangeRequest::Active(blocks_req_id),
            block_data_request,
            payloads_request: payloads_req_id.map(ByRangeRequest::Active),
        }
    }

    /// Returns true if the blocks component of this request has been received.
    pub fn blocks_received(&self) -> bool {
        self.blocks_request.to_finished().is_some()
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

    /// Adds received custody columns for a specific block root.
    ///
    /// Returns an error if not in DataColumns mode, or if columns for this root
    /// were already completed or never registered.
    pub fn add_custody_columns(
        &mut self,
        block_root: Hash256,
        columns: DataColumnSidecarList<E>,
        peer_group: PeerGroup,
    ) -> Result<(), String> {
        let RangeBlockDataRequest::DataColumns {
            custody_columns_by_root,
            ..
        } = &mut self.block_data_request
        else {
            return Err("received custody columns but not in DataColumns mode".to_owned());
        };
        match custody_columns_by_root.get(&block_root) {
            Some(DataColumnsState::Complete(..)) => Err(format!(
                "duplicate custody columns for block root {block_root:?}"
            )),
            None => Err(format!(
                "received custody columns for unregistered block root {block_root:?}"
            )),
            Some(DataColumnsState::Requesting) => {
                custody_columns_by_root
                    .insert(block_root, DataColumnsState::Complete(columns, peer_group));
                Ok(())
            }
        }
    }

    pub fn add_payload_envelopes(
        &mut self,
        req_id: PayloadEnvelopesByRangeRequestId,
        envelopes: Vec<Arc<SignedExecutionPayloadEnvelope<E>>>,
    ) -> Result<(), String> {
        match &mut self.payloads_request {
            Some(req) => req.finish(req_id, envelopes),
            None => Err("received payload envelopes but none were expected".to_owned()),
        }
    }

    /// After blocks arrive, initiates custody-by-root requests for blocks that need data columns.
    ///
    /// Only does work when blocks have arrived and we're in DataColumns mode. For each block
    /// with data, inserts a `Requesting` entry and fires a custody request via the network context.
    pub fn continue_requests<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        id: ComponentsByRangeRequestId,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), String> {
        let Some(blocks) = self.blocks_request.to_finished() else {
            return Ok(());
        };
        let RangeBlockDataRequest::DataColumns {
            custody_columns_by_root,
            ..
        } = &mut self.block_data_request
        else {
            return Ok(());
        };

        let mut errors = vec![];

        for block in blocks {
            if block.num_expected_blobs() == 0 {
                continue;
            }
            let block_root = get_block_root(block);
            if custody_columns_by_root.contains_key(&block_root) {
                continue;
            }

            let requester = CustodyRequester::RangeSync(RangeSyncCustodyId { id, block_root });
            match cx.custody_lookup_request(
                requester,
                block_root,
                block.slot(),
                // ignore_cache: range blocks are historical and won't have gossip-imported columns
                true,
                Arc::new(RwLock::new(HashSet::new())),
            ) {
                Ok(LookupRequestResult::RequestSent(_)) => {
                    custody_columns_by_root.insert(block_root, DataColumnsState::Requesting);
                    debug!(?block_root, %id, "Initiated custody-by-root for range block");
                }
                Ok(LookupRequestResult::NoRequestNeeded(reason, _)) => {
                    // All columns already available (e.g. arrived via gossip). Mark as complete.
                    debug!(?block_root, %id, %reason, "Custody-by-root not needed for range block");
                    custody_columns_by_root.insert(
                        block_root,
                        DataColumnsState::Complete(vec![], PeerGroup::from_set(Default::default())),
                    );
                }
                Ok(LookupRequestResult::Pending(reason)) => {
                    errors.push(format!(
                        "Custody request for {block_root:?} pending: {reason}"
                    ));
                }
                Err(e) => {
                    errors.push(format!(
                        "Failed to initiate custody for {block_root:?}: {e:?}"
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Registers a block root as awaiting custody columns. Used in tests to simulate
    /// the effect of `continue_requests` without requiring a full network context.
    #[cfg(test)]
    pub fn register_custody_block(&mut self, block_root: Hash256) {
        if let RangeBlockDataRequest::DataColumns {
            custody_columns_by_root,
            ..
        } = &mut self.block_data_request
        {
            custody_columns_by_root.insert(block_root, DataColumnsState::Requesting);
        }
    }

    /// Attempts to construct RPC blocks from all received components.
    ///
    /// Returns `None` if not all expected requests have completed.
    /// Returns `Some(Ok(_))` with valid RPC blocks if all data is present and valid.
    /// Returns `Some(Err(_))` if there are issues coupling blocks with their data.
    pub fn responses<T>(
        &mut self,
        da_checker: Arc<DataAvailabilityChecker<T>>,
        spec: Arc<ChainSpec>,
    ) -> Option<Result<Vec<RangeSyncBlock<E>>, CouplingError>>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        let Some(blocks) = self.blocks_request.to_finished() else {
            return None;
        };

        // Check if payload envelopes are still pending
        if let Some(ByRangeRequest::Active(_)) = &self.payloads_request {
            return None;
        }

        match &self.block_data_request {
            RangeBlockDataRequest::NoData => Some(Self::responses_with_blobs(
                blocks.to_vec(),
                vec![],
                da_checker,
                spec,
            )),
            RangeBlockDataRequest::Blobs(request) => {
                let Some(blobs) = request.to_finished() else {
                    return None;
                };
                Some(Self::responses_with_blobs(
                    blocks.to_vec(),
                    blobs.to_vec(),
                    da_checker,
                    spec,
                ))
            }
            RangeBlockDataRequest::DataColumns {
                custody_columns_by_root,
                expected_custody_columns,
            } => {
                // Wait until every registered custody-by-root request has resolved.
                if custody_columns_by_root
                    .values()
                    .any(|s| matches!(s, DataColumnsState::Requesting))
                {
                    return None;
                }

                let payload_envelopes = self.payloads_request.as_ref().and_then(|request| {
                    request
                        .to_finished()
                        .map(|payload_envelopes| payload_envelopes.to_vec())
                });

                Some(Self::responses_with_custody_columns(
                    blocks.to_vec(),
                    custody_columns_by_root.clone(),
                    expected_custody_columns,
                    da_checker,
                    spec,
                    payload_envelopes,
                ))
            }
        }
    }

    fn responses_with_blobs<T>(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        blobs: Vec<Arc<BlobSidecar<E>>>,
        da_checker: Arc<DataAvailabilityChecker<T>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Vec<RangeSyncBlock<E>>, CouplingError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
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
            let block_data = AvailableBlockData::new_with_blobs(blobs);
            responses.push(
                RangeSyncBlock::new(block, block_data, &da_checker, spec.clone())
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

    #[allow(clippy::too_many_arguments)]
    fn responses_with_custody_columns<T>(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        custody_columns_by_root: HashMap<Hash256, DataColumnsState<E>>,
        expects_custody_columns: &[ColumnIndex],
        da_checker: Arc<DataAvailabilityChecker<T>>,
        spec: Arc<ChainSpec>,
        payload_envelopes: Option<Vec<Arc<SignedExecutionPayloadEnvelope<E>>>>,
    ) -> Result<Vec<RangeSyncBlock<E>>, CouplingError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        // Index envelopes by beacon_block_root for correct coupling.
        let mut envelopes_by_block_root = payload_envelopes.map(|envelopes| {
            envelopes
                .into_iter()
                .map(|e| (e.beacon_block_root(), e))
                .collect::<HashMap<_, _>>()
        });

        let mut custody_columns_by_root = custody_columns_by_root;
        let mut range_sync_blocks = Vec::with_capacity(blocks.len());

        for block in blocks {
            let block_root = get_block_root(&block);
            let custody_columns = if block.num_expected_blobs() > 0 {
                let Some(DataColumnsState::Complete(data_columns, _peer_group)) =
                    custody_columns_by_root.remove(&block_root)
                else {
                    return Err(CouplingError::InternalError(format!(
                        "No columns for block {block_root:?} with data"
                    )));
                };

                let mut data_columns_by_index =
                    HashMap::<ColumnIndex, Arc<DataColumnSidecar<E>>>::new();
                for column in data_columns {
                    let index = *column.index();
                    if data_columns_by_index.insert(index, column).is_some() {
                        debug!(?block_root, ?index, "Repeated column for block_root");
                    }
                }

                let mut custody_columns = vec![];
                for index in expects_custody_columns {
                    // Safe to convert to `CustodyDataColumn`: the custody-by-root request only
                    // returns columns for the expected block root and custody indices.
                    if let Some(data_column) = data_columns_by_index.remove(index) {
                        custody_columns.push(CustodyDataColumn::from_asserted_custody(data_column));
                    } else {
                        return Err(CouplingError::InternalError(format!(
                            "Missing custody column {index} for block {block_root:?}"
                        )));
                    }
                }

                // Assert that there are no columns left
                if !data_columns_by_index.is_empty() {
                    let remaining_indices = data_columns_by_index.keys().collect::<Vec<_>>();
                    debug!(
                        ?block_root,
                        ?remaining_indices,
                        "Not all columns consumed for block"
                    );
                }

                custody_columns
                    .iter()
                    .map(|c| c.as_data_column().clone())
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };

            let range_sync_block = if let Some(envelopes_by_block_root) =
                envelopes_by_block_root.as_mut()
            {
                let envelope = envelopes_by_block_root.remove(&block_root);
                let available_envelope =
                    envelope.map(|env| AvailableEnvelope::new(env, custody_columns));

                RangeSyncBlock::new_gloas(block, available_envelope)
                    .map_err(CouplingError::EnvelopePeerFailure)?
            } else if custody_columns.is_empty() {
                RangeSyncBlock::new(block, AvailableBlockData::NoData, &da_checker, spec.clone())
                    .map_err(|e| CouplingError::InternalError(format!("{:?}", e)))?
            } else {
                let block_data = AvailableBlockData::new_with_data_columns(custody_columns);
                RangeSyncBlock::new(block, block_data, &da_checker, spec.clone())
                    .map_err(|e| CouplingError::InternalError(format!("{:?}", e)))?
            };
            range_sync_blocks.push(range_sync_block);
        }

        // Assert that there are no columns left for other blocks
        if !custody_columns_by_root.is_empty() {
            let remaining_roots = custody_columns_by_root.keys().collect::<Vec<_>>();
            // log the error but don't return an error, we can still progress with responses.
            debug!(?remaining_roots, "Not all columns consumed for block");
        }

        // Recoverable error, log and continue
        if let Some(envelopes_by_block_root) = envelopes_by_block_root
            && !envelopes_by_block_root.is_empty()
        {
            warn!("Peer returned extra envelopes not matching any block");
        }

        Ok(range_sync_blocks)
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
    use crate::sync::network_context::PeerGroup;
    use beacon_chain::block_verification_types::RangeSyncBlock;
    use beacon_chain::custody_context::NodeCustodyType;
    use beacon_chain::data_availability_checker::DataAvailabilityChecker;
    use beacon_chain::test_utils::{
        EphemeralHarnessType, NumBlobs, generate_rand_block_and_blobs,
        generate_rand_block_and_data_columns, test_da_checker, test_spec,
    };
    use bls::Signature;
    use lighthouse_network::service::api_types::{
        BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId,
        PayloadEnvelopesByRangeRequestId, RangeRequestId,
    };
    use std::sync::Arc;
    use types::{
        ChainSpec, ColumnIndex, DataColumnSidecarList, Epoch, ExecutionPayloadEnvelope, ForkName,
        Hash256, MinimalEthSpec as E, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
    };

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

    fn payloads_id(
        parent_request_id: ComponentsByRangeRequestId,
    ) -> PayloadEnvelopesByRangeRequestId {
        PayloadEnvelopesByRangeRequestId {
            id: 1,
            parent_request_id,
        }
    }

    /// The custody-column coupling tests below build Fulu data-column sidecars directly, which is
    /// incompatible with a Gloas genesis (Gloas columns have a different structure). Skip them when
    /// `FORK_NAME` schedules Gloas at genesis.
    fn skip_under_gloas() -> bool {
        test_spec::<E>()
            .fork_name_at_epoch(Epoch::new(0))
            .gloas_enabled()
    }

    /// Registers each data-bearing block root as awaiting custody, then completes its custody-by-root
    /// request with the columns the node is expected to custody.
    fn complete_custody_by_root(
        info: &mut RangeBlockComponentsRequest<E>,
        blocks_and_columns: &[(Arc<SignedBeaconBlock<E>>, DataColumnSidecarList<E>)],
        expected_custody_columns: &[ColumnIndex],
    ) {
        for (block, _) in blocks_and_columns {
            if block.num_expected_blobs() == 0 {
                continue;
            }
            let block_root = beacon_chain::get_block_root(block);
            info.register_custody_block(block_root);
        }
        for (block, data_columns) in blocks_and_columns {
            if block.num_expected_blobs() == 0 {
                continue;
            }
            let block_root = beacon_chain::get_block_root(block);
            let custody_columns: DataColumnSidecarList<E> = data_columns
                .iter()
                .filter(|d| expected_custody_columns.contains(d.index()))
                .cloned()
                .collect();
            info.add_custody_columns(
                block_root,
                custody_columns,
                PeerGroup::from_set(Default::default()),
            )
            .unwrap();
        }
    }

    #[test]
    fn no_blobs_into_responses() {
        // This exercises the pre-Gloas blobs/no-data coupling path.
        if skip_under_gloas() {
            return;
        }
        let spec = Arc::new(test_spec::<E>());

        let mut u = types::test_utils::test_unstructured();
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_blobs::<E>(
                    spec.fork_name_at_epoch(Epoch::new(0)),
                    NumBlobs::None,
                    &mut u,
                )
                .unwrap()
                .0
                .into()
            })
            .collect::<Vec<Arc<SignedBeaconBlock<E>>>>();

        let blocks_req_id = blocks_id(components_id());
        let mut info = RangeBlockComponentsRequest::<E>::new(blocks_req_id, None, None, None);

        // Send blocks and complete terminate response
        info.add_blocks(blocks_req_id, blocks).unwrap();

        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));

        // Assert response is finished and blocks can be constructed
        info.responses(da_checker, spec).unwrap().unwrap();
    }

    #[test]
    fn empty_blobs_into_responses() {
        let mut u = types::test_utils::test_unstructured();
        let blocks = (0..4)
            .map(|_| {
                // Always generate some blobs.
                generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Number(3), &mut u)
                    .unwrap()
                    .0
                    .into()
            })
            .collect::<Vec<Arc<SignedBeaconBlock<E>>>>();

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let blobs_req_id = blobs_id(components_id);
        let mut info =
            RangeBlockComponentsRequest::<E>::new(blocks_req_id, Some(blobs_req_id), None, None);

        // Send blocks and complete terminate response
        info.add_blocks(blocks_req_id, blocks).unwrap();
        // Expect no blobs returned
        info.add_blobs(blobs_req_id, vec![]).unwrap();

        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        // Pin to pre-PeerDAS so this exercises the blob (not custody-column) path under any
        // FORK_NAME.
        spec.fulu_fork_epoch = None;
        let spec = Arc::new(spec);
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        // Blobs are no longer required for availability, so the response succeeds without them.
        let result = info.responses(da_checker, spec).unwrap();
        assert!(result.is_ok())
    }

    #[test]
    fn rpc_block_with_custody_columns() {
        if skip_under_gloas() {
            return;
        }
        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        let spec = Arc::new(spec);
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        let expects_custody_columns = da_checker
            .custody_context()
            .sampling_columns_for_epoch(Epoch::new(0), &spec)
            .to_vec();
        let mut u = types::test_utils::test_unstructured();
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Fulu,
                    NumBlobs::Number(1),
                    &mut u,
                    &spec,
                )
                .unwrap()
            })
            .map(|(block, columns)| (Arc::new(block), columns))
            .collect::<Vec<_>>();

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some(expects_custody_columns.clone()),
            None,
        );

        // Send blocks
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|(b, _)| b.clone()).collect(),
        )
        .unwrap();
        // Assert response is not finished while custody-by-root is outstanding.
        for (block, _) in &blocks {
            info.register_custody_block(beacon_chain::get_block_root(block));
        }
        assert!(info.responses(da_checker.clone(), spec.clone()).is_none());

        // Complete each custody-by-root request.
        for (block, data_columns) in &blocks {
            let block_root = beacon_chain::get_block_root(block);
            let custody_columns: DataColumnSidecarList<E> = data_columns
                .iter()
                .filter(|d| expects_custody_columns.contains(d.index()))
                .cloned()
                .collect();
            info.add_custody_columns(
                block_root,
                custody_columns,
                PeerGroup::from_set(Default::default()),
            )
            .unwrap();
        }

        // All completed construct response
        info.responses(da_checker, spec).unwrap().unwrap();
    }

    #[test]
    fn add_custody_columns_rejects_unregistered_root() {
        let blocks_req_id = blocks_id(components_id());
        let mut info =
            RangeBlockComponentsRequest::<E>::new(blocks_req_id, None, Some(vec![0, 1]), None);
        let root = Hash256::random();
        let result =
            info.add_custody_columns(root, vec![], PeerGroup::from_set(Default::default()));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unregistered"));
    }

    #[test]
    fn add_custody_columns_rejects_duplicate() {
        let blocks_req_id = blocks_id(components_id());
        let mut info =
            RangeBlockComponentsRequest::<E>::new(blocks_req_id, None, Some(vec![0, 1]), None);
        let root = Hash256::random();
        info.register_custody_block(root);
        info.add_custody_columns(root, vec![], PeerGroup::from_set(Default::default()))
            .unwrap();
        let result =
            info.add_custody_columns(root, vec![], PeerGroup::from_set(Default::default()));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn responses_returns_none_while_custody_requesting() {
        if skip_under_gloas() {
            return;
        }
        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        let spec = Arc::new(spec);
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        let expects_custody_columns = da_checker
            .custody_context()
            .sampling_columns_for_epoch(Epoch::new(0), &spec)
            .to_vec();
        let mut u = types::test_utils::test_unstructured();
        let (block, _data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut u,
            &spec,
        )
        .unwrap();

        let blocks_req_id = blocks_id(components_id());
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some(expects_custody_columns),
            None,
        );

        info.add_blocks(blocks_req_id, vec![block.into()]).unwrap();
        let block_root = Hash256::random();
        info.register_custody_block(block_root);

        // Still requesting — responses should return None
        assert!(info.responses(da_checker, spec).is_none());
    }

    #[test]
    fn responses_error_on_missing_custody_columns() {
        if skip_under_gloas() {
            return;
        }
        // Block with data but no custody columns registered → error
        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        let spec = Arc::new(spec);
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        let expects_custody_columns = da_checker
            .custody_context()
            .sampling_columns_for_epoch(Epoch::new(0), &spec)
            .to_vec();
        let mut u = types::test_utils::test_unstructured();
        let (block, _data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut u,
            &spec,
        )
        .unwrap();

        let blocks_req_id = blocks_id(components_id());
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some(expects_custody_columns),
            None,
        );

        info.add_blocks(blocks_req_id, vec![block.into()]).unwrap();

        // No custody columns registered or completed — block has data so this should error
        let result = info.responses(da_checker, spec).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn mixed_blocks_with_and_without_data() {
        if skip_under_gloas() {
            return;
        }
        // Mix of blocks: some with blobs (need custody), some without
        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        let spec = Arc::new(spec);
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        let expects_custody_columns = da_checker
            .custody_context()
            .sampling_columns_for_epoch(Epoch::new(0), &spec)
            .to_vec();
        let mut u = types::test_utils::test_unstructured();

        let (block_with_data, data_columns) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut u,
            &spec,
        )
        .unwrap();
        let (block_no_data, _) = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::None,
            &mut u,
            &spec,
        )
        .unwrap();

        let blocks_req_id = blocks_id(components_id());
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some(expects_custody_columns.clone()),
            None,
        );

        let block_root_with_data = beacon_chain::get_block_root(&block_with_data);
        info.add_blocks(
            blocks_req_id,
            vec![block_with_data.into(), block_no_data.into()],
        )
        .unwrap();

        // Only register and complete custody for the block with data
        info.register_custody_block(block_root_with_data);
        let custody_columns: DataColumnSidecarList<E> = data_columns
            .iter()
            .filter(|d| expects_custody_columns.contains(d.index()))
            .cloned()
            .collect();
        info.add_custody_columns(
            block_root_with_data,
            custody_columns,
            PeerGroup::from_set(Default::default()),
        )
        .unwrap();

        // Both blocks should resolve — one with columns, one with NoData
        info.responses(da_checker, spec).unwrap().unwrap();
    }

    #[test]
    fn rpc_block_with_custody_columns_no_data_blocks() {
        if skip_under_gloas() {
            return;
        }
        // Test blocks that don't have blob commitments don't need custody
        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        let spec = Arc::new(spec);
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        let expects_custody_columns = da_checker
            .custody_context()
            .sampling_columns_for_epoch(Epoch::new(0), &spec)
            .to_vec();
        let mut u = types::test_utils::test_unstructured();
        // Generate blocks with NO blobs
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Fulu,
                    NumBlobs::None,
                    &mut u,
                    &spec,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let blocks_req_id = blocks_id(components_id());
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some(expects_custody_columns),
            None,
        );

        // Send blocks
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
        )
        .unwrap();

        // Response should be ready immediately (no blocks need custody columns)
        info.responses(da_checker, spec).unwrap().unwrap();
    }

    // ===== Gloas payload-envelope coupling tests =====

    fn gloas_spec() -> ChainSpec {
        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        spec.gloas_fork_epoch = Some(Epoch::new(0));
        spec
    }

    fn matching_envelope(block: &SignedBeaconBlock<E>) -> Arc<SignedExecutionPayloadEnvelope<E>> {
        let bid = &block
            .message()
            .body()
            .signed_execution_payload_bid()
            .expect("Gloas block should have payload bid")
            .message;
        let mut envelope = SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope::empty(),
            signature: Signature::empty(),
        };
        envelope.message.beacon_block_root = block.canonical_root();
        envelope.message.parent_beacon_block_root = block.parent_root();
        envelope.message.builder_index = bid.builder_index;
        envelope.message.payload.slot_number = block.slot();
        envelope.message.payload.parent_hash = bid.parent_block_hash;
        envelope.message.payload.block_hash = bid.block_hash;
        Arc::new(envelope)
    }

    #[allow(clippy::type_complexity)]
    fn make_gloas_blocks_and_columns(
        count: usize,
        spec: &ChainSpec,
    ) -> Vec<(
        Arc<SignedBeaconBlock<E>>,
        DataColumnSidecarList<E>,
        Arc<SignedExecutionPayloadEnvelope<E>>,
    )> {
        let mut u = types::test_utils::test_unstructured();
        (0..count)
            .map(|_| {
                let (block, data_columns) = generate_rand_block_and_data_columns::<E>(
                    ForkName::Gloas,
                    NumBlobs::Number(1),
                    &mut u,
                    spec,
                )
                .unwrap();
                let envelope = matching_envelope(&block);
                (Arc::new(block), data_columns, envelope)
            })
            .collect()
    }

    #[allow(clippy::type_complexity)]
    struct GloasSetup {
        info: RangeBlockComponentsRequest<E>,
        da_checker: Arc<DataAvailabilityChecker<EphemeralHarnessType<E>>>,
        spec: Arc<ChainSpec>,
        blocks: Vec<(
            Arc<SignedBeaconBlock<E>>,
            DataColumnSidecarList<E>,
            Arc<SignedExecutionPayloadEnvelope<E>>,
        )>,
        payloads_req_id: PayloadEnvelopesByRangeRequestId,
        expected_custody_columns: Vec<ColumnIndex>,
    }

    /// Builds a Gloas coupling request with `count` blocks and all custody columns added,
    /// ready for the per-test payload-envelope step.
    fn setup_gloas_coupling(count: usize) -> GloasSetup {
        let spec = Arc::new(gloas_spec());
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        let expected_custody_columns = da_checker
            .custody_context()
            .sampling_columns_for_epoch(Epoch::new(0), &spec)
            .to_vec();
        let blocks = make_gloas_blocks_and_columns(count, &spec);

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let payloads_req_id = payloads_id(components_id);
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some(expected_custody_columns.clone()),
            Some(payloads_req_id),
        );

        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|(block, _, _)| block.clone()).collect(),
        )
        .unwrap();

        let blocks_and_columns = blocks
            .iter()
            .map(|(block, columns, _)| (block.clone(), columns.clone()))
            .collect::<Vec<_>>();
        complete_custody_by_root(&mut info, &blocks_and_columns, &expected_custody_columns);

        GloasSetup {
            info,
            da_checker,
            spec,
            blocks,
            payloads_req_id,
            expected_custody_columns,
        }
    }

    #[test]
    fn gloas_payload_envelopes_must_complete_before_responses() {
        let GloasSetup {
            mut info,
            da_checker,
            spec,
            ..
        } = setup_gloas_coupling(2);

        // No payload envelopes added yet, so the request must not be complete.
        assert!(info.responses(da_checker, spec).is_none());
    }

    #[test]
    fn gloas_payload_envelopes_are_coupled_by_block_root() {
        let GloasSetup {
            mut info,
            da_checker,
            spec,
            blocks,
            payloads_req_id,
            expected_custody_columns,
        } = setup_gloas_coupling(2);

        // Supply envelopes in reverse order to prove coupling is by block root, not position.
        info.add_payload_envelopes(
            payloads_req_id,
            blocks
                .iter()
                .rev()
                .map(|(_, _, envelope)| envelope.clone())
                .collect(),
        )
        .unwrap();

        let responses = info.responses(da_checker, spec).unwrap().unwrap();
        assert_eq!(responses.len(), blocks.len());
        for response in responses {
            match response {
                RangeSyncBlock::Gloas {
                    block,
                    envelope: Some(envelope),
                } => {
                    assert_eq!(
                        envelope.envelope().beacon_block_root(),
                        block.canonical_root()
                    );
                    assert_eq!(envelope.columns.len(), expected_custody_columns.len());
                }
                other => panic!("expected Gloas block with envelope, got {other:?}"),
            }
        }
    }

    #[test]
    fn gloas_payload_envelopes_allow_missing_envelopes() {
        let GloasSetup {
            mut info,
            da_checker,
            spec,
            blocks,
            payloads_req_id,
            ..
        } = setup_gloas_coupling(2);

        // Supply an envelope for only one of the two blocks.
        info.add_payload_envelopes(payloads_req_id, vec![blocks[0].2.clone()])
            .unwrap();

        let responses = info.responses(da_checker, spec).unwrap().unwrap();
        let count_with = |with_envelope: bool| {
            responses
                .iter()
                .filter(|response| {
                    matches!(response, RangeSyncBlock::Gloas { envelope, .. } if envelope.is_some() == with_envelope)
                })
                .count()
        };
        assert_eq!(count_with(true), 1);
        assert_eq!(count_with(false), 1);
    }

    #[test]
    fn gloas_payload_envelope_mismatch_fails_coupling() {
        let GloasSetup {
            mut info,
            da_checker,
            spec,
            blocks,
            payloads_req_id,
            ..
        } = setup_gloas_coupling(1);

        let mut bad_envelope = (*blocks[0].2).clone();
        bad_envelope.message.payload.slot_number += 1;
        info.add_payload_envelopes(payloads_req_id, vec![Arc::new(bad_envelope)])
            .unwrap();

        let result = info.responses(da_checker, spec).unwrap();
        assert!(
            matches!(
                result,
                Err(super::CouplingError::EnvelopePeerFailure(ref error))
                    if error.contains("SlotMismatch")
            ),
            "expected envelope slot mismatch, got {result:?}"
        );
    }
}
