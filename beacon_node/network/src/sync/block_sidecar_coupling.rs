use beacon_chain::data_availability_checker::AvailabilityCheckError;
use beacon_chain::payload_envelope_verification::AvailableEnvelope;
use beacon_chain::{
    BeaconChainTypes,
    block_verification_types::{AvailableBlockData, RangeSyncBlock},
    custody_context::CustodyContext,
    get_block_root,
};
use lighthouse_network::{
    PeerId,
    service::api_types::{
        BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId,
        CustodyRequester, PayloadEnvelopesByRangeRequestId,
    },
};
use parking_lot::RwLock;
use ssz_types::RuntimeVariableList;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{Span, debug, warn};
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
    #[allow(clippy::type_complexity)]
    blocks_request:
        ByRangeRequest<BlocksByRangeRequestId, (Vec<Arc<SignedBeaconBlock<E>>>, PeerId)>,
    /// Sidecars we have received awaiting for their corresponding block.
    block_data_request: RangeBlockDataRequest<E>,
    /// Payload envelopes for Gloas blocks.
    payloads_request: Option<
        ByRangeRequest<
            PayloadEnvelopesByRangeRequestId,
            Vec<Arc<SignedExecutionPayloadEnvelope<E>>>,
        >,
    >,
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
    /// A single custody-by-root request fetches the custody columns of every data-bearing block
    /// in this batch.
    DataColumns(DataColumnsRequest<E>),
}

enum DataColumnsRequest<E: EthSpec> {
    /// Blocks have not arrived yet, so no custody-by-root request has been initiated.
    NotStarted,
    /// A custody-by-root request is in flight for the batch's data blocks.
    Requesting,
    /// All custody columns for the batch have been downloaded.
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
    AvailabilityCheckError(AvailabilityCheckError),
}

impl From<AvailabilityCheckError> for CouplingError {
    fn from(e: AvailabilityCheckError) -> Self {
        CouplingError::AvailabilityCheckError(e)
    }
}

impl<E: EthSpec> RangeBlockComponentsRequest<E> {
    /// Creates a new range request for blocks and their associated data (blobs or data columns).
    ///
    /// # Arguments
    /// * `blocks_req_id` - Request ID for the blocks
    /// * `blobs_req_id` - Optional request ID for blobs (pre-Fulu fork)
    /// * `expects_custody_columns` - If true, custody-by-root will be used after blocks arrive
    /// * `payloads_req_id` - Optional request ID for payload envelopes (Gloas fork)
    pub fn new(
        blocks_req_id: BlocksByRangeRequestId,
        blobs_req_id: Option<BlobsByRangeRequestId>,
        expects_custody_columns: bool,
        payloads_req_id: Option<PayloadEnvelopesByRangeRequestId>,
        request_span: Span,
    ) -> Self {
        let block_data_request = if let Some(blobs_req_id) = blobs_req_id {
            RangeBlockDataRequest::Blobs(ByRangeRequest::Active(blobs_req_id))
        } else if expects_custody_columns {
            RangeBlockDataRequest::DataColumns(DataColumnsRequest::NotStarted)
        } else {
            RangeBlockDataRequest::NoData
        };

        Self {
            blocks_request: ByRangeRequest::Active(blocks_req_id),
            block_data_request,
            payloads_request: payloads_req_id.map(ByRangeRequest::Active),
            request_span,
        }
    }

    /// Adds received blocks to the request.
    ///
    /// Returns an error if the request ID doesn't match the expected blocks request.
    pub fn add_blocks(
        &mut self,
        req_id: BlocksByRangeRequestId,
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        peer_id: PeerId,
    ) -> Result<(), String> {
        self.blocks_request.finish(req_id, (blocks, peer_id))
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

    /// Adds the custody columns downloaded for the whole batch via custody-by-root.
    ///
    /// Returns an error if not in DataColumns mode, or if the request was already completed or
    /// was never initiated.
    pub fn add_custody_columns(
        &mut self,
        columns: DataColumnSidecarList<E>,
        peer_group: PeerGroup,
    ) -> Result<(), String> {
        let RangeBlockDataRequest::DataColumns(state) = &mut self.block_data_request else {
            return Err("received custody columns but not in DataColumns mode".to_owned());
        };
        match state {
            DataColumnsRequest::Requesting => {
                *state = DataColumnsRequest::Complete(columns, peer_group);
                Ok(())
            }
            DataColumnsRequest::Complete(..) => {
                Err("duplicate custody columns for batch".to_owned())
            }
            DataColumnsRequest::NotStarted => {
                Err("received custody columns before request was initiated".to_owned())
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

    /// After blocks arrive, initiates a single custody-by-root request for all data-bearing blocks
    /// in the batch.
    ///
    /// Only does work when blocks have arrived and we're in DataColumns mode and haven't started
    /// yet. Fires one custody request covering every block with data via the network context.
    pub fn continue_requests<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        id: ComponentsByRangeRequestId,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), String> {
        let _guard = self.request_span.clone().entered();
        let Some((blocks, block_peer)) = self.blocks_request.to_finished() else {
            return Ok(());
        };

        // For Gloas, wait for the envelope response before requesting custody columns. Blocks
        // with withheld payloads have no envelope or columns on the network, and the bid alone
        // can't tell us which blocks those are. If the envelope peer lies by omission, the
        // reveal-status check in `import_historical_block_batch` catches it.
        let revealed_block_roots = match &self.payloads_request {
            Some(ByRangeRequest::Active(_)) => return Ok(()),
            Some(ByRangeRequest::Complete(envelopes)) => Some(
                envelopes
                    .iter()
                    .map(|envelope| envelope.beacon_block_root())
                    .collect::<HashSet<_>>(),
            ),
            None => None,
        };

        let RangeBlockDataRequest::DataColumns(state @ DataColumnsRequest::NotStarted) =
            &mut self.block_data_request
        else {
            return Ok(());
        };

        // Collect the data-bearing block roots that need custody columns. All blocks in a range
        // batch share an epoch (EPOCHS_PER_BATCH == 1).
        let block_roots = blocks
            .iter()
            .filter(|block| block.num_expected_blobs() > 0)
            .map(|block| get_block_root(block))
            .filter(|root| {
                revealed_block_roots
                    .as_ref()
                    .is_none_or(|revealed| revealed.contains(root))
            })
            .collect::<Vec<_>>();

        if block_roots.is_empty() {
            // No block in this batch has data; nothing to fetch.
            *state = DataColumnsRequest::Complete(vec![], PeerGroup::from_set(Default::default()));
            return Ok(());
        }
        let block_epoch = blocks[0].slot().epoch(E::slots_per_epoch());

        match cx.custody_lookup_request(
            CustodyRequester::RangeSync(id),
            &block_roots,
            block_epoch,
            // ignore_cache: range blocks are historical and won't have gossip-imported columns
            true,
            // The peer that provided the blocks is a signal that some peer has the block's data.
            Arc::new(RwLock::new(HashSet::from([*block_peer]))),
        ) {
            Ok(LookupRequestResult::RequestSent(_)) => {
                *state = DataColumnsRequest::Requesting;
                debug!(%id, blocks = block_roots.len(), "Initiated custody-by-root for range batch");
                Ok(())
            }
            Ok(LookupRequestResult::NoRequestNeeded(..)) => {
                Err("Unexpected custody_lookup_request returned NoRequestNeeded".to_owned())
            }
            Ok(LookupRequestResult::Pending(reason)) => Err(format!(
                "Unexpected custody_lookup_request returned Pending({reason})"
            )),
            Err(e) => Err(format!("Failed to initiate custody for batch {id}: {e:?}")),
        }
    }

    /// Marks the custody-by-root request as in flight. Used in tests to simulate the effect of
    /// `continue_requests` without requiring a full network context.
    #[cfg(test)]
    fn set_custody_requesting(&mut self) {
        if let RangeBlockDataRequest::DataColumns(state) = &mut self.block_data_request {
            *state = DataColumnsRequest::Requesting;
        }
    }

    /// Attempts to construct RPC blocks from all received components.
    ///
    /// Returns `None` if not all expected requests have completed.
    /// Returns `Some(Ok(_))` with valid RPC blocks if all data is present and valid.
    /// Returns `Some(Err(_))` if there are issues coupling blocks with their data.
    #[allow(clippy::type_complexity)]
    pub fn responses<T>(
        &mut self,
        custody_context: &CustodyContext<T>,
        spec: Arc<ChainSpec>,
    ) -> Option<(Result<Vec<RangeSyncBlock<E>>, CouplingError>, PeerId)>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        let Some((blocks, block_peer)) = self.blocks_request.to_finished() else {
            return None;
        };

        // Check if payload envelopes are still pending
        if let Some(ByRangeRequest::Active(_)) = &self.payloads_request {
            return None;
        }

        match &self.block_data_request {
            RangeBlockDataRequest::NoData => Some((
                Self::responses_with_blobs(blocks.to_vec(), vec![], custody_context, spec),
                *block_peer,
            )),
            RangeBlockDataRequest::Blobs(request) => {
                let Some(blobs) = request.to_finished() else {
                    return None;
                };
                Some((
                    Self::responses_with_blobs(
                        blocks.to_vec(),
                        blobs.to_vec(),
                        custody_context,
                        spec,
                    ),
                    *block_peer,
                ))
            }
            RangeBlockDataRequest::DataColumns(state) => {
                // Wait until the batch's custody-by-root request has resolved.
                let DataColumnsRequest::Complete(columns, _peer_group) = state else {
                    return None;
                };

                let payload_envelopes = self.payloads_request.as_ref().and_then(|request| {
                    request
                        .to_finished()
                        .map(|payload_envelopes| payload_envelopes.to_vec())
                });

                Some((
                    Self::responses_with_custody_columns(
                        blocks.to_vec(),
                        columns.clone(),
                        custody_context,
                        payload_envelopes,
                    ),
                    *block_peer,
                ))
            }
        }
    }

    fn responses_with_blobs<T>(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        blobs: Vec<Arc<BlobSidecar<E>>>,
        custody_context: &CustodyContext<T>,
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
                RangeSyncBlock::new(block, block_data, custody_context)
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

    fn responses_with_custody_columns<T>(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        columns: DataColumnSidecarList<E>,
        custody_context: &CustodyContext<T>,
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

        // Group the downloaded custody columns by block root. The custody-by-root request only
        // returns the requested custody columns, so we can couple them directly.
        let mut columns_by_block_root = HashMap::<Hash256, Vec<Arc<DataColumnSidecar<E>>>>::new();
        for column in columns {
            columns_by_block_root
                .entry(column.block_root())
                .or_default()
                .push(column);
        }

        let mut range_sync_blocks = Vec::with_capacity(blocks.len());

        for block in blocks {
            let block_root = get_block_root(&block);
            let custody_columns = if block.num_expected_blobs() > 0 {
                columns_by_block_root
                    .remove(&block_root)
                    .unwrap_or_default()
            } else {
                vec![]
            };

            let range_sync_block = if let Some(envelopes_by_block_root) =
                envelopes_by_block_root.as_mut()
            {
                let envelope = envelopes_by_block_root.remove(&block_root);
                let bid = block
                    .message()
                    .body()
                    .signed_execution_payload_bid()
                    // this really should never fail
                    .map_err(|_| AvailabilityCheckError::MissingBid(block_root))?;
                let available_envelope = envelope
                    .map(|env| AvailableEnvelope::new(env, custody_columns, bid, custody_context))
                    .transpose()?;

                RangeSyncBlock::new_gloas(block, available_envelope)
                    .map_err(CouplingError::EnvelopePeerFailure)?
            } else if custody_columns.is_empty() {
                RangeSyncBlock::new(block, AvailableBlockData::NoData, custody_context)
                    .map_err(|e| CouplingError::InternalError(format!("{:?}", e)))?
            } else {
                let block_data = AvailableBlockData::new_with_data_columns(custody_columns);
                RangeSyncBlock::new(block, block_data, custody_context)
                    .map_err(|e| CouplingError::InternalError(format!("{:?}", e)))?
            };
            range_sync_blocks.push(range_sync_block);
        }

        // Assert that there are no columns left for other blocks
        if !columns_by_block_root.is_empty() {
            let remaining_roots = columns_by_block_root.keys().collect::<Vec<_>>();
            // log the error but don't return an error, we can still progress with responses.
            // this is most likely an internal error with overrequesting or a client bug.
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
    use beacon_chain::custody_context::{CustodyContext, NodeCustodyType};
    use beacon_chain::test_utils::{
        EphemeralHarnessType, NumBlobs, generate_rand_block_and_blobs,
        generate_rand_block_and_data_columns, test_custody_context, test_spec,
    };
    use bls::Signature;
    use lighthouse_network::{
        PeerId,
        service::api_types::{
            BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId,
            PayloadEnvelopesByRangeRequestId, RangeRequestId,
        },
    };
    use std::sync::Arc;
    use tracing::Span;
    use tree_hash::TreeHash;
    use types::{
        ChainSpec, DataColumnSidecarList, Epoch, ExecutionPayloadEnvelope, ExecutionRequestsGloas,
        ForkName, MinimalEthSpec as E, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
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

    /// The custody-column coupling tests below build Fulu data-column sidecars directly, which is
    /// incompatible with a Gloas genesis (Gloas columns have a different structure). Skip them when
    /// `FORK_NAME` schedules Gloas at genesis. TODO(gloas): port the harness to build Gloas columns.
    fn skip_under_gloas() -> bool {
        test_spec::<E>()
            .fork_name_at_epoch(Epoch::new(0))
            .gloas_enabled()
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

    fn is_finished(info: &mut RangeBlockComponentsRequest<E>) -> bool {
        let spec = Arc::new(test_spec::<E>());
        let custody_context = test_custody_context(NodeCustodyType::Fullnode, spec.clone());
        info.responses(&custody_context, spec).is_some()
    }

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
                let (mut block, data_columns) = generate_rand_block_and_data_columns::<E>(
                    ForkName::Gloas,
                    NumBlobs::Number(1),
                    &mut u,
                    spec,
                )
                .unwrap();
                // Commit the (random) bid to the empty execution requests carried by
                // `matching_envelope`, so the envelope passes `verify_envelope_consistency`.
                if let Ok(bid) = block
                    .message_mut()
                    .body_mut()
                    .signed_execution_payload_bid_mut()
                {
                    bid.message.execution_requests_root =
                        ExecutionRequestsGloas::<E>::default().tree_hash_root();
                }
                // The bid mutation changed the block root; re-point the columns at the mutated
                // block so column<->block pairing (by block root) still holds.
                let new_root = block.canonical_root();
                let data_columns = data_columns
                    .into_iter()
                    .map(|column| {
                        let mut column = (*column).clone();
                        if let types::DataColumnSidecar::Gloas(ref mut gloas_column) = column {
                            gloas_column.beacon_block_root = new_root;
                        }
                        Arc::new(column)
                    })
                    .collect::<Vec<_>>();
                let envelope = matching_envelope(&block);
                (Arc::new(block), data_columns, envelope)
            })
            .collect()
    }

    #[allow(clippy::type_complexity)]
    fn add_all_columns(
        info: &mut RangeBlockComponentsRequest<E>,
        blocks: &[(
            Arc<SignedBeaconBlock<E>>,
            DataColumnSidecarList<E>,
            Arc<SignedExecutionPayloadEnvelope<E>>,
        )],
        expected_custody_columns: &[u64],
    ) {
        info.set_custody_requesting();
        let columns = expected_custody_columns
            .iter()
            .flat_map(|&column_index| {
                blocks.iter().flat_map(move |(_, columns, _)| {
                    columns
                        .iter()
                        .filter(move |column| *column.index() == column_index)
                        .cloned()
                })
            })
            .collect();
        info.add_custody_columns(columns, PeerGroup::from_set(Default::default()))
            .unwrap();
    }

    #[allow(clippy::type_complexity)]
    struct GloasSetup {
        info: RangeBlockComponentsRequest<E>,
        custody_context: Arc<CustodyContext<EphemeralHarnessType<E>>>,
        spec: Arc<ChainSpec>,
        blocks: Vec<(
            Arc<SignedBeaconBlock<E>>,
            DataColumnSidecarList<E>,
            Arc<SignedExecutionPayloadEnvelope<E>>,
        )>,
        payloads_req_id: PayloadEnvelopesByRangeRequestId,
        expected_custody_columns: Vec<u64>,
    }

    /// Builds a Gloas coupling request with `count` blocks and all custody columns added,
    /// ready for the per-test payload-envelope step.
    fn setup_gloas_coupling(count: usize) -> GloasSetup {
        let spec = Arc::new(gloas_spec());
        let custody_context = test_custody_context(NodeCustodyType::Fullnode, spec.clone());
        let expected_custody_columns = custody_context
            .sampling_columns_for_epoch(Epoch::new(0))
            .to_vec();
        let blocks = make_gloas_blocks_and_columns(count, &spec);

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let payloads_req_id = payloads_id(components_id);
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            true,
            Some(payloads_req_id),
            Span::none(),
        );

        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|(block, _, _)| block.clone()).collect(),
            PeerId::random(),
        )
        .unwrap();
        add_all_columns(&mut info, &blocks, &expected_custody_columns);

        GloasSetup {
            info,
            custody_context,
            spec,
            blocks,
            payloads_req_id,
            expected_custody_columns,
        }
    }

    #[test]
    fn no_blobs_into_responses() {
        // This exercises the pre-Gloas blobs/no-data coupling path. Gloas coupling is covered
        // by the dedicated `setup_gloas_coupling` tests below.
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
        let mut info =
            RangeBlockComponentsRequest::<E>::new(blocks_req_id, None, false, None, Span::none());

        // Send blocks and complete terminate response
        info.add_blocks(blocks_req_id, blocks, PeerId::random())
            .unwrap();

        let custody_context = test_custody_context(NodeCustodyType::Fullnode, spec.clone());

        // Assert response is finished and RpcBlocks can be constructed
        info.responses(&custody_context, spec).unwrap().0.unwrap();
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
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            Some(blobs_req_id),
            false,
            None,
            Span::none(),
        );

        // Send blocks and complete terminate response
        info.add_blocks(blocks_req_id, blocks, PeerId::random())
            .unwrap();
        // Expect no blobs returned
        info.add_blobs(blobs_req_id, vec![]).unwrap();

        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        // Pin to pre-PeerDAS so this exercises the blob (not custody-column) path under any
        // FORK_NAME.
        spec.fulu_fork_epoch = None;
        let spec = Arc::new(spec);
        let custody_context = test_custody_context(NodeCustodyType::Fullnode, spec.clone());
        // Blobs are no longer required for availability, so the response succeeds without them.
        let result = info.responses(&custody_context, spec).unwrap().0;
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
        let custody_context = test_custody_context(NodeCustodyType::Fullnode, spec.clone());
        let expects_custody_columns = custody_context
            .sampling_columns_for_epoch(Epoch::new(0))
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
            .collect::<Vec<_>>();

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let mut info =
            RangeBlockComponentsRequest::<E>::new(blocks_req_id, None, true, None, Span::none());
        // Send blocks and complete terminate response
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
            PeerId::random(),
        )
        .unwrap();
        // Assert response is not finished
        assert!(!is_finished(&mut info));

        // Send data columns
        info.set_custody_requesting();
        let columns = expects_custody_columns
            .iter()
            .flat_map(|&column_index| {
                blocks.iter().flat_map(move |b| {
                    b.1.iter()
                        .filter(move |d| *d.index() == column_index)
                        .cloned()
                })
            })
            .collect();
        info.add_custody_columns(columns, PeerGroup::from_set(Default::default()))
            .unwrap();

        // All completed construct response
        info.responses(&custody_context, spec).unwrap().0.unwrap();
    }

    #[test]
    fn gloas_payload_envelopes_must_complete_before_responses() {
        let GloasSetup {
            mut info,
            custody_context,
            spec,
            ..
        } = setup_gloas_coupling(2);

        // No payload envelopes added yet, so the request must not be complete.
        assert!(info.responses(&custody_context, spec).is_none());
    }

    #[test]
    fn gloas_payload_envelopes_are_coupled_by_block_root() {
        let GloasSetup {
            mut info,
            custody_context,
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

        let responses = info.responses(&custody_context, spec).unwrap().0.unwrap();
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
            custody_context,
            spec,
            blocks,
            payloads_req_id,
            ..
        } = setup_gloas_coupling(2);

        // Supply an envelope for only one of the two blocks.
        info.add_payload_envelopes(payloads_req_id, vec![blocks[0].2.clone()])
            .unwrap();

        let responses = info.responses(&custody_context, spec).unwrap().0.unwrap();
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
            custody_context,
            spec,
            blocks,
            payloads_req_id,
            ..
        } = setup_gloas_coupling(1);

        let mut bad_envelope = (*blocks[0].2).clone();
        bad_envelope.message.payload.slot_number += 1;
        info.add_payload_envelopes(payloads_req_id, vec![Arc::new(bad_envelope)])
            .unwrap();

        let result = info.responses(&custody_context, spec).unwrap().0;
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
